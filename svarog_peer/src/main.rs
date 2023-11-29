use blake2::{digest::consts::U16, Blake2b, Digest};
use clap::{Arg, ArgAction, Command};
use sqlx::{Row, SqlitePool};
use std::cmp::{max, min};
use std::path;
use svarog_grpc::prelude::{prost::Message, tonic::transport::Server};
use svarog_grpc::protogen::svarog::mpc_peer_server::MpcPeerServer;
use svarog_grpc::protogen::svarog::{
    mpc_peer_server::MpcPeer, JoinSessionRequest, SessionFruit, SessionId, Void, Whistle,
};
use svarog_grpc::protogen::svarog::{SessionConfig, Signatures};
use svarog_mpc_sdk::gg18::{AlgoKeygen, AlgoSign, KeyArch, KeyStore};
use svarog_mpc_sdk::{now, CompressAble, DecompressAble, MpcMember, SessionFruitValue};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tonic::{async_trait, Request, Response};
use xuanmi_base_support::{tracing::*, *};

#[tokio::main]
async fn main() -> Outcome<()> {
    let matches = Command::new("mpc_peer")
        .arg(
            Arg::new("log_level")
                .short('l')
                .long("log")
                .default_value("info")
                .action(ArgAction::Set),
        )
        .get_matches();
    let log_level = matches.get_one::<String>("log_level").unwrap().to_owned();
    let available_log_level = vec!["trace", "debug", "info", "warn", "error"];
    assert_throw!(available_log_level.contains(&log_level.as_str()));

    let mpc_sesmon_url = "http://127.0.0.1:9000";
    let service = MpcPeerService::new("", mpc_sesmon_url).await.catch_()?;

    Server::builder()
        .add_service(MpcPeerServer::new(service))
        .serve("127.0.0.1:9001".parse().unwrap())
        .await
        .catch_()?;
    Ok(())
}

pub struct MpcPeerService {
    pub sqlite_pool: SqlitePool,
    pub mpc_sesmon_hostport: String,
}

const CREATE_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS peer_session (
    session_id CHAR(32) NOT NULL,
    member_name CHAR(128) NOT NULL,
    expire_at INT NOT NULL,
    fruit BLOB DEFAULT NULL,
    primary key (session_id, member_name)
);
"#;

impl MpcPeerService {
    pub async fn new(sqlite_db_path: &str, mpc_sesmon_hostport: &str) -> Outcome<Self> {
        let url = if sqlite_db_path == "" {
            "/dev/shm/mpc_peer.db".to_owned()
        } else {
            sqlite_db_path.to_owned()
        };
        if path::Path::new(&url).exists() {
            let _ = tokio::fs::remove_file(&url).await.catch("", &url)?;
        }
        // create file
        let _ = tokio::fs::File::create(&url).await.catch("", &url)?;

        let sesmon: &str = if mpc_sesmon_hostport == "" {
            "localhost:9000"
        } else {
            mpc_sesmon_hostport
        };
        let sqlite_pool = SqlitePool::connect(&url).await.catch("", &url)?;
        let _ = sqlx::query(CREATE_TABLE)
            .execute(&sqlite_pool)
            .await
            .catch_()?;

        Ok(Self {
            sqlite_pool,
            mpc_sesmon_hostport: sesmon.to_owned(),
        })
    }
}

#[async_trait]
impl MpcPeer for MpcPeerService {
    async fn join_session(
        &self,
        request: Request<JoinSessionRequest>,
    ) -> Result<Response<Void>, tonic::Status> {
        let req = request.into_inner();
        let sql = "SELECT COUNT(session_id) AS count FROM peer_session WHERE session_id = ? AND member_name = ?";
        let row = sqlx::query(sql)
            .bind(&req.session_id)
            .bind(&req.member_name)
            .fetch_one(&self.sqlite_pool)
            .await
            .map_err(|err| tonic::Status::internal(err.to_string()))?;
        let count: i64 = row.get("count");
        if count > 0 {
            return Err(tonic::Status::already_exists("session already joined"));
        }

        let mpc_member = MpcMember::new(&self.mpc_sesmon_hostport)
            .await
            .map_err(|e| tonic::Status::internal(e.to_string()))?;
        let conf = mpc_member
            .fetch_session_config(&req.session_id)
            .await
            .map_err(|e| tonic::Status::internal(e.to_string()))?;
        let expire_at = conf.expire_before_finish;

        let mut reshare0 = false;
        let mut reshare1 = false;
        for group in conf.groups.iter() {
            for member in group.members.iter() {
                if &member.member_name == &req.member_name {
                    if group.is_reshare {
                        reshare1 = true;
                    } else {
                        reshare0 = true;
                    }
                }
            }
        }
        if (!reshare0) && !(reshare1) {
            return Err(tonic::Status::invalid_argument(
                "member not found in session",
            ));
        }

        if reshare0 {
            // execute mpc algo in another thread.
            let mut mpc_member_ = mpc_member.clone();
            mpc_member_
                .use_session_config(&conf, &req.member_name, false)
                .map_err(|e| tonic::Status::internal(e.to_string()))?;

            let db = self.sqlite_pool.clone();
            let conf_ = conf.clone();
            let req_ = req.clone();
            tokio::spawn(async move {
                let key_name = &req_.key_name;
                let token = &req_.token;

                let fruit: SessionFruit = match conf.session_type.as_str() {
                    "keygen" => match run_keygen_session(&mpc_member_, &conf_, key_name).await {
                        Ok(fruit) => fruit,
                        Err(err) => {
                            error!("Failed to run «keygen» session (member {} at session {} with key {}) --\n {}",
                                &mpc_member_.member_name, &conf_.session_id, key_name, err);
                            panic!("{:#?}", err);
                        }
                    },
                    "sign" => match run_sign_session(&mpc_member_, &conf_, key_name, token).await {
                        Ok(fruit) => fruit,
                        Err(err) => {
                            error!("Failed to run «sign» session (member {} at session {} with key {}) --\n {}",
                            &mpc_member_.member_name, &conf_.session_id, key_name, err);
                            panic!("{:#?}", err);
                        }
                    },
                    "keygen_mnem" => {
                        todo!("«keygen_mnem» not implemented yet");
                    }
                    "reshare" => {
                        todo!("«reshare» not implemented yet");
                    }
                    _st => {
                        panic!("invalid session type «{}»", _st);
                    }
                };
                let sql = "INSERT INTO peer_session (session_id, member_name, expire_at, fruit) VALUES (?, ?, ?, ?)";
                let fruit_bytes = fruit.encode_to_vec();
                let _res = sqlx::query(sql)
                    .bind(&conf_.session_id)
                    .bind(&req_.member_name)
                    .bind(expire_at)
                    .bind(fruit_bytes)
                    .execute(&db)
                    .await;
                if let Err(err) = _res {
                    error!("Failed to insert fruit to db -- {}", err);
                    panic!("{:#?}", err);
                };
            });
        }

        if reshare1 {
            // execute mpc algo in another thread.
            return Err(tonic::Status::unimplemented(
                "«Reshare» not implemented yet",
            ));
        }

        Ok(Response::new(Void {}))
    }

    async fn get_session_fruit(
        &self,
        request: Request<SessionId>,
    ) -> Result<Response<SessionFruit>, tonic::Status> {
        let req = request.into_inner();
        let mut fruit = SessionFruit::default();
        let sql = "SELECT fruit FROM peer_session WHERE session_id = ?";
        let _row = sqlx::query(sql)
            .bind(&req.session_id)
            .fetch_optional(&self.sqlite_pool)
            .await;
        if let Err(err) = _row {
            error!(
                "Failed to query fruit of session {} from db -- {}",
                &req.session_id, &err
            );
            return Err(tonic::Status::internal(err.to_string()));
        };
        let row = _row.unwrap();
        if let Some(row) = row {
            let fruit_bytes: Vec<u8> = row.get("fruit");
            // decode bytes to protobuf message, using prost
            let _fruit = SessionFruit::decode(fruit_bytes.as_slice());
            if let Err(err) = _fruit {
                error!(
                    "Failed to decode fruit of session {} from db -- {}",
                    &req.session_id, &err
                );
                return Err(tonic::Status::internal(err.to_string()));
            };
            fruit = _fruit.unwrap();
        }

        Ok(Response::new(fruit))
    }

    async fn abort_session(
        &self,
        request: Request<Whistle>,
    ) -> Result<Response<Void>, tonic::Status> {
        {
            // TODO: Call real abort session
        }

        let sql = "DELETE FROM peer_session WHERE session_id = ?";
        sqlx::query(sql)
            .bind(&request.into_inner().session_id)
            .execute(&self.sqlite_pool)
            .await
            .map_err(|err| tonic::Status::internal(err.to_string()))?;

        Ok(Response::new(Void {}))
    }
}

async fn run_keygen_session(
    mpc_member: &MpcMember,
    conf: &SessionConfig,
    key_name: &str,
) -> Outcome<SessionFruit> {
    let mut keystore = mpc_member.algo_keygen().await.catch_()?;
    keystore.key_arch = KeyArch::from(conf);

    let buf = keystore.compress().catch_()?;
    let path = if key_name.is_empty() {
        format!("{}@{}.keystore", &mpc_member.member_name, conf.session_id)
    } else {
        format!("{}@{}.keystore", &mpc_member.member_name, key_name)
    };
    let mut file = File::create(&path).await.catch_()?;
    file.write_all(&buf).await.catch_()?;

    let root_xpub = keystore.attr_root_xpub().catch_()?;
    let fruit = SessionFruit {
        value: Some(SessionFruitValue::RootXpub(root_xpub)),
    };

    Ok(fruit)
}

async fn run_sign_session(
    mpc_member: &MpcMember,
    conf: &SessionConfig,
    key_name: &str,
    token: &str,
) -> Outcome<SessionFruit> {
    let tasks = conf.to_sign.as_ref().ifnone_()?.tx_hashes.clone();
    assert_throw!(tasks.len() > 0, "No task to sign.");
    if tasks.len() > 1 {
        throw!("Unimplemented", "Batch sign not ready yet");
    }

    let path = &format!("{}@{}.keystore", &mpc_member.member_name, key_name);
    let mut file = File::open(path).await.catch_()?;
    let mut buf: Vec<u8> = Vec::new();
    file.read_to_end(&mut buf).await.catch_()?;
    let keystore: KeyStore = buf.decompress().catch_()?;

    if false {
        // TODO: Enable token check
        let root_xpub = keystore.attr_root_xpub().catch_()?;
        let minutes = now() / 60;
        let minutes_min = min(minutes, minutes - 3);
        let minutes_max = max(minutes, minutes + 3);
        let mut allow_to_use = false;
        for minute in minutes_min..=minutes_max {
            let text = format!("{}{}", &root_xpub, minute);
            let mut hasher: Blake2b<U16> = Blake2b::new();
            hasher.update(text.as_bytes());
            let hash = hasher.finalize();
            let hex_hash = hex::encode(hash);
            if hex_hash == token {
                allow_to_use = true;
                break;
            }
        }
        assert_throw!(allow_to_use, "Wrong token. Not allowed to use this key.");
    }

    // TODO: Ensure keyarch is same as session config

    let mut sigs = Vec::new();
    if tasks.len() == 1 {
        let sig = mpc_member.algo_sign(&keystore, &tasks[0]).await.catch_()?;
        sigs.push(sig);
    } else {
        throw!("Unimplemented", "Batch sign not ready yet");
    }

    let fruit = SessionFruit {
        value: Some(SessionFruitValue::Signatures(Signatures {
            signatures: sigs,
        })),
    };

    Ok(fruit)
}
