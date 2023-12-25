use blake2::{digest::consts::U16, Blake2b, Digest};
use sqlx::{Row, SqlitePool};
use std::cmp::{max, min};
use std::path;
use svarog_grpc::prelude::{prost::Message, tonic::transport::Server};
use svarog_grpc::protogen::svarog::mpc_peer_server::MpcPeerServer;
use svarog_grpc::protogen::svarog::{
    mpc_peer_server::MpcPeer, JoinSessionRequest, SessionFruit, SessionId, Void, Whistle,
};
use svarog_grpc::protogen::svarog::{SessionConfig, Signatures};
use svarog_mpc_sdk::biz_algo::{AlgoKeygen, AlgoSign, KeyArch, KeyStore};
use svarog_mpc_sdk::{now, CompressAble, DecompressAble, MpcMember, SessionFruitValue};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tonic::{async_trait, Request, Response};
use xuanmi_base_support::{tracing::*, *};
mod config;
use config::MpcServiceConfig;
const CONF_PATH: &'static str = "mpc_service_config.toml";

#[tokio::main]
async fn main() -> Outcome<()> {
    let conf_path_existing = path::Path::new(CONF_PATH).exists();
    assert_throw!(
        conf_path_existing,
        &format!(
            "{}\n{}",
            "`mpc_service_config.toml` not found.",
            "Originally, this file accompanies the executable."
        )
    );
    let conf_str = tokio::fs::read_to_string(CONF_PATH).await.catch_()?;
    let conf: MpcServiceConfig = toml::from_str(&conf_str).catch(
        "InvalidConfigFile",
        "Cannot decode `mpc_service_config.toml`. DO NOT rename or remove any field.",
    )?;

    let available_log_level = vec!["trace", "debug", "info", "warn", "error"];
    assert_throw!(available_log_level.contains(&conf.logging.Level.as_str()));
    init_tracer!("logs", "mpc_peer.log", &conf.logging.Level);

    let service = MpcPeerService::new(
        &conf.peer.SqlitePath,
        &conf.sesman.GrpcHost,
        conf.sesman.GrpcPort,
    )
    .await
    .catch("CannotCreatePeerService", "")?;
    let listen_at = format!("{}:{}", &conf.peer.GrpcHost, conf.peer.GrpcPort);
    println!("MpcPeerService will listen at {}", &listen_at);

    Server::builder()
        .add_service(MpcPeerServer::new(service))
        .serve(listen_at.parse().unwrap())
        .await
        .catch("Mpc Peer is down", "")?;
    Ok(())
}

pub struct MpcPeerService {
    pub sqlite_pool: SqlitePool,
    pub sesman_hostport: String,
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
    pub async fn new(sqlite_path: &str, sesman_host: &str, sesman_port: u16) -> Outcome<Self> {
        if path::Path::new(&sqlite_path).exists() {
            let _ = tokio::fs::remove_file(sqlite_path)
                .await
                .catch("CannotRemoveFile", sqlite_path)?;
        }
        let _ = tokio::fs::File::create(sqlite_path)
            .await
            .catch("CannotCreateFile", sqlite_path)?;

        let sqlite_pool = SqlitePool::connect(&sqlite_path)
            .await
            .catch("CannotConnectSqlite", sqlite_path)?;
        let _ = sqlx::query(CREATE_TABLE)
            .execute(&sqlite_pool)
            .await
            .catch("CannotCreateTable", sqlite_path)?;

        Ok(Self {
            sqlite_pool,
            sesman_hostport: format!("{}:{}", sesman_host, sesman_port),
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
        println!("MpcPeer.JoinSession -- {:#?}", &req);
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

        let mpc_member = MpcMember::new(&self.sesman_hostport)
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
            println!(
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
    println!(
        "member: {}, key_quorum: {}, ses_arch: {:#?}",
        &mpc_member.member_name, &conf.key_quorum, &conf.groups
    );
    let mut keystore = mpc_member.algo_keygen().await.catch_()?;
    keystore.key_arch = KeyArch::from(conf);

    let buf = keystore.compress().catch_()?;
    let path = if key_name.is_empty() {
        format!(
            "assets/{}@{}.keystore",
            &mpc_member.member_name, conf.session_id
        )
    } else {
        format!("assets/{}@{}.keystore", &mpc_member.member_name, key_name)
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
    println!(
        "member: {}, key_quorum: {}, ses_arch: {:#?}",
        &mpc_member.member_name, &conf.key_quorum, &conf.groups
    );
    let tasks = conf.to_sign.as_ref().ifnone_()?.tx_hashes.clone();
    assert_throw!(tasks.len() > 0, "No task to sign.");
    if tasks.len() > 1 {
        throw!("Unimplemented", "Batch sign not ready yet");
    }

    let path = &format!("assets/{}@{}.keystore", &mpc_member.member_name, key_name);
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
