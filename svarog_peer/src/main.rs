use blake2::{digest::consts::U16, Blake2b, Digest};
use sqlx::{Row, SqlitePool};
use std::cmp::{max, min};
use svarog_grpc::prelude::{prost::Message, tonic::transport::Server};
use svarog_grpc::protogen::svarog::mpc_peer_server::MpcPeerServer;
use svarog_grpc::protogen::svarog::Signatures;
use svarog_grpc::protogen::svarog::{
    mpc_peer_server::MpcPeer, JoinSessionRequest, SessionFruit, SessionId, Void, Whistle,
};
use svarog_mpc_sdk::gg18::{AlgoKeygen, AlgoSign, KeyArch, KeyStore};
use svarog_mpc_sdk::{now, CompressAble, DecompressAble, MpcMember, SessionFruitValue};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tonic::{async_trait, Request, Response};
use xuanmi_base_support::*;

pub struct MpcPeerService {
    pub sqlite_pool: SqlitePool,
    pub mpc_sesmon_hostport: String,
}

const CREATE_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS session (
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
            "sqlite://:memory:".to_owned()
        } else {
            format!("sqlite://{}", sqlite_db_path)
        };
        let sesmon: &str = if mpc_sesmon_hostport == "" {
            "localhost:9000"
        } else {
            mpc_sesmon_hostport
        };
        let sqlite_pool = SqlitePool::connect(&url).await.catch_()?;
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = MpcPeerService::new("", "http://127.0.0.1:9000").await?;
    Server::builder()
        .add_service(MpcPeerServer::new(service))
        .serve("127.0.0.1:9001".parse().unwrap())
        .await?;
    Ok(())
}

#[async_trait]
impl MpcPeer for MpcPeerService {
    async fn join_session(
        &self,
        request: Request<JoinSessionRequest>,
    ) -> Result<Response<Void>, tonic::Status> {
        let req = request.into_inner();
        let sql = "SELECT COUNT(session_id) AS count FROM session WHERE session_id = ? AND member_name = ?";
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

        println!("{}", self.mpc_sesmon_hostport);
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
                let fruit;
                match conf.session_type.as_str() {
                    "keygen" => {
                        let mut keystore = mpc_member_
                            .algo_keygen()
                            .await
                            .map_err(|e| tonic::Status::internal(e.to_string()))
                            .unwrap();
                        keystore.key_arch = KeyArch::from(&conf_);

                        let buf = keystore.compress().unwrap();
                        let path = if req_.key_name.is_empty() {
                            format!("{}@{}.keystore", &req_.member_name, conf.session_id)
                        } else {
                            format!("{}@{}.keystore", &req_.member_name, &req_.key_name)
                        };
                        let mut file = File::create(&path).await.unwrap();
                        file.write_all(&buf).await.unwrap();

                        let root_xpub = keystore.attr_root_xpub().unwrap();
                        println!("root_xpub: {}", root_xpub);
                        fruit = SessionFruit {
                            value: Some(SessionFruitValue::RootXpub(root_xpub)),
                        };
                    }
                    "sign" => {
                        let tasks = conf_.to_sign.unwrap().tx_hashes.clone();
                        assert!(tasks.len() > 0, "No task to sign.");
                        if tasks.len() > 1 {
                            todo!("Batch sign not ready yet");
                        }
                        assert!(tasks.len() == 1, "Batch sign not ready yet.");

                        let path = &format!("{}@{}.keystore", &req_.member_name, &req_.key_name);
                        let mut file = File::open(path).await.unwrap();
                        let mut buf: Vec<u8> = Vec::new();
                        file.read_to_end(&mut buf).await.unwrap();
                        let keystore: KeyStore = buf.decompress().unwrap();

                        let root_xpub = keystore.attr_root_xpub().unwrap();
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
                            if hex_hash == req_.token {
                                allow_to_use = true;
                                break;
                            }
                        }
                        assert!(allow_to_use, "Wrong token. Not allowed to use this key.");

                        // TODO: Ensure keyarch is same as session config

                        let mut sigs = Vec::new();
                        if tasks.len() == 1 {
                            let sig = mpc_member_
                                .algo_sign(&keystore, &tasks[0])
                                .await
                                .map_err(|e| tonic::Status::internal(e.to_string()))
                                .unwrap();
                            sigs.push(sig);
                        } else {
                            todo!("Batch sign not ready yet");
                        }

                        fruit = SessionFruit {
                            value: Some(SessionFruitValue::Signatures(Signatures {
                                signatures: sigs,
                            })),
                        };
                    }
                    "keygen_mnem" => {
                        todo!("keygen_mnem not ready yet");
                    }
                    "reshare" => {
                        todo!("reshare222 not ready yet");
                    }
                    _st => {
                        panic!("invalid session type «{}»", _st);
                    }
                }
                // if conf_.session_type == "keygen" {
                //     let fruit = mpc_member_
                //         .algo_keygen()
                //         .await
                //         .map_err(|e| tonic::Status::internal(e.to_string()))
                //         .unwrap();
                // }
                // let sql = "UPDATE session SET fruit = ? WHERE session_id = ? AND member_name = ?";
                let sql = "INSERT INTO session (session_id, member_name, expire_at, fruit) VALUES (?, ?, ?, ?)";
                let fruit_bytes = fruit.encode_to_vec();
                println!("fruit_bytes: {:?}", fruit_bytes);
                println!("session_id: {}", &conf_.session_id);
                println!("member_name: {}", &req_.member_name);
                let _ = sqlx::query(sql)
                    .bind(&conf_.session_id)
                    .bind(&req_.member_name)
                    .bind(expire_at)
                    .bind(fruit_bytes)
                    .execute(&db)
                    .await
                    .unwrap();
            });

            // if !reshare1 {
            //     todo!("reshare111 not ready yet");
            // }
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
        let mut fruit = SessionFruit::default();
        let sql = "SELECT fruit FROM session WHERE session_id = ?";
        let row = sqlx::query(sql)
            .bind(request.into_inner().session_id)
            .fetch_optional(&self.sqlite_pool)
            .await
            .map_err(|err| tonic::Status::internal(err.to_string()))?;
        if let Some(row) = row {
            let fruit_bytes: Vec<u8> = row.get("fruit");
            // decode bytes to protobuf message, using prost
            fruit = SessionFruit::decode(fruit_bytes.as_slice())
                .map_err(|err| tonic::Status::internal(err.to_string()))?;
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

        let sql = "DELETE FROM session WHERE session_id = ?";
        sqlx::query(sql)
            .bind(&request.into_inner().session_id)
            .execute(&self.sqlite_pool)
            .await
            .map_err(|err| tonic::Status::internal(err.to_string()))?;

        Ok(Response::new(Void {}))
    }
}
