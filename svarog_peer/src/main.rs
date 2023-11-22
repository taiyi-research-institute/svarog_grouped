use sqlx::{Row, SqlitePool};
use svarog_grpc::prelude::{prost::Message, tonic::transport::Server};
use svarog_grpc::protogen::svarog::mpc_peer_server::MpcPeerServer;
use svarog_grpc::protogen::svarog::{
    mpc_peer_server::MpcPeer, JoinSessionRequest, SessionConfig, SessionFruit, SessionId, Void,
    Whistle,
};
use svarog_mpc_sdk::{mpc_member, MpcMember, SessionFruitValue};
use tonic::{async_trait, Request, Response};
use xuanmi_base_support::*;

pub struct MpcPeerService {
    pub sqlite_pool: SqlitePool,
    pub mpc_sesmon_hostport: String,
}

const CREATE_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS mpc_session (
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
    let service = MpcPeerService::new("", "127.0.0.1:9000").await?;
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
        let session_id = req.session_id.clone();
        let member_name = req.member_name.clone();
        let row = sqlx::query(sql)
            .bind(&session_id)
            .bind(&member_name)
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
        let ses_conf = mpc_member
            .fetch_session_config(&session_id)
            .await
            .map_err(|e| tonic::Status::internal(e.to_string()))?;
        let expire_at = ses_conf.expire_before_finish;

        let mut reshare0 = false;
        let mut reshare1 = false;
        for group in ses_conf.groups.iter() {
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
            let mut mpc_member0 = mpc_member.clone();
            mpc_member0
                .use_session_config(&ses_conf, &req.member_name, false)
                .map_err(|e| tonic::Status::internal(e.to_string()))?;

            let db = self.sqlite_pool.clone();
            let sid_thlocal = session_id.clone();
            let mn_thlocal = member_name.clone();
            tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
                let sql = "UPDATE session SET fruit = ? WHERE session_id = ? AND member_name = ?";
                let rxb = "xpub661MyMwAqRbcEptpGtn77MuxVtCqFWsJxHKEwQUR5bci3vAtMjdY1utK1XKTFjoSP4GKwtioQBicjDByasN6GZELYALsHhQ6dpHBxN6BNir".to_owned();
                let fruit = SessionFruit {
                    value: Some(SessionFruitValue::RootXpub(rxb)),
                };
                let fruit_bytes = fruit.encode_to_vec();
                let _ = sqlx::query(sql)
                    .bind(fruit_bytes)
                    .bind(sid_thlocal)
                    .bind(mn_thlocal)
                    .execute(&db)
                    .await
                    .unwrap();
            });

            if !reshare1 {
                // insert session
                let sql = "INSERT INTO session (session_id, member_name, expire_at) VALUES (?, ?)";
                let _ = sqlx::query(sql)
                    .bind(&session_id)
                    .bind(&member_name)
                    .bind(expire_at)
                    .execute(&self.sqlite_pool)
                    .await
                    .map_err(|err| tonic::Status::internal(err.to_string()))?;
            }
        }

        if reshare1 {
            // execute mpc algo in another thread.
            let mut mpc_member1 = mpc_member.clone();
            mpc_member1
                .use_session_config(&ses_conf, &req.member_name, true)
                .map_err(|e| tonic::Status::internal(e.to_string()))?;

            let db = self.sqlite_pool.clone();
            let sid_thlocal = session_id.clone();
            let mn_thlocal = member_name.clone();
            tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
                let sql = "UPDATE session SET fruit = ? WHERE session_id = ? AND member_name = ?";
                let rxb = "xpub661MyMwAqRbcEptpGtn77MuxVtCqFWsJxHKEwQUR5bci3vAtMjdY1utK1XKTFjoSP4GKwtioQBicjDByasN6GZELYALsHhQ6dpHBxN6BNir".to_owned();
                let fruit = SessionFruit {
                    value: Some(SessionFruitValue::RootXpub(rxb)),
                };
                let fruit_bytes = fruit.encode_to_vec();
                let _ = sqlx::query(sql)
                    .bind(fruit_bytes)
                    .bind(sid_thlocal)
                    .bind(mn_thlocal)
                    .execute(&db)
                    .await
                    .unwrap();
            });

            // insert session
            let sql = "INSERT INTO session (session_id, member_name, expire_at) VALUES (?, ?)";
            let _ = sqlx::query(sql)
                .bind(&session_id)
                .bind(&member_name)
                .bind(expire_at)
                .execute(&self.sqlite_pool)
                .await
                .map_err(|err| tonic::Status::internal(err.to_string()))?;
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
