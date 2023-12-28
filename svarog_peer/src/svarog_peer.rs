pub mod prelude {
    pub use sqlx::{Row, SqlitePool};
    pub use svarog_mpc_sdk::exception::{self, *};
    pub use svarog_mpc_sdk::{assert_throw, throw};
    pub use tokio::fs::File;
    pub use tokio::io::{AsyncReadExt, AsyncWriteExt};
    pub use tonic::{async_trait, Request, Response};
    pub use tracing::error;

    pub use svarog_mpc_sdk::{
        CompressAble, DecompressAble, MpcMember, SessionFruit, SessionFruitValue,
    };
}
use prelude::*;
use svarog_grpc::protogen::svarog::GetSessionFruitRequest;

use std::path;
use svarog_grpc::prelude::{prost::Message, tonic::transport::Server};
use svarog_grpc::protogen::svarog::mpc_peer_server::MpcPeerServer;
use svarog_grpc::protogen::svarog::{mpc_peer_server::MpcPeer, JoinSessionRequest, Void, Whistle};

mod config;
use config::MpcServiceConfig;
mod role;
use role::*;
mod biz_spawn;
use biz_spawn::*;
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
    pub sesman_url: String,
}

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
        let _ = sqlx::query(SQL_CREATE_TABLE)
            .execute(&sqlite_pool)
            .await
            .catch("CannotCreateTable", sqlite_path)?;

        Ok(Self {
            sqlite_pool,
            sesman_url: format!("http://{}:{}", sesman_host, sesman_port),
        })
    }
}

#[async_trait]
impl MpcPeer for MpcPeerService {
    // TODO: Refactor by roles:
    // keygen, signer, mnem provider, reshare provider, reshare consumer.
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

        let mut mpc_member = MpcMember::new(&self.sesman_url)
            .await
            .map_err(|e| tonic::Status::internal(e.to_string()))?;
        let conf = mpc_member
            .fetch_session_config(&req.session_id)
            .await
            .map_err(|e| tonic::Status::internal(e.to_string()))?;

        let role = parse_role(&conf, &req).map_err(|e| tonic::Status::internal(e.to_string()))?;
        match role {
            Role::KeyGenerator => {
                mpc_member
                    .use_session_config(&conf, &req.member_name, false)
                    .map_err(|err| tonic::Status::internal(err.to_string()))?;
                spawn_keygen(self.sqlite_pool.clone(), mpc_member.clone());
            }
            Role::Signer(SignPayload::Single(task)) => {
                mpc_member
                    .use_session_config(&conf, &req.member_name, false)
                    .map_err(|err| tonic::Status::internal(err.to_string()))?;
                spawn_sign(
                    self.sqlite_pool.clone(),
                    mpc_member.clone(),
                    req.key_name.clone(),
                    req.token.clone(),
                    task,
                );
            }
            Role::Signer(SignPayload::Batch(_tasks)) => {
                todo!()
            }
            Role::MnemProvider => {
                todo!()
            }
            Role::Reshare(ReshareRole::Provider) => {
                mpc_member
                    .use_session_config(&conf, &req.member_name, false)
                    .map_err(|err| tonic::Status::internal(err.to_string()))?;
                spawn_reshare_provider(
                    self.sqlite_pool.clone(),
                    mpc_member.clone(),
                    req.key_name.clone(),
                    req.token.clone(),
                    false,
                );
            }
            Role::Reshare(ReshareRole::Consumer) => {
                mpc_member
                    .use_session_config(&conf, &req.member_name, true)
                    .map_err(|err| tonic::Status::internal(err.to_string()))?;
                spawn_reshare_consumer(self.sqlite_pool.clone(), mpc_member.clone());
            }
            Role::Reshare(ReshareRole::Both) => {
                mpc_member
                    .use_session_config(&conf, &req.member_name, false)
                    .map_err(|err| tonic::Status::internal(err.to_string()))?;
                spawn_reshare_provider(
                    self.sqlite_pool.clone(),
                    mpc_member.clone(),
                    req.key_name.clone(),
                    req.token.clone(),
                    true,
                );
                mpc_member
                    .use_session_config(&conf, &req.member_name, true)
                    .map_err(|err| tonic::Status::internal(err.to_string()))?;
                spawn_reshare_consumer(self.sqlite_pool.clone(), mpc_member.clone());
            }
        }

        Ok(Response::new(Void {}))
    }

    async fn get_session_fruit(
        &self,
        request: Request<GetSessionFruitRequest>,
    ) -> Result<Response<SessionFruit>, tonic::Status> {
        let ses_id = request.get_ref().session_id.as_str();
        let mem_name = request.get_ref().member_name.as_str();
        let _rows = sqlx::query(SQL_SELECT_SESSION_FRUIT)
            .bind(ses_id)
            .bind(mem_name)
            .fetch_all(&self.sqlite_pool)
            .await;
        if let Err(err) = _rows {
            error!(
                "Failed to query fruit of session {} from db -- {}",
                &ses_id, &err
            );
            return Err(tonic::Status::internal(err.to_string()));
        };
        let rows = _rows.unwrap();

        if rows.len() == 0 {
            return Ok(Response::new(SessionFruit::default()));
        } else if rows.len() == 1 {
            let row = &rows[0];
            let fb: Option<Vec<u8>> = row.get("fruit");
            let ex: Option<String> = row.get("exception");
            if let Some(ex) = ex {
                return Err(tonic::Status::internal(ex));
            }
            let fb = fb.unwrap(); // fb is Some, iff ex is None

            let _fruit = SessionFruit::decode(fb.as_slice());
            if let Err(err) = _fruit {
                error!("Failed to decode fruit of member {} -- {}", mem_name, &err);
                return Err(tonic::Status::internal(err.to_string()));
            };
            let fruit = _fruit.unwrap();
            return Ok(Response::new(fruit));
        } else {
            // In case a victim being both provider and consumer.
            let mut report: String = String::new();
            let row = &rows[0];
            let ex: Option<String> = row.get("exception");
            report.push_str(&ex.unwrap());
            let row = &rows[1];
            let ex: Option<String> = row.get("exception");
            report.push_str(&ex.unwrap());
            return Err(tonic::Status::internal(report));
        }
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

#[macro_export]
macro_rules! init_tracer {
    ($log_dir:expr, $logfile_prefix:expr, $log_level:expr) => {
        let level = match ($log_level).to_lowercase().as_str() {
            "trace" => tracing::Level::TRACE,
            "debug" => tracing::Level::DEBUG,
            "info" => tracing::Level::INFO,
            "warn" => tracing::Level::WARN,
            "error" => tracing::Level::ERROR,
            _ => tracing::Level::INFO,
        };
        let file_appender = tracing_appender::rolling::daily($log_dir, $logfile_prefix);
        let (nbl, _guard) = tracing_appender::non_blocking(file_appender);
        let subscriber = tracing_subscriber::fmt::Subscriber::builder()
            .with_writer(nbl)
            .with_max_level(level)
            .with_thread_ids(true)
            // without unsetting ANSI mode, the log file will be flattered with ANSI escape codes.
            .with_ansi(false)
            .compact()
            .pretty()
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();
    };
}
