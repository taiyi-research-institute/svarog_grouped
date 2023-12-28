use crate::prelude::*;
use svarog_grpc::protogen::svarog::TxHash;
mod biz;
use biz::*;
mod sql;
pub use sql::*;

pub fn spawn_keygen(db: SqlitePool, mpc_member: MpcMember) {
    tokio::spawn(async move {
        let fruit_bytes: Outcome<Vec<u8>> = biz_keygen(&mpc_member).await;
        mpc_member.post_fruit(&db, fruit_bytes).await;
    });
}

pub fn spawn_sign(
    db: SqlitePool,
    mpc_member: MpcMember,
    key_name: String,
    token: String,
    task: TxHash,
) {
    tokio::spawn(async move {
        let fruit_bytes: Outcome<Vec<u8>> = biz_sign(&mpc_member, &key_name, &token, &task).await;
        mpc_member.post_fruit(&db, fruit_bytes).await;
    });
}

pub fn spawn_reshare_provider(
    db: SqlitePool,
    mpc_member: MpcMember,
    key_name: String,
    token: String,
) {
    tokio::spawn(async move {
        let fruit_bytes: Outcome<Vec<u8>> =
            biz_reshare_provider(&mpc_member, &key_name, &token).await;
        mpc_member.post_fruit(&db, fruit_bytes).await;
    });
}

pub fn spawn_reshare_consumer(db: SqlitePool, mpc_member: MpcMember) {
    tokio::spawn(async move {
        let fruit_bytes: Outcome<Vec<u8>> = biz_reshare_consumer(&mpc_member).await;
        mpc_member.post_fruit(&db, fruit_bytes).await;
    });
}

/* ===== Utilities below ===== */

#[async_trait]
trait PostFruit {
    async fn post_fruit(&self, db: &SqlitePool, fruit_bytes: Outcome<Vec<u8>>);
}

#[async_trait]
impl PostFruit for MpcMember {
    async fn post_fruit(&self, db: &SqlitePool, fruit_bytes: Outcome<Vec<u8>>) {
        let (fb, ex) = match fruit_bytes {
            Ok(fb) => (Some(fb), None),
            Err(ex) => (None, Some(ex.to_string())),
        };
        let _query = sqlx::query(SQL_INSERT_SESSION_FRUIT)
            .bind(&self.session_id)
            .bind(&self.member_id)
            .bind(&self.member_name)
            .bind(&self.expire_at)
            .bind(fb)
            .bind(ex)
            .execute(db)
            .await;
        if let Err(err) = _query {
            error!("Failed to insert fruit to db -- {}", err);
            panic!("{:#?}", err);
        };
    }
}
