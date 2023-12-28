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
    only_post_on_fail: bool,
) {
    tokio::spawn(async move {
        let fruit_bytes: Outcome<Vec<u8>> =
            biz_reshare_provider(&mpc_member, &key_name, &token).await;
        if only_post_on_fail {
            if let Err(_) = fruit_bytes {
                mpc_member.post_fruit(&db, fruit_bytes).await;
            }
        } else {
            mpc_member.post_fruit(&db, fruit_bytes).await;
        }
    });
}

pub fn spawn_reshare_consumer(db: SqlitePool, mpc_member: MpcMember) {
    tokio::spawn(async move {
        let fruit_bytes: Outcome<Vec<u8>> = biz_reshare_consumer(&mpc_member).await;
        mpc_member.post_fruit(&db, fruit_bytes).await;
    });
}
