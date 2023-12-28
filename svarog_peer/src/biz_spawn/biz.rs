use super::SQL_INSERT_SESSION_FRUIT;
use crate::prelude::*;
use svarog_grpc::{
    prelude::prost::Message,
    protogen::svarog::{Signatures, TxHash},
};
use svarog_mpc_sdk::biz_algo::{AlgoKeygen, AlgoReshare, AlgoSign, KeyStore};

pub async fn biz_keygen(mpc_member: &MpcMember) -> Outcome<Vec<u8>> {
    let keystore = mpc_member.algo_keygen().await.catch_()?;
    let buf = keystore.compress().catch_()?;
    let path = format!(
        "assets/{}@{}.keystore",
        &mpc_member.member_name, &mpc_member.session_id
    );
    let mut file = File::create(&path).await.catch_()?;
    file.write_all(&buf).await.catch_()?;
    let root_xpub = keystore.attr_root_xpub().catch_()?;
    let fruit = SessionFruit {
        value: Some(SessionFruitValue::RootXpub(root_xpub)),
    };
    let fruit_bytes = fruit.encode_to_vec();
    Ok(fruit_bytes)
}

pub async fn biz_sign(
    mpc_member: &MpcMember,
    key_name: &str,
    _token: &str,
    task: &TxHash,
) -> Outcome<Vec<u8>> {
    let keystore: KeyStore = {
        let path = &format!("assets/{}@{}.keystore", &mpc_member.member_name, &key_name);
        let mut file = File::open(path).await.catch_()?;
        let mut buf: Vec<u8> = Vec::new();
        if let Err(err) = file.read_to_end(&mut buf).await {
            error!("Failed to read keystore file -- {}", err);
            panic!("{:#?}", err);
        }
        let keystore = buf.decompress();
        if let Err(err) = keystore {
            error!("Failed to decompress keystore -- {}", err);
            panic!("{:#?}", err);
        }
        keystore.unwrap()
    };

    {
        // TODO: Enable token check
        // TODO: Validate keyarch
    }

    let sig = mpc_member.algo_sign(&keystore, task).await.catch_()?;
    let sigs = Signatures {
        signatures: vec![sig],
    };
    let fruit = SessionFruit {
        value: Some(SessionFruitValue::Signatures(sigs)),
    };
    let fruit_bytes = fruit.encode_to_vec();

    Ok(fruit_bytes)
}

pub async fn biz_reshare_provider(
    mpc_member: &MpcMember,
    key_name: &str,
    _token: &str,
) -> Outcome<Vec<u8>> {
    let keystore: KeyStore = {
        let path = &format!("assets/{}@{}.keystore", &mpc_member.member_name, &key_name);
        let mut file = File::open(path).await.catch_()?;
        let mut buf: Vec<u8> = Vec::new();
        file.read_to_end(&mut buf).await.catch_()?;
        buf.decompress().catch_()?
    };

    {
        // TODO: Enable token check
        // TODO: Validate keyarch
    }

    mpc_member.algo_reshare_provider(&keystore).await.catch_()?;
    let fruit = SessionFruit {
        value: Some(SessionFruitValue::RootXpub("PROVIDED".to_string())), // alphabet I and O are not used in base58. Thus we can use "PROVIDED" to identify a provider.
    };
    let fruit_bytes = fruit.encode_to_vec();

    Ok(fruit_bytes)
}

pub async fn biz_reshare_consumer(mpc_member: &MpcMember) -> Outcome<Vec<u8>> {
    let keystore = mpc_member.algo_reshare_consumer().await.catch_()?;
    let buf = keystore.compress().catch_()?;
    let path = format!(
        "assets/{}@{}.keystore",
        &mpc_member.member_name, &mpc_member.session_id
    );
    let mut file = File::create(&path).await.catch_()?;
    file.write_all(&buf).await.catch_()?;
    let root_xpub = keystore.attr_root_xpub().catch_()?;
    let fruit = SessionFruit {
        value: Some(SessionFruitValue::RootXpub(root_xpub)),
    };
    let fruit_bytes = fruit.encode_to_vec();

    Ok(fruit_bytes)
}

#[async_trait]
pub trait PostFruit {
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
