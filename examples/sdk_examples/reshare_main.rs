use clap::{arg, Arg, ArgAction, Command, Parser};
use svarog_mpc_sdk::{
    biz_algo::{AlgoReshare, AlgoSign, KeyStore},
    exception::*,
    CompressAble, DecompressAble, MpcMember,
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long)]
    name: String,

    /// Number of times to greet
    #[arg(short, long, default_value_t = 1)]
    count: u8,
}

#[tokio::main]
async fn main() -> Outcome<()> {
    let matches = Command::new("svarog_mpc_example")
        .arg(
            Arg::new("member_name")
                .short('m')
                .required(true)
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("reshare")
                .short('r')
                .required(false)
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("url_sesman")
                .short('u')
                .default_value("http://127.0.0.1:9000")
                .action(ArgAction::Set),
        )
        .get_matches();
    let member_name: String = matches
        .get_one::<String>("member_name")
        .ifnone_()?
        .to_owned();
    let is_reshare: bool = matches.get_flag("reshare");
    let url_sesman: String = matches
        .get_one::<String>("url_sesman")
        .ifnone_()?
        .to_owned();

    let mut member = MpcMember::new(&url_sesman).await.catch_()?;
    let conf = member.fetch_session_config("reshare").await.catch_()?;
    member
        .use_session_config(&conf, &member_name, is_reshare)
        .catch_()?;

    if is_reshare {
        let keystore = member.algo_reshare_consumer().await.catch_()?;
        let buf = keystore.compress().catch_()?;
        let path = &format!("assets/{}@{}.keystore", member_name, conf.session_id);
        let mut file = File::create(path).await.catch_()?;
        file.write_all(&buf).await.catch_()?;
    } else {
        let keystore: KeyStore = {
            let key_name = "keygen".to_owned();
            let path = &format!("assets/{}@{}.keystore", member_name, &key_name);
            println!("Loading keystore from: {}", path);
            let mut file = File::open(path).await.catch_()?;
            let mut buf: Vec<u8> = Vec::new();
            file.read_to_end(&mut buf).await.catch_()?;
            buf.decompress().catch_()?
        };
        member.algo_reshare_provider(&keystore).await.catch_()?;
    }

    if is_reshare {
        // test sign after reshare
        let conf = member
            .fetch_session_config("sign_after_reshare")
            .await
            .catch_()?;
        member
            .use_session_config(&conf, &member_name, false)
            .catch_()?;
        let keystore: KeyStore = {
            let key_name = "reshare".to_owned();
            let path = &format!("assets/{}@{}.keystore", member_name, &key_name);
            println!("Loading keystore from: {}", path);
            let mut file = File::open(path).await.catch_()?;
            let mut buf: Vec<u8> = Vec::new();
            file.read_to_end(&mut buf).await.catch_()?;
            buf.decompress().catch_()?
        };
        for task in conf.to_sign.unwrap().tx_hashes.iter() {
            let sig = member.algo_sign(&keystore, task).await.catch_()?;
            println!("Signature: {:#?}", sig);
        }
    }

    Ok(())
}
