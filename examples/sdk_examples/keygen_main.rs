use clap::{arg, Arg, ArgAction, Command, Parser};
use svarog_mpc_sdk::{
    biz_algo::{AlgoKeygen, KeyArch},
    exception::*,
    CompressAble, MpcMember,
};
use tokio::{fs::File, io::AsyncWriteExt};

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
            Arg::new("url_sesmon")
                .short('u')
                .default_value("http://127.0.0.1:9000")
                .action(ArgAction::Set),
        )
        .get_matches();
    let member_name: String = matches
        .get_one::<String>("member_name")
        .ifnone_()?
        .to_owned();
    let url_sesmon: String = matches
        .get_one::<String>("url_sesmon")
        .ifnone_()?
        .to_owned();

    let mut member = MpcMember::new(&url_sesmon).await.catch_()?;
    let conf = member.fetch_session_config("keygen").await.catch_()?;

    member
        .use_session_config(&conf, &member_name, false)
        .catch_()?;

    let keystore = member.algo_keygen().await.catch_()?;
    let buf = keystore.compress().catch_()?;
    let path = &format!("assets/{}@{}.keystore", member_name, conf.session_id);
    let mut file = File::create(path).await.catch_()?;
    file.write_all(&buf).await.catch_()?;

    Ok(())
}
