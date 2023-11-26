use clap::{arg, Arg, ArgAction, Command, Parser};
use svarog_mpc_sdk::{gg18::AlgoKeygenMnem, MpcMember};
use xuanmi_base_support::*;

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
            Arg::new("mnem")
                .short('n')
                .required(false)
                .action(ArgAction::SetTrue),
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
    let is_mnem_provider: bool = matches.get_flag("mnem");
    let url_sesmon: String = matches
        .get_one::<String>("url_sesmon")
        .ifnone_()?
        .to_owned();

    let mut member = MpcMember::new(&url_sesmon).await.catch_()?;
    let conf = member.fetch_session_config("keygen").await.catch_()?;

    member
        .use_session_config(&conf, &member_name, false)
        .catch_()?;

    let (mnem, pwd) = if is_mnem_provider {
        let mnem = "park remain person kitchen mule spell knee armed position rail grid ankle";
        let pwd = "";
        (mnem, pwd)
    } else {
        ("", "")
    };
    let keystore = member.algo_keygen_mnem(mnem, pwd).await.catch_()?;

    println!("keystore: {:#?}", keystore);

    Ok(())
}
