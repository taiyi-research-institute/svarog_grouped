use clap::{Arg, ArgAction, Command};
use svarog_grpc::protogen::svarog::{
    mpc_session_manager_client::MpcSessionManagerClient, Group, Member, SessionConfig, ToSign,
    TxHash,
};
use xuanmi_base_support::*;

#[tokio::main]
async fn main() -> Outcome<()> {
    let matches = Command::new("svarog_mpc_example")
        .arg(
            Arg::new("url_sesmon")
                .short('u')
                .default_value("http://127.0.0.1:9000")
                .action(ArgAction::Set),
        )
        .arg(Arg::new("mode").required(true).action(ArgAction::Set))
        .get_matches();
    let url_sesmon: String = matches
        .get_one::<String>("url_sesmon")
        .ifnone_()?
        .to_owned();
    let mode: String = matches.get_one::<String>("mode").ifnone_()?.to_owned();

    let mut grpc_client = MpcSessionManagerClient::connect(url_sesmon)
        .await
        .catch_()?;

    let conf = match mode.as_str() {
        "keygen" => init_keygen_config(),
        "sign" => init_sign_config(),
        "reshare" => todo!(),
        _ => throw!("InvalidMode", &mode),
    };
    let conf_resp: SessionConfig = grpc_client.new_session(conf).await.catch_()?.into_inner();
    println!("{:#?}", &conf_resp);

    Ok(())
}

fn init_keygen_config() -> SessionConfig {
    let mut conf = SessionConfig::default();
    conf.session_id = "keygen".to_owned();
    conf.session_type = "keygen".to_owned();
    conf.key_quorum = 4;

    let mut group_halogen = Group::default();
    group_halogen.group_name = "halogen".to_owned();
    group_halogen.group_quorum = 2;
    group_halogen.members.push(Member {
        member_name: "fluorine".to_owned(),
        member_id: 0,
        is_attending: true,
    });
    group_halogen.members.push(Member {
        member_name: "chlorine".to_owned(),
        member_id: 0,
        is_attending: true,
    });
    group_halogen.members.push(Member {
        member_name: "bromine".to_owned(),
        member_id: 0,
        is_attending: true,
    });
    conf.groups.push(group_halogen);

    let mut group_noble_gas = Group::default();
    group_noble_gas.group_name = "noble_gas".to_owned();
    group_noble_gas.group_quorum = 1;
    group_noble_gas.members.push(Member {
        member_name: "helium".to_owned(),
        member_id: 0,
        is_attending: true,
    });
    group_noble_gas.members.push(Member {
        member_name: "neon".to_owned(),
        member_id: 0,
        is_attending: true,
    });
    group_noble_gas.members.push(Member {
        member_name: "argon".to_owned(),
        member_id: 0,
        is_attending: true,
    });
    conf.groups.push(group_noble_gas);

    conf
}

fn init_sign_config() -> SessionConfig {
    let mut conf = SessionConfig::default();
    conf.session_id = "sign".to_owned();
    conf.session_type = "sign".to_owned();
    conf.key_quorum = 4;

    let mut group_halogen = Group::default();
    group_halogen.group_name = "halogen".to_owned();
    group_halogen.group_quorum = 2;
    group_halogen.members.push(Member {
        member_name: "fluorine".to_owned(),
        member_id: 0,
        is_attending: false,
    });
    group_halogen.members.push(Member {
        member_name: "chlorine".to_owned(),
        member_id: 0,
        is_attending: true,
    });
    group_halogen.members.push(Member {
        member_name: "bromine".to_owned(),
        member_id: 0,
        is_attending: true,
    });
    conf.groups.push(group_halogen);

    let mut group_noble_gas = Group::default();
    group_noble_gas.group_name = "noble_gas".to_owned();
    group_noble_gas.group_quorum = 1;
    group_noble_gas.members.push(Member {
        member_name: "helium".to_owned(),
        member_id: 0,
        is_attending: true,
    });
    group_noble_gas.members.push(Member {
        member_name: "neon".to_owned(),
        member_id: 0,
        is_attending: false,
    });
    group_noble_gas.members.push(Member {
        member_name: "argon".to_owned(),
        member_id: 0,
        is_attending: true,
    });
    conf.groups.push(group_noble_gas);

    let mut tasks: Vec<TxHash> = Vec::new();
    tasks.push(TxHash {
        tx_hash: hex::decode("f935e58e85f81d3a8ebcb4ebf4f98b1df935e58e85f81d3a8ebcb4ebf4f98b1d")
            .unwrap(),
        derive_path: "m".to_owned(),
    });
    tasks.push(TxHash {
        tx_hash: hex::decode("d3a8ebcb4ebf4f98b1df935e58e85f81d3a8ebcb4ebf4f98b1df935e58e85f81")
            .unwrap(),
        derive_path: "m/0".to_owned(),
    });
    tasks.push(TxHash {
        tx_hash: hex::decode("cb4ebf4f98b1df935e58e85f81d3a8ebcb4ebf4f98b1df935e58e85f81d3a8eb")
            .unwrap(),
        derive_path: "m/0/1".to_owned(),
    });
    tasks.push(TxHash {
        tx_hash: hex::decode("ebcb4ebf4f98b1df935e58e85f81d3a8ebcb4ebf4f98b1df935e58e85f81d3a8")
            .unwrap(),
        derive_path: "m/0/1/2".to_owned(),
    });
    conf.to_sign = Some(ToSign { tx_hashes: tasks });

    conf
}
