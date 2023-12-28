use crate::prelude::*;
use svarog_grpc::protogen::svarog::{JoinSessionRequest, SessionConfig, TxHash};

pub enum Role {
    KeyGenerator,
    Signer(SignPayload),
    MnemProvider,
    Reshare(ReshareRole),
}

pub enum ReshareRole {
    Provider,
    Consumer,
    Both,
}

pub enum SignPayload {
    Single(TxHash),
    Batch(Vec<TxHash>),
}

pub fn parse_role(conf: &SessionConfig, req: &JoinSessionRequest) -> Outcome<Role> {
    let role;

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
    assert_throw!(reshare0 || reshare1, "member not found in session");
    match conf.session_type.as_str() {
        "keygen" => role = Some(Role::KeyGenerator),
        "keygen_mnem" => {
            if req.mnemonics != "" {
                role = Some(Role::MnemProvider)
            } else {
                role = Some(Role::KeyGenerator)
            }
        }
        "sign" => {
            let tx_hashes = conf
                .to_sign
                .clone()
                .ifnone("BizLogicError", "No tx to sign")?
                .tx_hashes;
            if tx_hashes.len() == 1 {
                role = Some(Role::Signer(SignPayload::Single(tx_hashes[0].clone())))
            } else if tx_hashes.len() > 1 {
                role = Some(Role::Signer(SignPayload::Batch(tx_hashes)))
            } else {
                throw!("BizLogicError", "No tx to sign")
            }
        }
        "reshare" => {
            if reshare0 && reshare1 {
                role = Some(Role::Reshare(ReshareRole::Both))
            } else if reshare0 {
                role = Some(Role::Reshare(ReshareRole::Provider))
            } else {
                // reshare1 only
                role = Some(Role::Reshare(ReshareRole::Consumer))
            }
        }
        invalid_ses_type => throw!("InvalidSessionType", invalid_ses_type),
    }
    Ok(role.ifnone("BizLogicError", "Cannot find proper role for member")?)
}
