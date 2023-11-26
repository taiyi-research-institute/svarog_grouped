use crate::util::*;
use miniz_oxide::{deflate::compress_to_vec, inflate::decompress_to_vec};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};
use svarog_grpc::protogen::svarog::{
    mpc_session_manager_client::MpcSessionManagerClient, Message, SessionConfig, SessionId,
    SessionTermination,
};
pub use svarog_grpc::protogen::svarog::{session_fruit::Value as SessionFruitValue, SessionFruit};
use tokio::time::{sleep, Duration};
use xuanmi_base_support::*;

#[derive(Clone)]
pub struct MpcMember {
    pub member_id: usize,
    pub group_id: usize,
    pub member_attending: HashSet<usize>,
    pub group_attending: HashMap<usize, HashSet<usize>>,
    pub member_group: HashMap<usize, usize>,
    pub group_member: HashMap<usize, HashSet<usize>>,
    pub group_quora: HashMap<usize, usize>,
    pub key_quorum: usize,
    pub reshare_groups: HashSet<usize>,
    pub reshare_members: HashSet<usize>,

    session_id: String,
    pub expire_at: u64,
    grpc_hostport: String,
}

pub enum MpcPeer<'a, C: IntoIterator<Item = usize>> {
    Single(usize),
    Plural(&'a C),
}

impl MpcMember {
    pub async fn new(grpc_hostport: &str) -> Outcome<Self> {
        Ok(MpcMember {
            member_id: 0,
            group_id: 0,
            member_attending: HashSet::new(),
            group_attending: HashMap::new(),
            member_group: HashMap::new(),
            group_member: HashMap::new(),
            group_quora: HashMap::new(),
            key_quorum: 0,
            reshare_groups: HashSet::new(),
            reshare_members: HashSet::new(),

            session_id: "".to_string(),
            expire_at: 0,
            grpc_hostport: grpc_hostport.to_owned(),
        })
    }

    pub async fn fetch_session_config(&self, ses_id: &str) -> Outcome<SessionConfig> {
        let mut grpc_client = MpcSessionManagerClient::connect(self.grpc_hostport.to_owned())
            .await
            .catch_()?;
        println!("[debug] fetch_session_config: {:?}", ses_id);
        let ses_config = grpc_client
            .get_session_config(SessionId {
                session_id: ses_id.to_string(),
            })
            .await
            .catch_()?
            .into_inner();
        Ok(ses_config)
    }

    pub fn use_session_config(
        &mut self,
        ses_config: &SessionConfig,
        member_name: &str,
        is_reshare: bool,
    ) -> Outcome<()> {
        self.key_quorum = ses_config.key_quorum as usize;
        for group in &ses_config.groups {
            let group_id = group.group_id;
            self.group_quora
                .insert(group_id as usize, group.group_quorum as usize);
            for member in &group.members {
                let member_id = member.member_id;
                self.member_group
                    .insert(member_id as usize, group_id as usize);
                if member.is_attending {
                    self.member_attending.insert(member_id as usize);
                    self.group_attending
                        .entry(group_id as usize)
                        .or_insert(HashSet::new())
                        .insert(member_id as usize);
                }
                self.group_member
                    .entry(group_id as usize)
                    .or_insert(HashSet::new())
                    .insert(member_id as usize);
                if group.is_reshare {
                    self.reshare_members.insert(member_id as usize);
                }
                if member.member_name == member_name && is_reshare == group.is_reshare {
                    self.member_id = member_id as usize;
                    self.group_id = group_id as usize;
                }
            }
            if group.is_reshare {
                self.reshare_groups.insert(group_id as usize);
            }
        }
        assert_throw!(
            member_name != "" && self.member_id != 0,
            "Member not found in session config"
        );
        self.session_id = ses_config.session_id.clone();
        self.expire_at = ses_config.expire_before_finish as u64;
        Ok(())
    }

    fn assert_on_time(&self) -> Outcome<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        assert_throw!(now <= self.expire_at as u64, "Session expired");
        Ok(())
    }

    pub async fn terminate_session(&self, value: SessionFruitValue) -> Outcome<()> {
        let mut grpc_client = MpcSessionManagerClient::connect(self.grpc_hostport.to_owned())
            .await
            .catch_()?;
        self.assert_on_time().catch_()?;
        let req = SessionTermination {
            session_id: self.session_id.clone(),
            member_id: self.member_id as u64,
            fruit: Some(SessionFruit { value: Some(value) }),
        };
        grpc_client.terminate_session(req).await.catch_()?;
        Ok(())
    }

    pub async fn postmsg_p2p<T>(&self, dst: usize, purpose: &str, obj: &T) -> Outcome<()>
    where
        T: Serialize + DeserializeOwned,
    {
        let mut grpc_client = MpcSessionManagerClient::connect(self.grpc_hostport.to_owned())
            .await
            .catch_()?;
        let bytes = obj.compress().catch_()?;
        let msg = Message {
            session_id: self.session_id.clone(),
            purpose: purpose.to_string(),
            member_id_src: self.member_id as u64,
            member_id_dst: dst as u64,
            body: bytes,
        };
        self.assert_on_time().catch_()?;
        let _ = grpc_client.post_message(msg).await.catch_()?;
        Ok(())
    }

    pub async fn getmsg_p2p<T>(&self, src: usize, purpose: &str) -> Outcome<T>
    where
        T: Serialize + DeserializeOwned,
    {
        let mut grpc_client = MpcSessionManagerClient::connect(self.grpc_hostport.to_owned())
            .await
            .catch_()?;
        let msg_idx = Message {
            session_id: self.session_id.clone(),
            purpose: purpose.to_string(),
            member_id_src: src as u64,
            member_id_dst: self.member_id as u64,
            body: Vec::new(),
        };
        let mut resp: Option<Message> = None;
        while now() < self.expire_at {
            let try_resp = grpc_client.get_message(msg_idx.clone()).await;
            if let Ok(_resp) = try_resp {
                resp = Some(_resp.into_inner());
                break;
            }
        }
        match resp {
            Some(msg) => {
                let obj = msg.body.decompress().catch_()?;
                Ok(obj)
            }
            None => {
                throw!(
                    "RequestTimeout",
                    &format!("purpose={}; src={}; dst={}", purpose, src, self.member_id)
                );
            }
        }
    }

    pub async fn postmsg_mcast<'a, It, T>(&self, dst_set: It, purpose: &str, obj: &T) -> Outcome<()>
    where
        It: Iterator<Item = &'a usize>,
        T: Serialize + DeserializeOwned,
    {
        let mut grpc_client = MpcSessionManagerClient::connect(self.grpc_hostport.to_owned())
            .await
            .catch_()?;
        let bytes = obj.compress().catch_()?;
        for dst in dst_set {
            let msg = Message {
                session_id: self.session_id.clone(),
                purpose: purpose.to_string(),
                member_id_src: self.member_id as u64,
                member_id_dst: *dst as u64,
                body: bytes.clone(),
            };
            self.assert_on_time().catch_()?;
            let _ = grpc_client.post_message(msg).await.catch_()?;
        }
        Ok(())
    }

    pub async fn getmsg_mcast<'a, It, T>(&self, src_set: It, purpose: &str) -> Outcome<SparseVec<T>>
    where
        It: Iterator<Item = &'a usize>,
        T: Serialize + DeserializeOwned,
    {
        let mut grpc_client = MpcSessionManagerClient::connect(self.grpc_hostport.to_owned())
            .await
            .catch_()?;
        let mut sparse_array = SparseVec::<T>::new();
        let mut src_set: VecDeque<usize> = src_set.cloned().collect();
        while now() < self.expire_at && !src_set.is_empty() {
            let src: usize = src_set.pop_front().unwrap();
            let msg_idx = Message {
                session_id: self.session_id.clone(),
                purpose: purpose.to_string(),
                member_id_src: src as u64,
                member_id_dst: self.member_id as u64,
                body: Vec::new(),
            };
            let try_resp = grpc_client.get_message(msg_idx).await;
            if let Ok(resp) = try_resp {
                let msg = resp.into_inner();
                let obj = msg.body.decompress().catch_()?;
                sparse_array.insert(src, obj);
            } else {
                src_set.push_back(src);
            }
            sleep(Duration::from_millis(100)).await;
        }
        assert_throw!(
            src_set.is_empty(),
            "RequestTimeout",
            &format!(
                "purpose={}; src_set={:?}; dst={}",
                purpose, &src_set, self.member_id
            )
        );
        Ok(sparse_array)
    }
}

pub trait CompressAble {
    fn compress(&self) -> Outcome<Vec<u8>>;
}

pub trait DecompressAble<T> {
    fn decompress(&self) -> Outcome<T>;
}

impl<T> CompressAble for T
where
    T: Serialize + DeserializeOwned,
{
    fn compress(&self) -> Outcome<Vec<u8>> {
        let json = serde_json::to_string(&self).catch_()?;
        let bytes = compress_to_vec(json.as_bytes(), 7);
        Ok(bytes)
    }
}

impl<S, D> DecompressAble<D> for S
where
    S: AsRef<[u8]>,
    D: Serialize + DeserializeOwned,
{
    fn decompress(&self) -> Outcome<D> {
        let bytes = decompress_to_vec(self.as_ref()).catch_()?;
        let json = String::from_utf8(bytes).catch_()?;
        let obj = serde_json::from_str(&json).catch_()?;
        Ok(obj)
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}
