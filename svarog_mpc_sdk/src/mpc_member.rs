use crate::{
    algo::SparseVec,
    protogen::server::{
        svarog_client::SvarogClient, Message, SessionConfig, SessionId, SessionTermination,
    },
};
use miniz_oxide::{deflate::compress_to_vec, inflate::decompress_to_vec};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use tonic;
use xuanmi_base_support::*;

#[derive(Clone)]
pub struct MpcMember {
    member_group: HashMap<usize, usize>,
    member_names: HashMap<usize, String>,
    member_attending: HashSet<usize>,
    group_member: HashMap<usize, HashSet<usize>>,
    group_names: HashMap<usize, String>,
    group_quora: HashMap<usize, usize>,
    key_quorum: usize,
    reshare_groups: HashSet<usize>,
    reshare_members: HashSet<usize>,
    member_id: usize,
    group_id: usize,

    derive_path: String,
    tx_raw: Vec<u8>,
    session_id: String,
    expire_at: i64,
    grpc_client: SvarogClient<tonic::transport::Channel>,
}

pub enum MpcPeer {
    Member(usize),
    Group(usize),
    All(),
}

impl MpcMember {
    pub async fn new(grpc_hostport: &str) -> Outcome<Self> {
        let grpc_client = SvarogClient::connect(grpc_hostport.to_owned())
            .await
            .catch_()?;
        Ok(MpcMember {
            member_group: HashMap::new(),
            member_names: HashMap::new(),
            member_attending: HashSet::new(),
            group_member: HashMap::new(),
            group_names: HashMap::new(),
            group_quora: HashMap::new(),
            key_quorum: 0,
            reshare_groups: HashSet::new(),
            reshare_members: HashSet::new(),
            member_id: 0,
            group_id: 0,
            derive_path: "".to_string(),
            tx_raw: Vec::new(),
            session_id: "".to_string(),
            expire_at: 0,
            grpc_client,
        })
    }

    pub async fn fetch_session_config(&mut self, ses_id: &str) -> Outcome<SessionConfig> {
        let ses_config = self
            .grpc_client
            .get_session_config(SessionId {
                session_id: ses_id.to_string(),
            })
            .await
            .catch_()?
            .into_inner();
        Ok(ses_config)
    }

    pub async fn use_session_config(
        &mut self,
        ses_config: &SessionConfig,
        member_name: &str,
        is_reshare: bool,
    ) -> Outcome<()> {
        self.key_quorum = ses_config.key_quorum as usize;
        for group in &ses_config.groups {
            let group_id = group.group_id;
            self.group_names
                .insert(group_id as usize, group.group_name.clone());
            self.group_quora
                .insert(group_id as usize, group.sub_quorum as usize);
            for member in &group.members {
                let member_id = member.member_id;
                self.member_group
                    .insert(member_id as usize, group_id as usize);
                self.member_names
                    .insert(member_id as usize, member.member_name.clone());
                if member.is_attending {
                    self.member_attending.insert(member_id as usize);
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
        assert_throw!(self.member_id != 0, "Member not found in session config");
        self.derive_path = ses_config.derive_path.clone();
        self.tx_raw = ses_config.tx_raw.clone();
        self.session_id = ses_config.session_id.clone();
        self.expire_at = ses_config.expire_before_finish;
        Ok(())
    }

    // pub async fn post_terminate(&mut self, dst: MpcPeer)
    fn assert_on_time(&mut self) -> Outcome<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        assert_throw!(now <= self.expire_at);
        Ok(())
    }

    pub async fn terminate_session(&mut self, request: &SessionTermination) -> Outcome<()> {
        self.assert_on_time().catch_()?;
        let _ = self.grpc_client.terminate_session(request).await.catch_()?;
    }

    pub async fn post_message<T>(&mut self, dst: MpcPeer, purpose: &str, obj: &T) -> Outcome<()>
    where
        T: Serialize + DeserializeOwned,
    {
        match dst {
            MpcPeer::Member(member_id) => {
                let bytes = obj.compress().catch_()?;
                let msg = Message {
                    session_id: self.session_id.clone(),
                    purpose: purpose.to_string(),
                    member_id_src: self.member_id as u64,
                    member_id_dst: member_id as u64,
                    body: bytes,
                };
                self.assert_on_time().catch_()?;
                let _ = self.grpc_client.post_message(msg).await.catch_()?;
            }
            MpcPeer::Group(group_id) => {
                let bytes = obj.compress().catch_()?;
                for member_id in self.group_member.get(&group_id).unwrap() {
                    let msg = Message {
                        session_id: self.session_id.clone(),
                        purpose: purpose.to_string(),
                        member_id_src: self.member_id as u64,
                        member_id_dst: *member_id as u64,
                        body: bytes.clone(),
                    };
                    self.assert_on_time().catch_()?;
                    let _ = self.grpc_client.post_message(msg).await.catch_()?;
                }
            }
            MpcPeer::All() => {
                let bytes = obj.compress().catch_()?;
                for member_id in self.member_group.keys() {
                    let msg = Message {
                        session_id: self.session_id.clone(),
                        purpose: purpose.to_string(),
                        member_id_src: self.member_id as u64,
                        member_id_dst: *member_id as u64,
                        body: bytes.clone(),
                    };
                    self.assert_on_time().catch_()?;
                    let _ = self.grpc_client.post_message(msg).await.catch_()?;
                }
            }
        }
        Ok(())
    }

    pub async fn get_message<T>(&mut self, src: MpcPeer, purpose: &str) -> Outcome<SparseVec<T>>
    where
        T: Serialize + DeserializeOwned,
    {
        let mut sparse_array = SparseVec::<T>::new();
        match src {
            MpcPeer::Member(member_id) => {
                let msg = Message {
                    session_id: self.session_id.clone(),
                    purpose: purpose.to_string(),
                    member_id_src: member_id as u64,
                    member_id_dst: self.member_id as u64,
                    body: Vec::new(),
                };
                self.assert_on_time().catch_()?;
                let msg = self
                    .grpc_client
                    .get_message(msg)
                    .await
                    .catch_()?
                    .into_inner();
                let obj = msg.body.decompress().catch_()?;
                sparse_array.insert(member_id, obj);
            }
            MpcPeer::Group(group_id) => {
                for member_id in self.group_member.get(&group_id).unwrap() {
                    let msg = Message {
                        session_id: self.session_id.clone(),
                        purpose: purpose.to_string(),
                        member_id_src: *member_id as u64,
                        member_id_dst: self.member_id as u64,
                        body: Vec::new(),
                    };
                    self.assert_on_time().catch_()?;
                    let msg = self
                        .grpc_client
                        .get_message(msg)
                        .await
                        .catch_()?
                        .into_inner();
                    let obj = msg.body.decompress().catch_()?;
                    sparse_array.insert(*member_id, obj);
                }
            }
            MpcPeer::All() => {
                for member_id in self.member_group.keys() {
                    let msg = Message {
                        session_id: self.session_id.clone(),
                        purpose: purpose.to_string(),
                        member_id_src: *member_id as u64,
                        member_id_dst: self.member_id as u64,
                        body: Vec::new(),
                    };
                    self.assert_on_time().catch_()?;
                    let msg = self
                        .grpc_client
                        .get_message(msg)
                        .await
                        .catch_()?
                        .into_inner();
                    let obj = msg.body.decompress().catch_()?;
                    sparse_array.insert(*member_id, obj);
                }
            }
        }
        Ok(sparse_array)
    }

    pub fn attr_member_id(&self) -> usize {
        self.member_id as u16
    }

    pub fn attr_group_id(&self) -> usize {
        self.group_id
    }

    pub fn attr_key_quorum(&self) -> usize {
        self.key_quorum
    }

    pub fn attr_gruop_quorum(&self) -> usize {
        self.group_quora.get(&self.group_id).unwrap().clone()
    }

    pub fn attr_n_registered(&self) -> usize {
        self.member_names.len()
    }

    pub fn attr_n_attend(&self) -> usize {
        self.member_attending.len()
    }

    pub fn attr_group_n_registered(&self) -> usize {
        self.group_member.get(&self.group_id).unwrap().len()
    }

    pub fn attr_group_n_attend(&self) -> usize {
        let mut n_attend = 0;
        let candidates = self.group_member.get(&self.group_id).unwrap();
        for member_id in candidates {
            if self.member_attending.contains(member_id) {
                n_attend += 1;
            }
        }
        n_attend
    }

    pub fn attr_my_group_member_ids(&self) -> &HashSet<usize> {
        self.group_member.get(&self.group_id).unwrap()
    }

    pub fn attr_all_registered_member_ids(&self) -> &HashSet<usize> {
        &self.member_names.keys()
    }
}

pub trait CompressAble {
    fn compress(&self) -> Outcome<Vec<u8>>;
}

trait DecompressAble<T> {
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
