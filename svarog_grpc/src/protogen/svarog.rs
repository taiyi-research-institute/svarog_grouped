#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SessionConfig {
    /// When creating session, set to ""
    #[prost(string, tag = "1")]
    pub session_id: ::prost::alloc::string::String,
    /// one of "keygen", "sign", "reshare"
    #[prost(string, tag = "2")]
    pub session_type: ::prost::alloc::string::String,
    #[prost(uint64, tag = "3")]
    pub key_quorum: u64,
    #[prost(uint64, tag = "4")]
    pub reshare_key_quorum: u64,
    #[prost(message, repeated, tag = "5")]
    pub groups: ::prost::alloc::vec::Vec<Group>,
    /// When creating session, set to 0
    #[prost(int64, tag = "6")]
    pub expire_before_finish: i64,
    /// When creating session, set to 0
    #[prost(int64, tag = "7")]
    pub expire_after_finish: i64,
    /// [] means unset
    #[prost(message, optional, tag = "17")]
    pub to_sign: ::core::option::Option<ToSign>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct JoinSessionRequest {
    #[prost(string, tag = "1")]
    pub session_id: ::prost::alloc::string::String,
    /// Name of MPC participant
    #[prost(string, tag = "2")]
    pub member_name: ::prost::alloc::string::String,
    /// Name of root private key
    #[prost(string, tag = "3")]
    pub key_name: ::prost::alloc::string::String,
    /// Used for authentication
    #[prost(string, tag = "4")]
    pub token: ::prost::alloc::string::String,
    /// Only end-user provides this. Leave blank for API calls.
    #[prost(string, tag = "5")]
    pub mnemonics: ::prost::alloc::string::String,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AbortSessionRequest {
    #[prost(string, tag = "1")]
    pub peer_id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub reason: ::prost::alloc::string::String,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Group {
    #[prost(string, tag = "1")]
    pub group_name: ::prost::alloc::string::String,
    /// When creating session, set to 0
    #[prost(uint64, tag = "2")]
    pub group_id: u64,
    #[prost(uint64, tag = "3")]
    pub group_quorum: u64,
    #[prost(bool, tag = "4")]
    pub is_reshare: bool,
    #[prost(message, repeated, tag = "5")]
    pub members: ::prost::alloc::vec::Vec<Member>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Member {
    #[prost(string, tag = "1")]
    pub member_name: ::prost::alloc::string::String,
    /// When creating session, set to 0
    #[prost(uint64, tag = "2")]
    pub member_id: u64,
    #[prost(bool, tag = "3")]
    pub is_attending: bool,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Signature {
    #[prost(bytes = "vec", tag = "1")]
    pub r: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub s: ::prost::alloc::vec::Vec<u8>,
    #[prost(bool, tag = "3")]
    pub v: bool,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Signatures {
    #[prost(message, repeated, tag = "1")]
    pub signatures: ::prost::alloc::vec::Vec<Signature>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Void {}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TxHash {
    #[prost(string, tag = "1")]
    pub derive_path: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "2")]
    pub tx_hash: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ToSign {
    #[prost(message, repeated, tag = "1")]
    pub tx_hashes: ::prost::alloc::vec::Vec<TxHash>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SessionId {
    #[prost(string, tag = "1")]
    pub session_id: ::prost::alloc::string::String,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Whistle {
    #[prost(string, tag = "1")]
    pub session_id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub message: ::prost::alloc::string::String,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Message {
    #[prost(string, tag = "1")]
    pub session_id: ::prost::alloc::string::String,
    /// formerly "round"
    #[prost(string, tag = "2")]
    pub purpose: ::prost::alloc::string::String,
    #[prost(uint64, tag = "3")]
    pub member_id_src: u64,
    #[prost(uint64, tag = "4")]
    pub member_id_dst: u64,
    /// if set to [], remaining fields are used as index.
    #[prost(bytes = "vec", tag = "5")]
    pub body: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SessionFruit {
    #[prost(oneof = "session_fruit::Value", tags = "1, 2")]
    pub value: ::core::option::Option<session_fruit::Value>,
}
/// Nested message and enum types in `SessionFruit`.
pub mod session_fruit {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Value {
        /// keygen or reshare result
        #[prost(string, tag = "1")]
        RootXpub(::prost::alloc::string::String),
        /// sign result
        #[prost(message, tag = "2")]
        Signatures(super::Signatures),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SessionTermination {
    #[prost(string, tag = "1")]
    pub session_id: ::prost::alloc::string::String,
    /// member_id
    #[prost(uint64, tag = "2")]
    pub member_id: u64,
    #[prost(message, optional, tag = "3")]
    pub fruit: ::core::option::Option<SessionFruit>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BizCallbackUrl {
    #[prost(string, tag = "1")]
    pub heartbeat: ::prost::alloc::string::String,
}
/// Generated client implementations.
pub mod mpc_peer_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    use tonic::codegen::http::Uri;
    /// A peer handles multiple shards of multiple keys.
    /// All called by biz
    #[derive(Debug, Clone)]
    pub struct MpcPeerClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl MpcPeerClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> MpcPeerClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> MpcPeerClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
            >>::Error: Into<StdError> + Send + Sync,
        {
            MpcPeerClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with the given encoding.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        /// Enable decompressing responses.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_encoding_message_size(limit);
            self
        }
        pub async fn join_session(
            &mut self,
            request: impl tonic::IntoRequest<super::JoinSessionRequest>,
        ) -> std::result::Result<tonic::Response<super::Void>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/svarog.MpcPeer/JoinSession",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("svarog.MpcPeer", "JoinSession"));
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_session_fruit(
            &mut self,
            request: impl tonic::IntoRequest<super::SessionId>,
        ) -> std::result::Result<tonic::Response<super::SessionFruit>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/svarog.MpcPeer/GetSessionFruit",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("svarog.MpcPeer", "GetSessionFruit"));
            self.inner.unary(req, path, codec).await
        }
        /// When biz detected wrong Tx, call this to abort session.
        pub async fn abort_session(
            &mut self,
            request: impl tonic::IntoRequest<super::AbortSessionRequest>,
        ) -> std::result::Result<tonic::Response<super::Void>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/svarog.MpcPeer/AbortSession",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("svarog.MpcPeer", "AbortSession"));
            self.inner.unary(req, path, codec).await
        }
    }
}
/// Generated client implementations.
pub mod mpc_session_manager_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    use tonic::codegen::http::Uri;
    #[derive(Debug, Clone)]
    pub struct MpcSessionManagerClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl MpcSessionManagerClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> MpcSessionManagerClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> MpcSessionManagerClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
            >>::Error: Into<StdError> + Send + Sync,
        {
            MpcSessionManagerClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with the given encoding.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        /// Enable decompressing responses.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_encoding_message_size(limit);
            self
        }
        /// In the request, `session_id`, `group_id`s, `member_id`s
        /// are set to "zero-value"s.
        pub async fn new_session(
            &mut self,
            request: impl tonic::IntoRequest<super::SessionConfig>,
        ) -> std::result::Result<tonic::Response<super::SessionConfig>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/svarog.MpcSessionManager/NewSession",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("svarog.MpcSessionManager", "NewSession"));
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_session_config(
            &mut self,
            request: impl tonic::IntoRequest<super::SessionId>,
        ) -> std::result::Result<tonic::Response<super::SessionConfig>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/svarog.MpcSessionManager/GetSessionConfig",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("svarog.MpcSessionManager", "GetSessionConfig"));
            self.inner.unary(req, path, codec).await
        }
        pub async fn blow_whistle(
            &mut self,
            request: impl tonic::IntoRequest<super::Whistle>,
        ) -> std::result::Result<tonic::Response<super::Void>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/svarog.MpcSessionManager/BlowWhistle",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("svarog.MpcSessionManager", "BlowWhistle"));
            self.inner.unary(req, path, codec).await
        }
        pub async fn post_message(
            &mut self,
            request: impl tonic::IntoRequest<super::Message>,
        ) -> std::result::Result<tonic::Response<super::Void>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/svarog.MpcSessionManager/PostMessage",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("svarog.MpcSessionManager", "PostMessage"));
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_message(
            &mut self,
            request: impl tonic::IntoRequest<super::Message>,
        ) -> std::result::Result<tonic::Response<super::Message>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/svarog.MpcSessionManager/GetMessage",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("svarog.MpcSessionManager", "GetMessage"));
            self.inner.unary(req, path, codec).await
        }
        pub async fn terminate_session(
            &mut self,
            request: impl tonic::IntoRequest<super::SessionTermination>,
        ) -> std::result::Result<tonic::Response<super::Void>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/svarog.MpcSessionManager/TerminateSession",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("svarog.MpcSessionManager", "TerminateSession"));
            self.inner.unary(req, path, codec).await
        }
    }
}
/// Generated server implementations.
pub mod mpc_peer_server {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Generated trait containing gRPC methods that should be implemented for use with MpcPeerServer.
    #[async_trait]
    pub trait MpcPeer: Send + Sync + 'static {
        async fn join_session(
            &self,
            request: tonic::Request<super::JoinSessionRequest>,
        ) -> std::result::Result<tonic::Response<super::Void>, tonic::Status>;
        async fn get_session_fruit(
            &self,
            request: tonic::Request<super::SessionId>,
        ) -> std::result::Result<tonic::Response<super::SessionFruit>, tonic::Status>;
        /// When biz detected wrong Tx, call this to abort session.
        async fn abort_session(
            &self,
            request: tonic::Request<super::AbortSessionRequest>,
        ) -> std::result::Result<tonic::Response<super::Void>, tonic::Status>;
    }
    /// A peer handles multiple shards of multiple keys.
    /// All called by biz
    #[derive(Debug)]
    pub struct MpcPeerServer<T: MpcPeer> {
        inner: _Inner<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
        max_decoding_message_size: Option<usize>,
        max_encoding_message_size: Option<usize>,
    }
    struct _Inner<T>(Arc<T>);
    impl<T: MpcPeer> MpcPeerServer<T> {
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }
        pub fn from_arc(inner: Arc<T>) -> Self {
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
                max_decoding_message_size: None,
                max_encoding_message_size: None,
            }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
        /// Enable decompressing requests with the given encoding.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }
        /// Compress responses with the given encoding, if the client supports it.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.max_decoding_message_size = Some(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.max_encoding_message_size = Some(limit);
            self
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for MpcPeerServer<T>
    where
        T: MpcPeer,
        B: Body + Send + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/svarog.MpcPeer/JoinSession" => {
                    #[allow(non_camel_case_types)]
                    struct JoinSessionSvc<T: MpcPeer>(pub Arc<T>);
                    impl<
                        T: MpcPeer,
                    > tonic::server::UnaryService<super::JoinSessionRequest>
                    for JoinSessionSvc<T> {
                        type Response = super::Void;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::JoinSessionRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                (*inner).join_session(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = JoinSessionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/svarog.MpcPeer/GetSessionFruit" => {
                    #[allow(non_camel_case_types)]
                    struct GetSessionFruitSvc<T: MpcPeer>(pub Arc<T>);
                    impl<T: MpcPeer> tonic::server::UnaryService<super::SessionId>
                    for GetSessionFruitSvc<T> {
                        type Response = super::SessionFruit;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SessionId>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                (*inner).get_session_fruit(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetSessionFruitSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/svarog.MpcPeer/AbortSession" => {
                    #[allow(non_camel_case_types)]
                    struct AbortSessionSvc<T: MpcPeer>(pub Arc<T>);
                    impl<
                        T: MpcPeer,
                    > tonic::server::UnaryService<super::AbortSessionRequest>
                    for AbortSessionSvc<T> {
                        type Response = super::Void;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::AbortSessionRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                (*inner).abort_session(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = AbortSessionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => {
                    Box::pin(async move {
                        Ok(
                            http::Response::builder()
                                .status(200)
                                .header("grpc-status", "12")
                                .header("content-type", "application/grpc")
                                .body(empty_body())
                                .unwrap(),
                        )
                    })
                }
            }
        }
    }
    impl<T: MpcPeer> Clone for MpcPeerServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
                max_decoding_message_size: self.max_decoding_message_size,
                max_encoding_message_size: self.max_encoding_message_size,
            }
        }
    }
    impl<T: MpcPeer> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(Arc::clone(&self.0))
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: MpcPeer> tonic::server::NamedService for MpcPeerServer<T> {
        const NAME: &'static str = "svarog.MpcPeer";
    }
}
/// Generated server implementations.
pub mod mpc_session_manager_server {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Generated trait containing gRPC methods that should be implemented for use with MpcSessionManagerServer.
    #[async_trait]
    pub trait MpcSessionManager: Send + Sync + 'static {
        /// In the request, `session_id`, `group_id`s, `member_id`s
        /// are set to "zero-value"s.
        async fn new_session(
            &self,
            request: tonic::Request<super::SessionConfig>,
        ) -> std::result::Result<tonic::Response<super::SessionConfig>, tonic::Status>;
        async fn get_session_config(
            &self,
            request: tonic::Request<super::SessionId>,
        ) -> std::result::Result<tonic::Response<super::SessionConfig>, tonic::Status>;
        async fn blow_whistle(
            &self,
            request: tonic::Request<super::Whistle>,
        ) -> std::result::Result<tonic::Response<super::Void>, tonic::Status>;
        async fn post_message(
            &self,
            request: tonic::Request<super::Message>,
        ) -> std::result::Result<tonic::Response<super::Void>, tonic::Status>;
        async fn get_message(
            &self,
            request: tonic::Request<super::Message>,
        ) -> std::result::Result<tonic::Response<super::Message>, tonic::Status>;
        async fn terminate_session(
            &self,
            request: tonic::Request<super::SessionTermination>,
        ) -> std::result::Result<tonic::Response<super::Void>, tonic::Status>;
    }
    #[derive(Debug)]
    pub struct MpcSessionManagerServer<T: MpcSessionManager> {
        inner: _Inner<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
        max_decoding_message_size: Option<usize>,
        max_encoding_message_size: Option<usize>,
    }
    struct _Inner<T>(Arc<T>);
    impl<T: MpcSessionManager> MpcSessionManagerServer<T> {
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }
        pub fn from_arc(inner: Arc<T>) -> Self {
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
                max_decoding_message_size: None,
                max_encoding_message_size: None,
            }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
        /// Enable decompressing requests with the given encoding.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }
        /// Compress responses with the given encoding, if the client supports it.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.max_decoding_message_size = Some(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.max_encoding_message_size = Some(limit);
            self
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for MpcSessionManagerServer<T>
    where
        T: MpcSessionManager,
        B: Body + Send + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/svarog.MpcSessionManager/NewSession" => {
                    #[allow(non_camel_case_types)]
                    struct NewSessionSvc<T: MpcSessionManager>(pub Arc<T>);
                    impl<
                        T: MpcSessionManager,
                    > tonic::server::UnaryService<super::SessionConfig>
                    for NewSessionSvc<T> {
                        type Response = super::SessionConfig;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SessionConfig>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move { (*inner).new_session(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = NewSessionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/svarog.MpcSessionManager/GetSessionConfig" => {
                    #[allow(non_camel_case_types)]
                    struct GetSessionConfigSvc<T: MpcSessionManager>(pub Arc<T>);
                    impl<
                        T: MpcSessionManager,
                    > tonic::server::UnaryService<super::SessionId>
                    for GetSessionConfigSvc<T> {
                        type Response = super::SessionConfig;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SessionId>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                (*inner).get_session_config(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetSessionConfigSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/svarog.MpcSessionManager/BlowWhistle" => {
                    #[allow(non_camel_case_types)]
                    struct BlowWhistleSvc<T: MpcSessionManager>(pub Arc<T>);
                    impl<
                        T: MpcSessionManager,
                    > tonic::server::UnaryService<super::Whistle> for BlowWhistleSvc<T> {
                        type Response = super::Void;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::Whistle>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                (*inner).blow_whistle(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = BlowWhistleSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/svarog.MpcSessionManager/PostMessage" => {
                    #[allow(non_camel_case_types)]
                    struct PostMessageSvc<T: MpcSessionManager>(pub Arc<T>);
                    impl<
                        T: MpcSessionManager,
                    > tonic::server::UnaryService<super::Message> for PostMessageSvc<T> {
                        type Response = super::Void;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::Message>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                (*inner).post_message(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = PostMessageSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/svarog.MpcSessionManager/GetMessage" => {
                    #[allow(non_camel_case_types)]
                    struct GetMessageSvc<T: MpcSessionManager>(pub Arc<T>);
                    impl<
                        T: MpcSessionManager,
                    > tonic::server::UnaryService<super::Message> for GetMessageSvc<T> {
                        type Response = super::Message;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::Message>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move { (*inner).get_message(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetMessageSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/svarog.MpcSessionManager/TerminateSession" => {
                    #[allow(non_camel_case_types)]
                    struct TerminateSessionSvc<T: MpcSessionManager>(pub Arc<T>);
                    impl<
                        T: MpcSessionManager,
                    > tonic::server::UnaryService<super::SessionTermination>
                    for TerminateSessionSvc<T> {
                        type Response = super::Void;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SessionTermination>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                (*inner).terminate_session(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = TerminateSessionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => {
                    Box::pin(async move {
                        Ok(
                            http::Response::builder()
                                .status(200)
                                .header("grpc-status", "12")
                                .header("content-type", "application/grpc")
                                .body(empty_body())
                                .unwrap(),
                        )
                    })
                }
            }
        }
    }
    impl<T: MpcSessionManager> Clone for MpcSessionManagerServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
                max_decoding_message_size: self.max_decoding_message_size,
                max_encoding_message_size: self.max_encoding_message_size,
            }
        }
    }
    impl<T: MpcSessionManager> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(Arc::clone(&self.0))
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: MpcSessionManager> tonic::server::NamedService
    for MpcSessionManagerServer<T> {
        const NAME: &'static str = "svarog.MpcSessionManager";
    }
}
