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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Void {}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Member {
    #[prost(string, tag = "1")]
    pub member_name: ::prost::alloc::string::String,
    /// 0 means unset
    #[prost(uint64, tag = "2")]
    pub member_id: u64,
    #[prost(bool, tag = "3")]
    pub is_attending: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Group {
    #[prost(string, tag = "1")]
    pub group_name: ::prost::alloc::string::String,
    /// 0 means unset
    #[prost(uint64, tag = "2")]
    pub group_id: u64,
    #[prost(uint64, tag = "3")]
    pub group_quorum: u64,
    #[prost(bool, tag = "4")]
    pub is_reshare: bool,
    #[prost(message, repeated, tag = "5")]
    pub members: ::prost::alloc::vec::Vec<Member>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SessionConfig {
    #[prost(string, tag = "1")]
    pub session_id: ::prost::alloc::string::String,
    /// one of "keygen", "sign", "reshare"
    #[prost(string, tag = "2")]
    pub session_type: ::prost::alloc::string::String,
    #[prost(uint64, tag = "3")]
    pub key_quorum: u64,
    #[prost(message, repeated, tag = "4")]
    pub groups: ::prost::alloc::vec::Vec<Group>,
    /// 0 means unset
    #[prost(int64, tag = "5")]
    pub expire_before_finish: i64,
    /// 0 means unset
    #[prost(int64, tag = "6")]
    pub expire_after_finish: i64,
    /// "" means unset
    #[prost(string, tag = "16")]
    pub derive_path: ::prost::alloc::string::String,
    /// [] means unset
    #[prost(bytes = "vec", tag = "17")]
    pub tx_raw: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SessionId {
    #[prost(string, tag = "1")]
    pub session_id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Whistle {
    #[prost(string, tag = "1")]
    pub session_id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub message: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Message {
    #[prost(string, tag = "1")]
    pub session_id: ::prost::alloc::string::String,
    /// formerly "round"
    #[prost(string, tag = "2")]
    pub purpose: ::prost::alloc::string::String,
    /// member_id or negated group_id
    #[prost(uint64, tag = "3")]
    pub member_id_src: u64,
    #[prost(uint64, tag = "4")]
    pub member_id_dst: u64,
    /// if not provided, use first two fields as index.
    #[prost(bytes = "vec", tag = "5")]
    pub body: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SessionResult {
    #[prost(oneof = "session_result::Value", tags = "1, 2")]
    pub value: ::core::option::Option<session_result::Value>,
}
/// Nested message and enum types in `SessionResult`.
pub mod session_result {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Value {
        /// keygen or reshare result
        #[prost(string, tag = "1")]
        RootXpub(::prost::alloc::string::String),
        /// sign result
        #[prost(message, tag = "2")]
        Signature(super::Signature),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SessionTermination {
    #[prost(string, tag = "1")]
    pub session_id: ::prost::alloc::string::String,
    /// member_id
    #[prost(uint64, tag = "2")]
    pub member_id: u64,
    #[prost(message, optional, tag = "3")]
    pub result: ::core::option::Option<SessionResult>,
}
/// Generated client implementations.
pub mod svarog_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    use tonic::codegen::http::Uri;
    #[derive(Debug, Clone)]
    pub struct SvarogClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl SvarogClient<tonic::transport::Channel> {
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
    impl<T> SvarogClient<T>
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
        ) -> SvarogClient<InterceptedService<T, F>>
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
            SvarogClient::new(InterceptedService::new(inner, interceptor))
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
        pub async fn new_session(
            &mut self,
            request: impl tonic::IntoRequest<super::SessionConfig>,
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
            let path = http::uri::PathAndQuery::from_static("/server.Svarog/NewSession");
            let mut req = request.into_request();
            req.extensions_mut().insert(GrpcMethod::new("server.Svarog", "NewSession"));
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
                "/server.Svarog/TerminateSession",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("server.Svarog", "TerminateSession"));
            self.inner.unary(req, path, codec).await
        }
        /// receive the SessionConfig whose
        /// 1) group_id are filled, reflecting the asc order of (is_reshare, group_name).
        /// 2) member_id are sorted, reflecting the asc order of (group_id, member_name).
        /// 3) expire times are filled, if not provided in the request.
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
                "/server.Svarog/GetSessionConfig",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("server.Svarog", "GetSessionConfig"));
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
                "/server.Svarog/BlowWhistle",
            );
            let mut req = request.into_request();
            req.extensions_mut().insert(GrpcMethod::new("server.Svarog", "BlowWhistle"));
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
                "/server.Svarog/PostMessage",
            );
            let mut req = request.into_request();
            req.extensions_mut().insert(GrpcMethod::new("server.Svarog", "PostMessage"));
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
            let path = http::uri::PathAndQuery::from_static("/server.Svarog/GetMessage");
            let mut req = request.into_request();
            req.extensions_mut().insert(GrpcMethod::new("server.Svarog", "GetMessage"));
            self.inner.unary(req, path, codec).await
        }
    }
}
/// Generated server implementations.
pub mod svarog_server {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Generated trait containing gRPC methods that should be implemented for use with SvarogServer.
    #[async_trait]
    pub trait Svarog: Send + Sync + 'static {
        async fn new_session(
            &self,
            request: tonic::Request<super::SessionConfig>,
        ) -> std::result::Result<tonic::Response<super::Void>, tonic::Status>;
        async fn terminate_session(
            &self,
            request: tonic::Request<super::SessionTermination>,
        ) -> std::result::Result<tonic::Response<super::Void>, tonic::Status>;
        /// receive the SessionConfig whose
        /// 1) group_id are filled, reflecting the asc order of (is_reshare, group_name).
        /// 2) member_id are sorted, reflecting the asc order of (group_id, member_name).
        /// 3) expire times are filled, if not provided in the request.
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
    }
    #[derive(Debug)]
    pub struct SvarogServer<T: Svarog> {
        inner: _Inner<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
        max_decoding_message_size: Option<usize>,
        max_encoding_message_size: Option<usize>,
    }
    struct _Inner<T>(Arc<T>);
    impl<T: Svarog> SvarogServer<T> {
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
    impl<T, B> tonic::codegen::Service<http::Request<B>> for SvarogServer<T>
    where
        T: Svarog,
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
                "/server.Svarog/NewSession" => {
                    #[allow(non_camel_case_types)]
                    struct NewSessionSvc<T: Svarog>(pub Arc<T>);
                    impl<T: Svarog> tonic::server::UnaryService<super::SessionConfig>
                    for NewSessionSvc<T> {
                        type Response = super::Void;
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
                "/server.Svarog/TerminateSession" => {
                    #[allow(non_camel_case_types)]
                    struct TerminateSessionSvc<T: Svarog>(pub Arc<T>);
                    impl<
                        T: Svarog,
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
                "/server.Svarog/GetSessionConfig" => {
                    #[allow(non_camel_case_types)]
                    struct GetSessionConfigSvc<T: Svarog>(pub Arc<T>);
                    impl<T: Svarog> tonic::server::UnaryService<super::SessionId>
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
                "/server.Svarog/BlowWhistle" => {
                    #[allow(non_camel_case_types)]
                    struct BlowWhistleSvc<T: Svarog>(pub Arc<T>);
                    impl<T: Svarog> tonic::server::UnaryService<super::Whistle>
                    for BlowWhistleSvc<T> {
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
                "/server.Svarog/PostMessage" => {
                    #[allow(non_camel_case_types)]
                    struct PostMessageSvc<T: Svarog>(pub Arc<T>);
                    impl<T: Svarog> tonic::server::UnaryService<super::Message>
                    for PostMessageSvc<T> {
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
                "/server.Svarog/GetMessage" => {
                    #[allow(non_camel_case_types)]
                    struct GetMessageSvc<T: Svarog>(pub Arc<T>);
                    impl<T: Svarog> tonic::server::UnaryService<super::Message>
                    for GetMessageSvc<T> {
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
    impl<T: Svarog> Clone for SvarogServer<T> {
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
    impl<T: Svarog> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(Arc::clone(&self.0))
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: Svarog> tonic::server::NamedService for SvarogServer<T> {
        const NAME: &'static str = "server.Svarog";
    }
}
