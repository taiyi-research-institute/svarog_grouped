//! Structure of the configuration file.
//!
#![allow(non_snake_case)]

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct MpcServiceConfig {
    pub peer: GrpcServiceConfig,
    pub sesman: GrpcServiceConfig,
    pub logging: LoggingConfig,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GrpcServiceConfig {
    pub GrpcHost: String,
    pub GrpcPort: u16,
    pub SqlitePath: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoggingConfig {
    pub Level: String,
    pub Dir: String,
}
