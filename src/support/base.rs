use std::{fs, mem};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

use crate::crypto::*;
use crate::dns::*;
use crate::support::*;


pub struct AccessControlConfig {
    pub enabled: bool,
    pub tokens: Vec<String>,
}
