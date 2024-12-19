use std::fs;
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::AtomicU32;
use std::time::Duration;
use serde_derive::{Serialize, Deserialize};
use siphasher::sip128::SipHasher13;
use slabigator::Slab;
use tokio::io::AsyncWriteExt;
use tokio::runtime::Handle;
use tokio::sync::oneshot;
use crate::crypto::{*};
use crate::dns::base::DNSCryptEncryptionParams;
use crate::dns::crypt;


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccessControlConfig {
    pub enabled: bool,
    pub tokens: Vec<String>,
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AnonymizedDNSConfig {
    pub enabled: bool,
    pub allowed_ports: Vec<u16>,
    pub allow_non_reserved_ports: Option<bool>,
    pub blacklisted_ips: Vec<IpAddr>,
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MetricsConfig {
    pub r#type: String,
    pub listen_address: SocketAddr,
    pub path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DNSCryptoConfig {
    pub enabled: Option<bool>,
    pub provider_name: String,
    pub key_cache_capacity: usize,
    pub dnssec: bool,
    pub no_filters: bool,
    pub no_logs: bool,
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TLSConfig {
    pub upstream_address:Option<SocketAddr>,
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ListenAddressConfig {
    pub local: SocketAddr,
    pub external: SocketAddr,
}



#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FilteringConfig {
    pub domain_blacklist: Option<PathBuf>,
    pub undelegated_list: Option<PathBuf>,
    pub ignored_unqualified_hostnames: Option<bool>,
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub listen_address: Vec<ListenAddressConfig>,
    pub external_address: Option<IpAddr>,
    pub upstream_address: SocketAddr,
    pub state_file: PathBuf,
    pub udp_socket_timeout: u32,
    pub tcp_socket_timeout: u32,
    pub udp_socket_max_active_connections: u32,
    pub tcp_socket_max_active_connections: u32,
    pub cache_capacity: usize,
    pub cache_ttl_min: u32,
    pub cache_ttl_max: u32,
    pub cache_ttl_error: u32,
    pub user: Option<String>,
    pub group: Option<String>,
    pub chroot: Option<String>,
    pub filtering: FilteringConfig,
    pub dns_crypt: DNSCryptoConfig,
    pub tls: TLSConfig,
    pub daemonize: bool,
    pub pid_file: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
    pub ip: Option<String>,
    pub client_ttl_holdon: Option<u32>,

    #[cfg(feature = "metrics")]
    pub metrics: Option<MetricsConfig>,
    pub anonymized_dns: Option<AnonymizedDNSConfig>,
    pub access_control: Option<AccessControlConfig>,
}



#[derive(Serialize, Deserialize, Debug)]
pub struct State {
    pub provider_kp: SignKeyPair,
    pub dns_crypt_encryption_params_set: Vec<DNSCryptEncryptionParams>,
}


#[derive(Clone, Educe)]
#[educe(Debug)]
pub struct Globals {
    pub runtime_handle: Handle,
    pub state_file: PathBuf,
    pub dnscrypt_encryption_params_set: Arc<RwLock<Arc<Vec<Arc<DNSCryptEncryptionParams>>>>>,
    pub provider_name: String,
    pub provider_kp: SignKeyPair,
    pub listen_addrs: Vec<SocketAddr>,
    pub external_addr: Option<SocketAddr>,
    pub upstream_addr: SocketAddr,
    pub tls_upstream_addr: Option<SocketAddr>,
    pub udp_timeout: Duration,
    pub tcp_timeout: Duration,
    pub udp_concurrent_connections: Arc<AtomicU32>,
    pub tcp_concurrent_connections: Arc<AtomicU32>,
    pub udp_max_active_connections: u32,
    pub tcp_max_active_connections: u32,
    pub udp_active_connections: Arc<Mutex<Slab<oneshot::Sender<()>>>>,
    pub tcp_active_connections: Arc<Mutex<Slab<oneshot::Sender<()>>>>,
    pub key_cache_capacity: usize,
    pub hasher: SipHasher13,
    pub cache: Cache,
    pub cert_cache: Cache,
    pub blacklist: Option<BlackList>,
    pub undelegated_list: Option<BlackList>,
    pub ignore_unqualified_hostnames: bool,
    pub dns_crypt_enabled: bool,
    pub anonymized_dns_enabled: bool,
    pub anonymized_dns_allowed_ports: Vec<u16>,
    pub anonymized_dns_allow_non_reserved_ports: bool,
    pub anonymized_dns_blacklisted_ips: Vec<IpAddr>,
    pub access_control_tokens: Option<Vec<String>>,
    pub client_ttl_holdon: u32,
    pub my_ip: Option<Vec<u8>>,

    #[cfg(feature = "metrics")]
    #[educe(Debug(ignore))]
    pub varz: Varz,
}

