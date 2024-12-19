use std::hash::Hasher;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use byteorder::{BigEndian, ByteOrder};
use educe::Educe;
use ipext::IpExt;
use libsodium_sys::{crypto_box_curve25519xchacha20poly1305_MACBYTES, crypto_box_curve25519xchacha20poly1305_NONCEBYTES};
use serde_derive::{Deserialize, Serialize};
use sieve_cache::SieveCache;
use siphasher::sip128::Hasher128;

use crate::support::errors::{*};
use crate::config::base::{*};
use crate::{*};



pub const ANONYMIZED_DNS_CRYPT_QUERY_MAGIC: [u8; 10] = [
    0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0x00, 0x00
];
pub const ANONYMIZED_DNS_CRYPT_OVERHEAD: usize = 16 + 2;
pub const RELAYED_CERT_CACHE_SIZE: usize = 1000;
pub const RELAYED_CERT_CACHE_TTL: u32 = 600;
pub const DNS_MAX_HOSTNAME_SIZE: usize = 256;
pub const DNS_HEADER_SIZE: usize = 12;
pub const DNS_OFFSET_FLAGS: usize = 2;
pub const DNS_MAX_PACKET_SIZE: usize = 0x1600;
pub const DNS_MAX_IN_DIRECTIONS: usize = 16;
pub const DNS_FLAGS_TC: u16 = 1u16 << 9;
pub const DNS_FLAGS_QR: u16 = 1u16 << 15;
pub const DNS_FLAGS_RA: u16 = 1u16 << 7;
pub const DNS_FLAGS_RD: u16 = 1u16 << 8;
pub const DNS_FLAGS_CD: u16 = 1u16 << 4;
pub const DNS_OFFSET_QUESTION: usize = DNS_HEADER_SIZE;
pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_AAAA: u16 = 28;
pub const DNS_TYPE_OPT: u16 = 41;
pub const DNS_TYPE_TXT: u16 = 16;
pub const DNS_TYPE_HINFO: u16 = 13;
pub const DNS_CLASS_INET: u16 = 1;
pub const DNS_RCODE_SERVFAIL: u8 = 2;
pub const DNS_RCODE_NXDOMAIN: u8 = 3;
pub const DNS_RCODE_RFUSED: u8 = 5;
pub const DNS_CRYPT_FULL_NONCE_SIZE: usize = crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize;
pub const DNS_CRYPT_MAC_SIZE: usize = crypto_box_curve25519xchacha20poly1305_MACBYTES as usize;
pub const DNS_CRYPT_QUERY_MAGIC_SIZE: usize = 8;
pub const DNS_CRYPT_QUERY_PK_SIZE: usize = 32;
pub const DNS_CRYPT_QUERY_NONCE_SIZE: usize = DNS_CRYPT_FULL_NONCE_SIZE / 2;
pub const DNS_CRYPT_QUERY_HEADER_SIZE: usize = DNS_CRYPT_QUERY_MAGIC_SIZE + DNS_CRYPT_QUERY_PK_SIZE + DNS_CRYPT_QUERY_NONCE_SIZE;
pub const DNS_CRYPT_QUERY_MIN_PADDING_SIZE: usize = 1;
pub const DNS_CRYPT_QUERY_MIN_OVERHEAD: usize = DNS_CRYPT_QUERY_HEADER_SIZE + DNS_CRYPT_MAC_SIZE + DNS_CRYPT_QUERY_MIN_PADDING_SIZE;
pub const DNS_CRYPT_RESPONSE_MAGIC_SIZE: usize = 8;
pub const DNS_CRYPT_RESPONSE_MAGIC: [u8; DNS_CRYPT_RESPONSE_MAGIC_SIZE] = [0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38];
pub const DNS_CRYPT_RESPONSE_CERT_PREFIX_OFFSET: usize = 4;
pub const DNS_CRYPT_RESPONSE_NONCE_SIZE: usize = DNS_CRYPT_FULL_NONCE_SIZE;
pub const DNS_CRYPT_RESPONSE_HEADER_SIZE: usize = DNS_CRYPT_RESPONSE_MAGIC_SIZE + DNS_CRYPT_RESPONSE_NONCE_SIZE;
pub const DNS_CRYPT_RESPONSE_MIN_PADDING_SIZE: usize = 1;
pub const DNS_CRYPT_RESPONSE_MIN_OVERHEAD: usize = DNS_CRYPT_RESPONSE_HEADER_SIZE + DNS_CRYPT_MAC_SIZE + DNS_CRYPT_RESPONSE_MIN_PADDING_SIZE;
pub const DNS_CRYPT_UDP_QUERY_MIN_SIZE: usize = DNS_CRYPT_QUERY_MIN_OVERHEAD + DNS_HEADER_SIZE;
pub const DNS_CRYPT_UDP_QUERY_MAX_SIZE: usize = DNS_MAX_PACKET_SIZE;
pub const DNS_CRYPT_TCP_QUERY_MIN_SIZE: usize = DNS_CRYPT_QUERY_MIN_OVERHEAD + DNS_HEADER_SIZE;
pub const DNS_CRYPT_TCP_QUERY_MAX_SIZE: usize = DNS_CRYPT_QUERY_MIN_OVERHEAD + DNS_MAX_PACKET_SIZE;
pub const DNS_CRYPT_UDP_RESPONSE_MIN_SIZE: usize = DNS_CRYPT_RESPONSE_MIN_OVERHEAD + DNS_HEADER_SIZE;
pub const DNS_CRYPT_UDP_RESPONSE_MAX_SIZE: usize = DNS_MAX_PACKET_SIZE;
pub const DNS_CRYPT_TCP_RESPONSE_MIN_SIZE: usize = DNS_CRYPT_RESPONSE_MIN_OVERHEAD + DNS_HEADER_SIZE;
pub const DNS_CRYPT_TCP_RESPONSE_MAX_SIZE: usize = DNS_CRYPT_RESPONSE_MIN_OVERHEAD + DNS_MAX_PACKET_SIZE;
pub const DNS_CRYPT_CERTS_TTL: u32 = 86400;
pub const DNS_CRYPT_CERTS_RENEWAL: u32 = 28800;



#[derive(Debug, Default, Copy, Clone, Serialize, Deserialize)]
#[repr(C, packed)]
pub struct DNSCryptCertInner {
    resolver_pk: [u8; 32],
    client_magic: [u8; 8],
    serial: [u8; 4],
    ts_start: [u8; 4],
    ts_end: [u8; 4],
}


#[derive(Educe, Serialize, Deserialize)]
#[educe(Debug, Default, Clone)]
#[repr(C, packed)]
pub struct DNSCryptCert {
    cert_magic: [u8; 4],
    es_version: [u8; 2],
    minor_version: [u8; 2],
    #[educe(Debug(ignore), Default = [0u8; 64])]
    #[serde(with = "BigArray")]
    signature: [u8; 64],
    inner: DNSCryptCertInner,
}


#[derive(Serialize, Deserialize, Clone, Educe)]
#[educe(Debug)]
pub struct DNSCryptEncryptionParams {
    dnscrypt_cert: DNSCryptCert,
    resolver_kp: CryptKeyPair,
    #[serde(skip)]
    #[educe(Debug(ignore))]
    pub key_cache: Option<Arc<Mutex<SieveCache<[u8; DNS_CRYPT_QUERY_PK_SIZE], SharedKey>>>>,
}


pub struct DNSCryptEncryptionParamsUpdater {
    globals: Arc<Globals>,
}
































