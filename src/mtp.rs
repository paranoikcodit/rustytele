use std::collections::HashMap;
use std::default;
use std::io::{Cursor, Read};

use lazy_static::lazy_static;

use crate::stream::{Endian, Stream};

// Определяем аналог IntEnum для Environment
#[derive(Debug, Clone, Copy, PartialEq, Default, Eq)]
pub enum Environment {
    #[default]
    Production = 0,
    Test = 1,
}

#[derive(Debug, Clone, Default)]
pub struct RSAPublicKey;

pub type DcId = i32;

#[derive(Clone, Debug)]
pub struct BuiltInDc(i32, String, u16);

lazy_static! {
    pub static ref K_BUILT_IN_DCS: Vec<BuiltInDc> = vec![
        BuiltInDc(1, "149.154.175.50".to_string(), 443),
        BuiltInDc(2, "149.154.167.51".to_string(), 443),
        BuiltInDc(2, "95.161.76.100".to_string(), 443),
        BuiltInDc(3, "149.154.175.100".to_string(), 443),
        BuiltInDc(4, "149.154.167.91".to_string(), 443),
        BuiltInDc(5, "149.154.171.5".to_string(), 443),
    ];
    pub static ref K_BUILT_IN_DCS_IPV6: Vec<BuiltInDc> = vec![
        BuiltInDc(
            1,
            "2001:0b28:f23d:f001:0000:0000:0000:000a".to_string(),
            443
        ),
        BuiltInDc(
            2,
            "2001:067c:04e8:f002:0000:0000:0000:000a".to_string(),
            443
        ),
        BuiltInDc(
            3,
            "2001:0b28:f23d:f003:0000:0000:0000:000a".to_string(),
            443
        ),
        BuiltInDc(
            4,
            "2001:067c:04e8:f004:0000:0000:0000:000a".to_string(),
            443
        ),
        BuiltInDc(
            5,
            "2001:0b28:f23f:f005:0000:0000:0000:000a".to_string(),
            443
        ),
    ];
    pub static ref K_BUILT_IN_DCS_TEST: Vec<BuiltInDc> = vec![
        BuiltInDc(1, "149.154.175.10".to_string(), 443),
        BuiltInDc(2, "149.154.167.40".to_string(), 443),
        BuiltInDc(3, "149.154.175.117".to_string(), 443),
    ];
    pub static ref K_BUILT_IN_DCS_IPV6_TEST: Vec<BuiltInDc> = vec![
        BuiltInDc(
            1,
            "2001:0b28:f23d:f001:0000:0000:0000:000e".to_string(),
            443
        ),
        BuiltInDc(
            2,
            "2001:067c:04e8:f002:0000:0000:0000:000e".to_string(),
            443
        ),
        BuiltInDc(
            3,
            "2001:0b28:f23d:f003:0000:0000:0000:000e".to_string(),
            443
        ),
    ];
}

#[derive(Debug, Clone, Default)]
pub struct DcOptions {
    pub enviroment: Environment,
    pub public_keys: HashMap<DcId, RSAPublicKey>,
    pub cdn_public_keys: HashMap<DcId, RSAPublicKey>,
    pub data: HashMap<DcId, Vec<Endpoint>>,
}

impl DcOptions {
    pub fn new(enviroment: Environment) -> Self {
        let mut self_ = Self {
            enviroment,
            public_keys: HashMap::new(),
            cdn_public_keys: HashMap::new(),
            data: HashMap::new(),
        };

        self_.construct_from_built_in();

        self_
    }

    pub fn is_test_mode(&self) -> bool {
        self.enviroment != Environment::Production
    }

    pub fn apply_one_guarded(
        &mut self,
        id: DcId,
        flags: u32,
        ip: String,
        port: u16,
        secret: Vec<u8>,
    ) {
        if !self.data.contains_key(&id) {
            self.data.insert(id, Vec::new());
        }

        let endpoint = Endpoint {
            id,
            flags,
            ip: ip.clone(),
            port,
            secret: secret.clone(),
        };

        if let Some(endpoints) = self.data.get_mut(&id) {
            if !endpoints.iter().any(|e| e.ip == ip && e.port == port) {
                endpoints.push(endpoint);
            }
        }
    }

    pub fn add_data(&mut self, dcs: Vec<BuiltInDc>, flags: u32) {
        for dc in dcs {
            self.apply_one_guarded(dc.0, flags, dc.1, dc.2, vec![]);
        }
    }

    pub fn construct_from_built_in(&mut self) {
        if self.is_test_mode() {
            self.add_data(K_BUILT_IN_DCS_TEST.clone(), (1 << 4) | 0);
            self.add_data(K_BUILT_IN_DCS_IPV6_TEST.clone(), (1 << 4) | (1 << 0));
        } else {
            self.add_data(K_BUILT_IN_DCS.clone(), (1 << 4) | 0);
            self.add_data(K_BUILT_IN_DCS_IPV6.clone(), (1 << 4) | (1 << 0));
        }
    }

    pub fn construct_from_serialized(&mut self, serialized: Vec<u8>) {
        let mut stream = Stream::new(serialized);
        let minus_version = stream.read_i32(Endian::Little).unwrap();
        let version = if minus_version < 0 { -minus_version } else { 0 };

        let count = if version > 0 {
            stream.read_i32(Endian::Little).unwrap()
        } else {
            minus_version
        };

        self.data.clear();
        for _ in 0..count {
            let dc_id = stream.read_i32(Endian::Little).unwrap();
            let flags = stream.read_i32(Endian::Little).unwrap() as u32;
            let port = stream.read_i32(Endian::Little).unwrap() as u16;
            let ip_size = stream.read_i32(Endian::Little).unwrap();

            let ip = stream.read_string(ip_size as usize).unwrap();

            let secret = if version > 0 {
                let secret_size = stream.read_i32(Endian::Little).unwrap();

                stream.read_raw_data(secret_size as usize).unwrap()
            } else {
                Vec::new()
            };

            self.apply_one_guarded(dc_id, flags, ip, port, secret);
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Endpoint {
    id: DcId,
    flags: u32,
    pub ip: String,
    pub port: u16,
    secret: Vec<u8>,
}

// Адреса
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Address {
    IPv4,
    IPv6,
}

// Протоколы
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Http,
}

#[derive(Debug, Clone, Default)]
pub struct ConfigFields {
    chat_size_max: i32,
    megagroup_size_max: i32,
    forwarded_count_max: i32,
    online_update_period: i32,
    offline_blur_timeout: i32,
    offline_idle_timeout: i32,
    online_focus_timeout: i32,
    online_cloud_timeout: i32,
    notify_cloud_delay: i32,
    notify_default_delay: i32,
    saved_gifs_limit: i32,
    edit_time_limit: i32,
    revoke_time_limit: i32,
    revoke_private_time_limit: i32,
    revoke_private_inbox: bool,
    stickers_recent_limit: i32,
    stickers_faved_limit: i32,
    pinned_dialogs_count_max: i32,
    pinned_dialogs_in_folder_max: i32,
    internal_links_domain: String,
    channels_read_media_period: i32,
    call_receive_timeout_ms: i32,
    call_ring_timeout_ms: i32,
    call_connect_timeout_ms: i32,
    call_packet_timeout_ms: i32,
    web_file_dc_id: i32,
    txt_domain_string: String,
    phone_calls_enabled: bool,
    blocked_mode: bool,
    caption_length_max: i32,
}

impl ConfigFields {
    pub fn new() -> Self {
        Self {
            chat_size_max: 200,
            megagroup_size_max: 10000,
            forwarded_count_max: 100,
            online_update_period: 120000,
            offline_blur_timeout: 5000,
            offline_idle_timeout: 30000,
            online_focus_timeout: 1000,
            online_cloud_timeout: 300000,
            notify_cloud_delay: 30000,
            notify_default_delay: 1500,
            saved_gifs_limit: 200,
            edit_time_limit: 172800,
            revoke_time_limit: 172800,
            revoke_private_time_limit: 172800,
            revoke_private_inbox: false,
            stickers_recent_limit: 30,
            stickers_faved_limit: 5,
            pinned_dialogs_count_max: 5,
            pinned_dialogs_in_folder_max: 100,
            internal_links_domain: "https://t.me/".to_string(),
            channels_read_media_period: 86400 * 7,
            call_receive_timeout_ms: 20000,
            call_ring_timeout_ms: 90000,
            call_connect_timeout_ms: 30000,
            call_packet_timeout_ms: 10000,
            web_file_dc_id: 4,
            txt_domain_string: String::new(),
            phone_calls_enabled: true,
            blocked_mode: false,
            caption_length_max: 1024,
        }
    }
}

// Аналог MTP.Config
#[derive(Debug, Clone, Default)]
pub struct Config {
    dc_options: DcOptions,
    fields: ConfigFields,
}

impl Config {
    pub fn new(enviroment: Environment) -> Self {
        let dc_options = DcOptions::new(enviroment);
        let mut fields = ConfigFields::new();
        fields.web_file_dc_id = if dc_options.is_test_mode() { 2 } else { 4 };
        fields.txt_domain_string = if dc_options.is_test_mode() {
            "tapv3.stel.com".to_string()
        } else {
            "apv3.stel.com".to_string()
        };

        Self { dc_options, fields }
    }

    // Метод для получения эндпоинтов
    pub fn endpoints(&self, dc_id: DcId) -> HashMap<Address, HashMap<Protocol, Vec<&Endpoint>>> {
        let mut results: HashMap<Address, HashMap<Protocol, Vec<&Endpoint>>> = HashMap::new();
        results.insert(Address::IPv4, HashMap::new());
        results.insert(Address::IPv6, HashMap::new());

        if let Some(endpoints) = self.dc_options.data.get(&dc_id) {
            for endpoint in endpoints {
                if dc_id == 0 || endpoint.id == dc_id {
                    let address = if endpoint.flags & 0b0001 != 0 {
                        Address::IPv6
                    } else {
                        Address::IPv4
                    };

                    let protocol_tcp = results
                        .get_mut(&address)
                        .unwrap()
                        .entry(Protocol::Tcp)
                        .or_insert(vec![]);
                    protocol_tcp.push(endpoint);

                    if endpoint.flags & 1028 == 0 {
                        let protocol_http = results
                            .get_mut(&address)
                            .unwrap()
                            .entry(Protocol::Http)
                            .or_insert(vec![]);
                        protocol_http.push(endpoint);
                    }
                }
            }
        }

        results
    }

    // Десериализация объекта из потока
    pub fn from_serialized(serialized: Vec<u8>) -> Self {
        let mut stream = Stream::new(serialized);
        let version = stream.read_i32(Endian::Little).unwrap();
        assert_eq!(version, 1); // kVersion

        let env = stream.read_i32(Endian::Little).unwrap();
        let environment = if env == Environment::Test as i32 {
            Environment::Test
        } else {
            Environment::Production
        };

        let mut config = Config::new(environment);
        let dc_options_serialized = stream.read_to_end().unwrap();

        config
            .dc_options
            .construct_from_serialized(dc_options_serialized);
        config
    }
}

pub fn read_i32(cursor: &mut Cursor<Vec<u8>>) -> Result<i32, std::io::Error> {
    let mut buffer = [0u8; 4];
    cursor.read_exact(&mut buffer)?;
    Ok(i32::from_be_bytes(buffer))
}
