#![allow(dead_code)]

use std::{io::Write, net::Ipv4Addr, path::Path};

use account::{Account, TELEGRAM_DESKTOP};
use auth::{AuthKey, AuthKeyType};
use byteorder::{LittleEndian, WriteBytesExt};
use mtp::{Address, Config, Endpoint, Protocol};
use rusqlite::Connection;
use session::Session;
use storage::Storage;
use stream::{Endian, Stream};

pub mod account;
pub mod auth;
pub mod configs;
pub mod ige256;
pub mod mtp;
pub mod session;
pub mod storage;
pub mod stream;

const PYROGRAM_TABLE: &'static [(&'static str, &'static [&'static str])] = &[
    (
        "sessions",
        &[
            "dc_id",
            "test_mode",
            "auth_key",
            "date",
            "user_id",
            "is_bot",
        ],
    ),
    (
        "peers",
        &[
            "id",
            "access_hash",
            "type",
            "username",
            "phone_number",
            "last_update_on",
        ],
    ),
    ("version", &["number"]),
];

const TELETHON_TABLE: &'static [(&'static str, &'static [&'static str])] = &[
    (
        "sessions",
        &["dc_id", "server_address", "port", "auth_key", "takeout_id"],
    ),
    (
        "entities",
        &["id", "hash", "username", "phone", "name", "date"],
    ),
    (
        "sent_files",
        &["md5_digest", "file_size", "type", "id", "hash"],
    ),
    ("update_state", &["id", "pts", "qts", "date", "seq"]),
    ("version", &["version"]),
];

pub struct TelegramDesktop {
    main_account: Account,
}

impl TelegramDesktop {
    pub fn new(path: String) -> Self {
        let data = storage::Storage::read_file("key_data".to_string(), path.clone());

        let mut stream = Stream::new(data);

        let salt = stream.read_buffer().unwrap();
        let key_enc = stream.read_buffer().unwrap();
        let info_enc = stream.read_buffer().unwrap();

        let passcode = Storage::create_local_key(salt, b"".to_vec());
        let key_inner_data = Storage::decrypt_local(key_enc, passcode);

        let key = key_inner_data.stream().read_raw_data(256).unwrap();
        let local_key = AuthKey::new(key, AuthKeyType::Generated, 0);

        let mut info = Storage::decrypt_local(info_enc, local_key.clone()).stream();
        let count = info.read_i32(Endian::Big).unwrap();

        if count < 0 {
            panic!("accountsCount is zero");
        }

        let mut accounts = vec![];

        for _ in 0..count {
            let index = info.read_i32(Endian::Big).unwrap();

            if index >= 0 && (index < 3) {
                let mut account = Account::new(
                    TELEGRAM_DESKTOP.clone(),
                    path.clone(),
                    String::from("data"),
                    index,
                );

                account.prepare_start(local_key.clone());

                if account.is_loaded {
                    accounts.push(account);
                }
            }
        }

        let mut active_index = 0;

        if !info.at_end() {
            active_index = info.read_i32(Endian::Big).unwrap();
        }

        let main_account = accounts
            .iter()
            .find(|s| s.index == active_index)
            .unwrap_or(&accounts[0]);

        Self {
            main_account: main_account.clone(),
        }
    }

    pub fn to_raw_data(&self) -> (i32, AuthKey, Endpoint) {
        let endpoints = self
            .main_account
            .local
            .config
            .endpoints(self.main_account.main_dc_id);

        let address = mtp::Address::IPv4;
        let protocol = mtp::Protocol::Tcp;

        let mut endpoint = None;

        if let Some(endpoints_) = endpoints.get(&address) {
            if let Some(endpoints) = endpoints_.get(&protocol) {
                if endpoints.is_empty() {
                    panic!("Couldn't find endpoint for this account");
                }

                endpoint = Some(endpoints[0]);
            }
        }

        let endpoint = endpoint
            .expect("Failed to find endpoint for account")
            .clone();

        (
            self.main_account.main_dc_id,
            self.main_account.auth_key.clone().unwrap(),
            endpoint,
        )
    }
}
impl Session for TelegramDesktop {
    fn open<T: ToString>(path: T) -> rusqlite::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self::new(path.to_string()))
    }

    fn serialize(&self) -> Vec<u8> {
        let (dc_id, auth_key, endpoint) = self.to_raw_data();

        serialize_telegram_data_to_session(dc_id, endpoint.ip, endpoint.port.into(), auth_key.key)
    }

    fn validate<T: ToString>(path: T) -> rusqlite::Result<bool> {
        let path = path.to_string();

        let path = Path::new(&path);
        let chr = &["s", "1", "0"];

        Ok(path.is_dir()
            && chr
                .iter()
                .any(|c| path.join(format!("key_data{c}")).exists()))
    }
}

#[derive(Clone, Debug)]
pub struct TelethonSession {
    dc_id: i32,
    auth_key: Vec<u8>,
    server_address: Option<String>,
    port: Option<i32>,
    takeout_id: Option<i32>,
}

impl Session for TelethonSession {
    fn serialize(&self) -> Vec<u8> {
        serialize_telegram_data_to_session(
            self.dc_id,
            self.server_address.clone().expect("Ip is not founded"),
            self.port.expect("Port is not founded"),
            self.auth_key.clone(),
        )
    }

    fn validate<T: ToString>(path: T) -> rusqlite::Result<bool> {
        if let Ok(conn) = Connection::open(path.to_string()) {
            let mut stmt = conn
                .prepare("SELECT name FROM sqlite_master WHERE type='table'")
                .unwrap();

            let tables: Vec<String> = stmt
                .query_map([], |row| row.get(0))
                .unwrap()
                .map(|s| s.unwrap())
                .collect();

            if !TELETHON_TABLE
                .iter()
                .map(|s| s.0)
                .all(|s| tables.contains(&s.to_string()))
            {
                return Ok(false);
            }

            for (table, session_column) in TELETHON_TABLE {
                let mut cur = conn.prepare("select * from pragma_table_info(?1)")?;
                // println!("{table}")
                let data = cur
                    .query_map([table], |s| s.get(1))?
                    .map(|s| s.unwrap())
                    .collect::<Vec<String>>();

                if &data != session_column {
                    return Ok(false);
                }
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn open<T: ToString>(path: T) -> rusqlite::Result<Self> {
        let connection = Connection::open(path.to_string())?;
        let self_ = connection.query_row(
            "SELECT dc_id, server_address, port, auth_key, takeout_id FROM sessions",
            [],
            |s| -> rusqlite::Result<Self> {
                let self_ = Self {
                    dc_id: s.get_unwrap(0),
                    server_address: s.get_unwrap(1),
                    port: s.get_unwrap(2),
                    auth_key: s.get_unwrap(3),
                    takeout_id: s.get_unwrap(4),
                };

                Ok(self_)
            },
        )?;

        Ok(self_)
    }
}

#[derive(Clone, Debug)]
pub struct PyrogramSession {
    dc_id: i32,
    auth_key: Vec<u8>,
    user_id: Option<u64>,
    is_bot: bool,
    test_mode: bool,
    api_id: Option<i32>,
    date: Option<i64>,
    ip: String,
    port: u16,
}

impl Session for PyrogramSession {
    fn validate<T: ToString>(path: T) -> rusqlite::Result<bool> {
        if let Ok(conn) = Connection::open(path.to_string()) {
            let mut stmt = conn
                .prepare("SELECT name FROM sqlite_master WHERE type='table'")
                .unwrap();

            let tables: Vec<String> = stmt
                .query_map([], |row| row.get(0))
                .unwrap()
                .map(|s| s.unwrap())
                .collect();

            if PYROGRAM_TABLE.iter().map(|s| s.0).collect::<Vec<_>>() != tables {
                return Ok(false);
            }

            for (table, session_column) in PYROGRAM_TABLE {
                let mut cur = conn.prepare("select * from pragma_table_info(?1)")?;
                // println!("{table}")
                let mut data = cur
                    .query_map([table], |s| s.get(1))?
                    .map(|s| s.unwrap())
                    .collect::<Vec<String>>();

                let api_id_index = data.iter().position(|s| s == &String::from("api_id"));

                if let Some(api_id_index) = api_id_index {
                    data.remove(api_id_index);
                }

                if &data != session_column {
                    return Ok(false);
                }
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn open<T: ToString>(path: T) -> rusqlite::Result<Self>
    where
        Self: Sized,
    {
        let conn = Connection::open(path.to_string())?;

        let mut stmt = conn.prepare(
            "SELECT dc_id, test_mode, auth_key, date, user_id, is_bot FROM sessions LIMIT 1",
        )?;
        let mut rows = stmt.query([])?;

        if let Ok(Some(row)) = rows.next() {
            let dc_id: i32 = row.get(0)?;
            let test_mode: u8 = row.get(1)?;
            let auth_key: Vec<u8> = row.get(2)?;
            let date: Option<i64> = row.get(3)?;
            let user_id: Option<u64> = row.get(4)?;
            let is_bot: bool = row.get(5)?;

            let endpoint = Config::new(mtp::Environment::Production).endpoints(dc_id)
                [&Address::IPv4][&Protocol::Tcp][0]
                .clone();

            Ok(PyrogramSession {
                dc_id,
                auth_key,
                user_id,
                is_bot,
                test_mode: if test_mode == 0 { false } else { true },
                date,
                api_id: None,
                ip: endpoint.ip,
                port: endpoint.port,
            })
        } else {
            Err(rusqlite::Error::InvalidQuery)
        }
    }
    fn serialize(&self) -> Vec<u8> {
        serialize_telegram_data_to_session(
            self.dc_id,
            self.ip.clone(),
            self.port.into(),
            self.auth_key.clone(),
        )
    }
}

fn ip2int(addr: &str) -> Result<u32, std::net::AddrParseError> {
    addr.parse::<Ipv4Addr>().map(|ip| u32::from(ip))
}

fn serialize_telegram_data_to_session(
    dc_id: i32,
    ip: String,
    port: i32,
    auth_key: Vec<u8>,
) -> Vec<u8> {
    let mut session = vec![];

    session.write_i64::<LittleEndian>(2805905614).unwrap(); // Пишем ID сессии
    session.write_i32::<LittleEndian>(481674261).unwrap();
    session.write_i32::<LittleEndian>(1).unwrap();
    session.write_i32::<LittleEndian>(1970083510).unwrap();

    session.write_i32::<LittleEndian>(0 | 1 | 0 | 4).unwrap();
    session.write_i32::<LittleEndian>(dc_id).unwrap();

    let ip_bytes = ip2int(&ip).unwrap();
    session.write_u32::<LittleEndian>(ip_bytes).unwrap();
    session.write_i32::<LittleEndian>(port).unwrap();

    let auth_key_len = auth_key.len();
    if auth_key_len <= 253 {
        session.write_u8(auth_key_len as u8).unwrap();
        session.write_all(&auth_key).unwrap();
    } else {
        session.write_u8(254).unwrap();
        session.write_u8((auth_key_len & 0xFF) as u8).unwrap();
        session.write_u8((auth_key_len >> 8 & 0xFF) as u8).unwrap();
        session.write_u8((auth_key_len >> 16 & 0xFF) as u8).unwrap();
        session.write_all(&auth_key).unwrap();
    }

    let padding = (4 - (auth_key_len % 4)) % 4;
    session.extend(vec![0u8; padding]);

    session
}
