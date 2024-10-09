use std::{
    io::{Cursor, Seek, SeekFrom},
    ops::Deref,
    path::Path,
};

use pbkdf2::pbkdf2_hmac_array;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha512};

use crate::{
    auth::AuthKey,
    ige256::ige256,
    stream::{Endian, Stream},
};

pub struct Serialize;

impl Serialize {
    pub fn bytearray_size(arr: Vec<u8>) -> usize {
        std::mem::size_of::<u32>() + arr.len()
    }

    pub fn bytes_size(arr: &[u8]) -> usize {
        std::mem::size_of::<u32>() + arr.len()
    }

    pub fn string_size(arr: &str) -> usize {
        std::mem::size_of::<u32>() + arr.len() + std::mem::size_of::<u16>()
    }
}

pub struct EncryptedDescriptor {
    data: Vec<u8>,
}

impl EncryptedDescriptor {
    pub fn new(size: Option<usize>) -> Self {
        let mut data = vec![];
        if let Some(size) = size {
            let mut full_size = 4 + size;
            if full_size & 0x0F != 0 {
                full_size += 0x10 - (full_size & 0x0F);
            }
            data.resize(full_size, 0);
        }
        EncryptedDescriptor { data }
    }

    pub fn stream(&self) -> Stream {
        Stream::new(self.data.clone())
    }
}

// Основная структура Storage
pub struct Storage;

impl Storage {
    pub fn read_encrypted_file(
        file_name: String,
        base_path: String,
        auth_key: AuthKey,
    ) -> EncryptedDescriptor {
        let result = Self::read_file(file_name, base_path);
        let mut stream = Stream::new(result);

        let encrypted = stream.read_buffer().unwrap();

        Storage::decrypt_local(encrypted, auth_key)
    }

    pub fn read_file(file_name: String, base_path: String) -> Vec<u8> {
        let chr = &["s", "1", "0"];

        for ch in chr {
            let data =
                std::fs::read(Path::new(&base_path).join(&format!("{file_name}{ch}"))).unwrap();

            let mut stream = Stream::new(data);

            let magic = stream.read_raw_data(4).unwrap();
            if magic != b"TDF$" {
                println!("Invalid magic");
                continue;
            }

            let version = stream.read_i32(Endian::Little).unwrap();
            let mut data = stream.read_to_end().unwrap();

            let data_size = data.len() - 16;

            let check_md5 = &[
                &data[..data_size],
                &(data_size as i32).to_le_bytes(),
                &version.to_le_bytes(),
                &magic,
            ]
            .concat();

            let needed_md5 = &data[data_size..];
            let check_md5 = md5::compute(check_md5).deref().clone();

            if check_md5 != needed_md5 {
                println!("Invalid md5");
                continue;
            }

            data.resize(data_size, 0);

            return data;
        }

        panic!("Failed to read file");
    }

    pub fn compute_data_name_key(data_name: String) -> u128 {
        let data = md5::compute(data_name.as_bytes());
        return u128::from_le_bytes(data.0);
    }

    pub fn to_file_part(val: usize) -> String {
        let mut result = String::new();
        let mut val = val.clone();

        for _ in 0..0x10 {
            let v = val & 0xF;

            if v < 0x0A {
                let s: u32 = '0'.into();
                let res: char = ((s as usize + v) as u32).try_into().unwrap();
                result += &res.to_string();
            } else {
                let s: u32 = 'A'.into();
                let res: char = ((s as usize + (v - 0x0A)) as u32).try_into().unwrap();
                result += &res.to_string();
            }

            val >>= 4;
        }

        result
    }

    pub fn create_legacy_local_key(salt: Vec<u8>, passcode: Vec<u8>) -> AuthKey {
        let interations = if passcode.is_empty() { 1 } else { 100000 };

        AuthKey::new(
            pbkdf2_hmac_array::<Sha512, 256>(&passcode, &salt, interations).to_vec(),
            crate::auth::AuthKeyType::Generated,
            0,
        )
    }

    pub fn prepare_encrypted(data: &mut EncryptedDescriptor, key: AuthKey) -> Vec<u8> {
        let mut to_encrypt = data.data.clone();

        let size = to_encrypt.len();
        let mut full_size = size;
        if full_size & 0x0F != 0 {
            full_size += 0x10 - (full_size & 0x0F);
            to_encrypt.resize(full_size, 0);
        }

        let mut size_bytes = (size as u32).to_le_bytes().to_vec();
        size_bytes.append(&mut to_encrypt[4..].to_vec());

        let mut hasher = Sha1::default();
        hasher.update(&size_bytes);
        let hash = hasher.finalize();
        let encrypted = hash[0..16].to_vec();

        let aes_encrypted = Storage::aes_encrypt_local(&size_bytes, key, &encrypted);
        let encrypted = &[&encrypted[..0x10], &aes_encrypted[..]].concat();

        encrypted.to_vec()
    }

    pub fn aes_encrypt_local(src: &[u8], key: AuthKey, iv: &[u8]) -> Vec<u8> {
        let (aes_key, aes_iv) = key.prepare_aes_oldmtp(iv, false);

        ige256(src, &aes_key, &aes_iv, true)
    }

    pub fn aes_decrypt_local(src: &[u8], key: AuthKey, iv: &[u8]) -> Vec<u8> {
        let (aes_key, aes_iv) = key.prepare_aes_oldmtp(iv, false);
        ige256(src, &aes_key, &aes_iv, false)
    }

    pub fn create_local_key(salt: Vec<u8>, passcode: Vec<u8>) -> AuthKey {
        let mut hasher = Sha512::new();

        hasher.update(&salt);
        hasher.update(&passcode);
        hasher.update(&salt);

        let hash_key = &hasher.finalize()[..];

        let iterations = if passcode.is_empty() { 1 } else { 100000 };

        AuthKey::new(
            pbkdf2::pbkdf2_hmac_array::<sha2::Sha512, 256>(&hash_key, &salt, iterations).to_vec(),
            crate::auth::AuthKeyType::Generated,
            0,
        )
    }

    pub fn decrypt_local(encrypted: Vec<u8>, auth_key: AuthKey) -> EncryptedDescriptor {
        let encrypted_size = encrypted.len();

        if encrypted_size <= 16 || (encrypted_size & 0x0F != 0) {
            panic!("Bad encrypted part size: {}", encrypted_size);
        }

        let full_len = encrypted_size - 16;
        let encrypted_key = &encrypted[0..16];
        let encrypted_data = &encrypted[16..];

        let decrypted = Storage::aes_decrypt_local(encrypted_data, auth_key, encrypted_key);

        let check_hash = &Sha1::digest(&decrypted)[..16];

        if check_hash != encrypted_key {
            panic!("Bad decrypt key, data not decrypted - incorrect password?");
        }

        let data_len =
            u32::from_le_bytes([decrypted[0], decrypted[1], decrypted[2], decrypted[3]]) as usize;

        if data_len > decrypted.len() || data_len <= full_len - 16 || data_len < 4 {
            panic!(
                "Bad decrypted part size: {}, full_len: {}, decrypted size: {}",
                encrypted_size,
                full_len,
                decrypted.len()
            );
        }

        EncryptedDescriptor {
            data: decrypted[4..data_len].to_vec(),
        }
    }
}
