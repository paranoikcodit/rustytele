use sha1::{Digest, Sha1};

use crate::{
    mtp::DcId,
    stream::{Endian, Stream},
};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum AuthKeyType {
    #[default]
    Generated = 0,
    Temporary = 1,
    ReadFromFile = 2,
    Local = 3,
}

#[derive(Clone, Default, Debug)]
pub struct AuthKey {
    pub key_type: AuthKeyType,
    pub dc_id: DcId,
    pub key: Vec<u8>,
    pub key_id: u64,
}

impl From<&mut Stream> for AuthKey {
    fn from(value: &mut Stream) -> Self {
        let dc_id = value.read_i32(Endian::Big).unwrap();
        let data = value.read_raw_data(256).unwrap();

        Self::new(data, AuthKeyType::ReadFromFile, dc_id)
    }
}

impl AuthKey {
    const KSIZE: usize = 256;

    pub fn new(key: Vec<u8>, key_type: AuthKeyType, dc_id: DcId) -> Self {
        let mut auth_key = AuthKey {
            key_type,
            dc_id,
            key,
            key_id: 0,
        };

        auth_key.count_key_id();
        auth_key
    }

    fn count_key_id(&mut self) {
        let mut hasher = Sha1::new();
        hasher.update(&self.key);
        let hash = hasher.finalize();

        self.key_id = u64::from_le_bytes([
            hash[12], hash[13], hash[14], hash[15], hash[16], hash[17], hash[18], hash[19],
        ]);
    }

    pub fn prepare_aes_oldmtp(&self, msg_key: &[u8], send: bool) -> (Vec<u8>, Vec<u8>) {
        let x = if send { 0 } else { 8 };

        // Compute sha1_a
        let mut hasher_a = Sha1::new();
        hasher_a.update(&msg_key[..16]);
        hasher_a.update(&self.key[x..x + 32]);
        let sha1_a = hasher_a.finalize();

        // Compute sha1_b
        let mut hasher_b = Sha1::new();
        hasher_b.update(&self.key[x + 32..x + 48]);
        hasher_b.update(&msg_key[..16]);
        hasher_b.update(&self.key[x + 48..x + 64]);
        let sha1_b = hasher_b.finalize();

        // Compute sha1_c
        let mut hasher_c = Sha1::new();
        hasher_c.update(&self.key[x + 64..x + 96]);
        hasher_c.update(&msg_key[..16]);
        let sha1_c = hasher_c.finalize();

        // Compute sha1_d
        let mut hasher_d = Sha1::new();
        hasher_d.update(&msg_key[..16]);
        hasher_d.update(&self.key[x + 96..x + 128]);
        let sha1_d = hasher_d.finalize();

        // Construct aesKey
        let mut aes_key = Vec::with_capacity(32);
        aes_key.extend_from_slice(&sha1_a[0..8]);
        aes_key.extend_from_slice(&sha1_b[8..20]);
        aes_key.extend_from_slice(&sha1_c[4..16]);

        // Construct aesIv
        let mut aes_iv = Vec::with_capacity(32);
        aes_iv.extend_from_slice(&sha1_a[8..20]);
        aes_iv.extend_from_slice(&sha1_b[0..8]);
        aes_iv.extend_from_slice(&sha1_c[16..20]);
        aes_iv.extend_from_slice(&sha1_d[0..8]);

        (aes_key, aes_iv)
    }

    fn sha1_concat(parts: &[&[u8]]) -> Vec<u8> {
        let mut hasher = Sha1::default();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize().to_vec()
    }

    pub fn from_stream(stream: &mut Stream, key_type: AuthKeyType, dc_id: DcId) -> Self {
        let key_data = stream.read_raw_data(Self::KSIZE).unwrap();
        AuthKey::new(key_data, key_type, dc_id)
    }
}
