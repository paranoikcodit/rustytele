use std::{collections::HashMap, path::Path};

use lazy_static::lazy_static;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use crate::{
    auth::AuthKey,
    configs::{FileKey, PeerId},
    mtp::{self, DcId},
    storage::Storage,
    stream::{Endian, Stream},
};

#[derive(Default, Clone)]
pub struct Api {
    api_id: i32,
    api_hash: String,
    device_model: Option<String>,
    system_version: Option<String>,
    app_version: Option<String>,
    lang_code: Option<String>,
    system_lang_code: Option<String>,
    lang_pack: Option<String>,
}
lazy_static! {
    pub static ref TELEGRAM_DESKTOP: Api = Api {
        api_id: 2040,
        api_hash: String::from("b18441a1ff607e10a989891a5462e627"),
        ..Default::default()
    };
}

#[derive(Debug, PartialEq, Eq, FromPrimitive)]
enum LskType {
    LskUserMap = 0x00,
    LskDraft = 0x01,                 // data: PeerId peer
    LskDraftPosition = 0x02,         // data: PeerId peer
    LskLegacyImages = 0x03,          // legacy
    LskLocations = 0x04,             // no data
    LskLegacyStickerImages = 0x05,   // legacy
    LskLegacyAudios = 0x06,          // legacy
    LskRecentStickersOld = 0x07,     // no data
    LskBackgroundOldOld = 0x08,      // no data
    LskUserSettings = 0x09,          // no data
    LskRecentHashtagsAndBots = 0x0A, // no data
    LskStickersOld = 0x0B,           // no data
    LskSavedPeersOld = 0x0C,         // no data
    LskReportSpamStatusesOld = 0x0D, // no data
    LskSavedGifsOld = 0x0E,          // no data
    LskSavedGifs = 0x0F,             // no data
    LskStickersKeys = 0x10,          // no data
    LskTrustedBots = 0x11,           // no data
    LskFavedStickers = 0x12,         // no data
    LskExportSettings = 0x13,        // no data
    LskBackgroundOld = 0x14,         // no data
    LskSelfSerialized = 0x15,        // serialized self
    LskMasksKeys = 0x16,             // no data
    LskCustomEmojiKeys = 0x17,       // no data
    LskSearchSuggestions = 0x18,     // no data
    LskWebviewTokens = 0x19,         // data: QByteArray bots, QByteArray other
}

impl From<i32> for LskType {
    fn from(value: i32) -> Self {
        match value {
            0x00 => LskType::LskUserMap,
            0x01 => LskType::LskDraft,
            0x02 => LskType::LskDraftPosition,
            0x03 => LskType::LskLegacyImages,
            0x04 => LskType::LskLocations,
            0x05 => LskType::LskLegacyStickerImages,
            0x06 => LskType::LskLegacyAudios,
            0x07 => LskType::LskRecentStickersOld,
            0x08 => LskType::LskBackgroundOldOld,
            0x09 => LskType::LskUserSettings,
            0x0A => LskType::LskRecentHashtagsAndBots,
            0x0B => LskType::LskStickersOld,
            0x0C => LskType::LskSavedPeersOld,
            0x0D => LskType::LskReportSpamStatusesOld,
            0x0E => LskType::LskSavedGifsOld,
            0x0F => LskType::LskSavedGifs,
            0x10 => LskType::LskStickersKeys,
            0x11 => LskType::LskTrustedBots,
            0x12 => LskType::LskFavedStickers,
            0x13 => LskType::LskExportSettings,
            0x14 => LskType::LskBackgroundOld,
            0x15 => LskType::LskSelfSerialized,
            0x16 => LskType::LskMasksKeys,
            0x17 => LskType::LskCustomEmojiKeys,
            0x18 => LskType::LskSearchSuggestions,
            0x19 => LskType::LskWebviewTokens,
            _ => panic!("Invalid LskType value!"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MapData {
    base_path: String,
    drafts_map: HashMap<PeerId, FileKey>,
    draft_cursors_map: HashMap<PeerId, FileKey>,
    drafts_not_read_map: HashMap<PeerId, bool>,
    locations_key: FileKey,
    trusted_bots_key: FileKey,
    installed_stickers_key: FileKey,
    featured_stickers_key: FileKey,
    recent_stickers_key: FileKey,
    faved_stickers_key: FileKey,
    archived_stickers_key: FileKey,
    archived_masks_key: FileKey,
    installed_custom_emoji_key: FileKey,
    featured_custom_emoji_key: FileKey,
    archived_custom_emoji_key: FileKey,
    search_suggestions_key: FileKey,
    webview_storage_token_bots: FileKey,
    webview_storage_token_other: FileKey,
    saved_gifs_key: FileKey,
    recent_stickers_key_old: FileKey,
    legacy_background_key_day: FileKey,
    legacy_background_key_night: FileKey,

    settings_key: FileKey, // This one must be initialized with a specific value

    recent_hashtags_and_bots_key: FileKey,
    export_settings_key: FileKey,
    installed_masks_key: FileKey,
    recent_masks_key: FileKey,
}

pub fn read_map_data(local: Option<AuthKey>, base_path: String) -> MapData {
    let map_data = Storage::read_file("map".to_string(), base_path);
    let mut stream = Stream::new(map_data);

    let legacy_salt = stream.read_buffer().unwrap();
    let legacy_key_enc = stream.read_buffer().unwrap();
    let map_enc = stream.read_buffer().unwrap();

    let local_key = if let Some(local_key) = local {
        local_key
    } else {
        if legacy_salt.len() < 32 {
            panic!("Bad salt in map file");
        }

        let legacy_pass_key = Storage::create_local_key(legacy_salt, vec![]);
        let key = Storage::decrypt_local(legacy_key_enc, legacy_pass_key)
            .stream()
            .read_raw_data(256)
            .unwrap();

        AuthKey::new(key, crate::auth::AuthKeyType::Generated, 0)
    };

    let mut map = Storage::decrypt_local(map_enc, local_key).stream();

    // let mut self_serialized = Vec::new();
    let mut drafts_map: HashMap<PeerId, FileKey> = HashMap::new();
    let mut draft_cursors_map: HashMap<PeerId, FileKey> = HashMap::new();
    let mut drafts_not_read_map: HashMap<PeerId, bool> = HashMap::new();

    let mut locations_key = FileKey(0);
    let mut trusted_bots_key = FileKey(0);
    let mut recent_stickers_key_old = FileKey(0);
    let mut installed_stickers_key = FileKey(0);
    let mut featured_stickers_key = FileKey(0);
    let mut recent_stickers_key = FileKey(0);
    let mut faved_stickers_key = FileKey(0);
    let mut archived_stickers_key = FileKey(0);
    let mut installed_masks_key = FileKey(0);
    let mut recent_masks_key = FileKey(0);
    let mut archived_masks_key = FileKey(0);
    let mut installed_custom_emoji_key = FileKey(0);
    let mut featured_custom_emoji_key = FileKey(0);
    let mut archived_custom_emoji_key = FileKey(0);
    let mut search_suggestions_key = FileKey(0);
    let webview_storage_token_bots = FileKey(0);
    let webview_storage_token_other = FileKey(0);
    let mut saved_gifs_key = FileKey(0);
    let mut legacy_background_key_day = FileKey(0);
    let mut legacy_background_key_night = FileKey(0);
    let mut user_settings_key = FileKey(0);
    let mut recent_hashtags_and_bots_key = FileKey(0);
    let mut export_settings_key = FileKey(0);

    let mut is_finished = false;

    while !is_finished && !map.at_end() {
        if let Some(key_type) = LskType::from_u32(map.read_u32(Endian::Big).unwrap()) {
            match key_type {
                LskType::LskDraft => {
                    let count = map.read_u32(Endian::Big).unwrap();
                    for _ in 0..count {
                        let key = FileKey(map.read_u64(Endian::Big).unwrap());
                        let peer_id_serialized = map.read_u64(Endian::Big).unwrap();
                        let peer_id = PeerId::deserialize(peer_id_serialized);
                        drafts_map.insert(peer_id.clone(), key);
                        drafts_not_read_map.insert(peer_id.clone(), true);
                    }
                }
                LskType::LskSelfSerialized => {
                    let _self_serialized = map.read_buffer().unwrap(); // Чтение данных в selfSerialized
                }
                LskType::LskDraftPosition => {
                    let count = map.read_u32(Endian::Big).unwrap();
                    for _ in 0..count {
                        let key = FileKey(map.read_u64(Endian::Big).unwrap());
                        let peer_id_serialized = map.read_u64(Endian::Big).unwrap();
                        let peer_id = PeerId::deserialize(peer_id_serialized);
                        draft_cursors_map.insert(peer_id, key);
                    }
                }
                LskType::LskLegacyImages
                | LskType::LskLegacyStickerImages
                | LskType::LskLegacyAudios => {
                    let count = map.read_u32(Endian::Big).unwrap();
                    for _ in 0..count {
                        let _file_key = map.read_u64(Endian::Big).unwrap();
                        let _first = map.read_u64(Endian::Big).unwrap();
                        let _second = map.read_u64(Endian::Big).unwrap();
                        let _size = map.read_i32(Endian::Little).unwrap();
                    }
                }
                LskType::LskLocations => {
                    locations_key = FileKey(map.read_u64(Endian::Big).unwrap());
                }
                LskType::LskReportSpamStatusesOld => {
                    let _report_spam_statuses_key = FileKey(map.read_u64(Endian::Big).unwrap());
                }
                LskType::LskTrustedBots => {
                    trusted_bots_key = FileKey(map.read_u64(Endian::Big).unwrap());
                }
                LskType::LskRecentStickersOld => {
                    recent_stickers_key_old = FileKey(map.read_u64(Endian::Big).unwrap());
                }
                LskType::LskBackgroundOldOld => {
                    // TO BE ADDED: обработка старого фона
                    legacy_background_key_day = FileKey(map.read_u64(Endian::Big).unwrap());
                }
                LskType::LskBackgroundOld => {
                    legacy_background_key_day = FileKey(map.read_u64(Endian::Big).unwrap());
                    legacy_background_key_night = FileKey(map.read_u64(Endian::Big).unwrap());
                }
                LskType::LskUserSettings => {
                    user_settings_key = FileKey(map.read_u64(Endian::Big).unwrap());
                }
                LskType::LskRecentHashtagsAndBots => {
                    recent_hashtags_and_bots_key = FileKey(map.read_u64(Endian::Big).unwrap());
                }
                LskType::LskStickersOld => {
                    installed_stickers_key = FileKey(map.read_u64(Endian::Big).unwrap());
                }
                LskType::LskStickersKeys => {
                    installed_stickers_key = FileKey(map.read_u64(Endian::Big).unwrap());
                    featured_stickers_key = FileKey(map.read_u64(Endian::Big).unwrap());
                    recent_stickers_key = FileKey(map.read_u64(Endian::Big).unwrap());
                    archived_stickers_key = FileKey(map.read_u64(Endian::Big).unwrap());
                }
                LskType::LskFavedStickers => {
                    faved_stickers_key = FileKey(map.read_u64(Endian::Big).unwrap());
                }
                LskType::LskSavedGifsOld => {
                    let _key = map.read_u64(Endian::Big).unwrap();
                }
                LskType::LskSavedGifs => {
                    saved_gifs_key = FileKey(map.read_u64(Endian::Big).unwrap());
                }
                LskType::LskSavedPeersOld => {
                    let _key = map.read_u64(Endian::Big).unwrap();
                }
                LskType::LskExportSettings => {
                    export_settings_key = FileKey(map.read_u64(Endian::Big).unwrap());
                }
                LskType::LskMasksKeys => {
                    installed_masks_key = FileKey(map.read_u64(Endian::Big).unwrap());
                    recent_masks_key = FileKey(map.read_u64(Endian::Big).unwrap());
                    archived_masks_key = FileKey(map.read_u64(Endian::Big).unwrap());
                }
                LskType::LskCustomEmojiKeys => {
                    installed_custom_emoji_key = FileKey(map.read_u64(Endian::Big).unwrap());
                    featured_custom_emoji_key = FileKey(map.read_u64(Endian::Big).unwrap());
                    archived_custom_emoji_key = FileKey(map.read_u64(Endian::Big).unwrap());
                }
                LskType::LskSearchSuggestions => {
                    search_suggestions_key = FileKey(map.read_u64(Endian::Big).unwrap());
                }
                LskType::LskWebviewTokens => {
                    is_finished = true;
                }
                _ => {
                    panic!("Unknown key type in encrypted map: {:#?}", key_type);
                }
            }
        }
    }

    MapData {
        archived_custom_emoji_key,
        archived_masks_key,
        archived_stickers_key,
        draft_cursors_map,
        drafts_map,
        drafts_not_read_map,
        export_settings_key,
        faved_stickers_key,
        featured_custom_emoji_key,
        featured_stickers_key,
        installed_custom_emoji_key,
        installed_masks_key,
        legacy_background_key_day,
        installed_stickers_key,
        legacy_background_key_night,
        locations_key,
        recent_hashtags_and_bots_key,
        recent_masks_key,
        recent_stickers_key,
        recent_stickers_key_old,
        saved_gifs_key,
        search_suggestions_key,
        settings_key: user_settings_key,
        trusted_bots_key,
        webview_storage_token_bots,
        webview_storage_token_other,
        base_path: String::new(),
    }
}

#[derive(Clone, Default)]
pub struct StorageAccount {
    // owned: Account,
    work_path: String,
    base_path: String,
    data_name_key: u128,
    pub config: mtp::Config,

    auth_key: Option<AuthKey>,

    local_key: AuthKey,
    map_data: Option<MapData>,
}

impl StorageAccount {
    pub fn new(key_file: String, base_path: String) -> Self {
        let data_name_key = Storage::compute_data_name_key(key_file);
        let work_path = Path::new(&base_path).join(Storage::to_file_part(data_name_key as usize));
        // let work_name = Storage::to_file_part(data_name_key as usize);
        let config = mtp::Config::new(mtp::Environment::Production);

        Self {
            work_path: work_path.to_str().unwrap().to_string(),
            data_name_key,
            base_path,
            config,

            ..Default::default()
        }
    }

    pub fn read_keys(stream: &mut Stream, keys: &mut Vec<AuthKey>) {
        let count = stream.read_i32(Endian::Big).unwrap();

        for _ in 0..count {
            let dc_id = stream.read_i32(Endian::Big).unwrap();
            keys.push(AuthKey::from_stream(
                stream,
                crate::auth::AuthKeyType::ReadFromFile,
                dc_id,
            ));
        }
    }

    pub fn read_mtp_data(&self) -> Vec<u8> {
        let mut file = Storage::read_encrypted_file(
            Storage::to_file_part(self.data_name_key as usize),
            self.base_path.clone(),
            self.local_key.clone(),
        )
        .stream();

        let block_id = file.read_i32(Endian::Big).unwrap();

        if block_id != 75 {
            panic!("Not supported file version");
        }

        file.read_buffer().unwrap()
    }

    pub fn start(&mut self, local_key: AuthKey) {
        self.local_key = local_key.clone();
        self.map_data = Some(read_map_data(Some(local_key), self.work_path.clone()));
    }
}

#[derive(Clone, Default)]
pub struct Account {
    api: Api,
    base_path: String,
    key_file: String,
    pub index: i32,
    mtp_keys: Vec<AuthKey>,
    mtp_keys_to_destroy: Vec<AuthKey>,
    pub main_dc_id: DcId,
    pub user_id: u64,
    pub is_loaded: bool,
    pub local: StorageAccount,
    pub auth_key: Option<AuthKey>,
    local_key: Option<AuthKey>,
}

impl Account {
    pub fn new(api: Api, base_path: String, key_file: String, index: i32) -> Self {
        Self {
            api,
            index,
            base_path: base_path.clone(),
            key_file: key_file.clone(),
            local: StorageAccount::new(key_file, base_path),

            ..Default::default()
        }
    }

    pub fn read_mtp_authorization(&mut self, data: Vec<u8>) {
        let mut stream = Stream::new(data);

        let user_id = stream.read_i32(Endian::Big).unwrap() as i64;
        let main_dc_id = stream.read_i32(Endian::Big).unwrap() as i64;

        if ((user_id << 32) | main_dc_id) == -1 {
            self.user_id = stream.read_u64(Endian::Big).unwrap();
            self.main_dc_id = stream.read_i32(Endian::Big).unwrap();
        } else {
            self.user_id = user_id as u64;
            self.main_dc_id = main_dc_id as i32;
        }

        let mut mtp_keys = Vec::new();
        let mut mtp_keys_to_destroy = Vec::new();

        StorageAccount::read_keys(&mut stream, &mut mtp_keys);
        StorageAccount::read_keys(&mut stream, &mut mtp_keys_to_destroy);

        for key in mtp_keys {
            if key.dc_id == self.main_dc_id {
                self.auth_key = Some(key);
            }
        }

        if self.auth_key.is_none() {
            panic!("Could not find authKey");
        }

        self.is_loaded = true;
    }

    pub fn prepare_start(&mut self, local_key: AuthKey) {
        self.local.start(local_key);

        let serialized = self.local.read_mtp_data();

        self.read_mtp_authorization(serialized);
    }
}
