#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileKey(pub u64);

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct PeerId(pub u128);

impl PeerId {
    pub fn deserialize(data: u64) -> Self {
        let flag: u64 = 128 << 48;
        let legacy = !(data & flag as u64);

        if legacy == 0 {
            Self(((data as i128) & (-((flag as i128) + 1))) as u128);
        }

        let mask = 0xFFFFFFFF;
        let type_mask = 0xF00000000;
        let user_shift = 0x000000000;
        let chat_shift = 0x100000000;
        let channel_shift = 0x200000000;
        let fake_shift = 0xF00000000;

        let data = data as u128;

        Self(if (data & type_mask) == user_shift {
            (data & mask) | (0 << 48)
        } else if (data & type_mask) == chat_shift {
            (data & mask) | (1 << 48)
        } else if (data & type_mask) == channel_shift {
            (data & mask) | (2 << 48)
        } else if (data & type_mask) == fake_shift {
            (data & mask) | (3 << 48)
        } else {
            0
        })
    }
}

// НАДО ДЕЙСТВОВАТЬ
