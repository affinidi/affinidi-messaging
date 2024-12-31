use bitfield_struct::bitfield;
use serde::{Deserialize, Serialize};

/// Each boolean value is a single bit
/// First field starts at least significant bits
#[bitfield(u16)]
#[derive(Serialize, Deserialize)]
pub struct LocalACLSet {
    #[bits(8)]
    pub acl_mode: LocalACLMode,
    pub anon_allowed: bool,
    pub change_mode: bool,
    pub change_anon_allowed: bool,
    /// These are reserved bits for future use
    #[bits(5)]
    __: usize,
}

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LocalACLMode {
    ExplicitAllow = 0,
    ExplicitDeny = 1,
}

impl LocalACLMode {
    // This has to be a const fn
    const fn into_bits(self) -> u8 {
        self as _
    }

    const fn from_bits(value: u8) -> Self {
        match value {
            0 => Self::ExplicitAllow,
            1 => Self::ExplicitDeny,
            _ => unreachable!(),
        }
    }
}
