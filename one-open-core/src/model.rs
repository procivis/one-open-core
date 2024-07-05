use strum_macros::{Display, EnumString};

#[derive(Debug, Copy, Clone, Display, EnumString, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyAlgorithmType {
    #[strum(serialize = "EDDSA")]
    Eddsa,
    #[strum(serialize = "BBS_PLUS")]
    BbsPlus,
    #[strum(serialize = "ES256")]
    Es256,
}
