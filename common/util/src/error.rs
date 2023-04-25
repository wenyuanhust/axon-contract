use ckb_std::error::SysError;

/// Error
#[repr(i8)]
pub enum Error {
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,

    // common
    BadWitnessInputType = 10,
    BadWitnessLock,
    SignatureMismatch,
    LockScriptEmpty,
    TypeScriptEmpty,
    MismatchInputOutputAtAmount,
    ATCellShouldEmpty,
    BadScriptArgs,
    UnknownMode,

    // selection contract
    OmniCheckpointCountError = 20,

    // stake AT type script
    StakeDataEmpty,
    MissMatchSmtTypeId,
    UpdateModeError,
    BadSudtDataFormat,
    BadInaugurationEpoch,
    BadStakeChange,
    RedeemExceedLimit,
    BadStakeStakeChange,
    BadStakeRedeemChange,
    IllegalDefaultStakeInfo,
    IllegalInputStakeInfo,
    IllegalOutputStakeInfo,
    BadRedeem,
    BadElectionTime,
    OldStakeInfosErr,
    StaleStakeInfo,
    NewStakeInfosErr,
    BadInputStakeSmtCellCount,
    BadOutputStakeSmtCellCount,

    // checkpoint
    CheckpointDataEmpty,
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        use SysError::*;
        match err {
            IndexOutOfBound => Self::IndexOutOfBound,
            ItemMissing => Self::ItemMissing,
            LengthNotEnough(_) => Self::LengthNotEnough,
            Encoding => Self::Encoding,
            Unknown(err_code) => panic!("unexpected sys error {}", err_code),
        }
    }
}
