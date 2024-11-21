use crate::*;

#[derive(Serialize, SchemaType)]
pub struct InitParam {
    /// The contract address of the token.
    pub token_address: ContractAddress,
    /// The weight at which rewards are calculated, should be in percentage
    pub weight: u32,
    /// the decimals of the token contract,
    pub decimals: u8,
    pub admin: Address,
    pub smart_wallet: ContractAddress,
}

pub type ContractTokenId = TokenIdUnit;
pub type ContractTokenAmount = TokenAmountU64;

#[derive(Serialize, SchemaType, Clone, Debug)]
pub struct Unbounding {
    amount: Amount,
    unlock_time: Timestamp,
}

#[derive(Serialize, SchemaType, Clone)]
pub struct StakerInfo {
    staked_amount: Amount,
    last_reward_timestamp: Timestamp,
    pending_rewards: Amount,
    unbonding: Vec<Unbounding>,
    slashed: bool, // Track if staker has been slashed
}

#[derive(Serialize, SchemaType, PartialEq, Eq, Clone, Debug)]
pub struct StakeEntry {
    pub amount: TokenAmountU64,
    pub time_of_stake: Timestamp,
    pub token_id: TokenIdUnit,
}

#[derive(Debug, Serial, Deserial, PartialEq, Eq, SchemaType)]
#[concordium(repr(u8))]
pub enum StakingEvent {
    #[concordium(tag = 246)]
    Staked {
        staker: PublicKeyEd25519,
        amount: TokenAmountU64,
        time: Timestamp,
    },
    #[concordium(tag = 245)]
    Unstaking {
        staker: PublicKeyEd25519,
        amount: TokenAmountU64,
        time: Timestamp,
    },
    #[concordium(tag = 244)]
    TokenDeposit {
        sender: Address,
        amount: TokenAmountU64,
    },
    #[concordium(tag = 243)]
    AdminWithdraw {
        sender: Address,
        amount: TokenAmountU64,
    },
}

#[derive(Debug, PartialEq, Eq, Clone, Reject, Serialize, SchemaType)]
pub enum StakingError {
    StakingNotFound,
    InsufficientFunds,
    InvalidPrice,
    InvalidReleaseTime,
    InvalidStakingState,
    #[from(ParseError)]
    ParseParams,
    #[from(TransferError)]
    TransferError,
    ContractInvokeError,
    OnlyContractCanStake,
    SenderContractAddressIsNotAllowedToStake,
    CannotStakeLessThanAllowAmount,
    SenderIsNotOwner,
    DaysOfStakeCouldNotBeCalculated,
    SenderIsNotAdmin,
    Expired,
    WrongSignature,
    SignatureVerficationFailed,
    CouldNotParseAdditionalData,
    Overflow,
}

#[derive(Serialize, SchemaType)]
pub struct RewardResult {
    pub days: u64,
    pub rewards: u64,
    pub amount_staked: u64,
}

pub type StakeQuery = Option<StakeEntry>;

#[derive(Serialize, SchemaType)]
pub struct UnstakeParam {
    pub amount: TokenAmountU64,
    pub staker: PublicKeyEd25519,
}

pub const TOKEN_ID: TokenIdUnit = TokenIdUnit();
