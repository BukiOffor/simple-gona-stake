//! Tests for the `smart_contract_wallet` contract.
use concordium_cis2::*;
use concordium_smart_contract_testing::*;
use concordium_std::{Deserial, PublicKeyEd25519, SchemaType, Serial, Serialize, SignatureEd25519};
use gona_stake::types::*;
use gona_stake::*;
use primitive_types::*;

/// The tests accounts.
const ALICE: AccountAddress = AccountAddress([0; 32]);
const ALICE_ADDR: Address = Address::Account(ALICE);
const BOB: AccountAddress = AccountAddress([1; 32]);
//const BOB_ADDR: Address = Address::Account(BOB);
const CHARLIE: AccountAddress = AccountAddress([2; 32]);
const CHARLIE_ADDR: Address = Address::Account(CHARLIE);

const ALICE_PUBLIC_KEY: PublicKeyEd25519 = PublicKeyEd25519([7; 32]);
const BOB_PUBLIC_KEY: PublicKeyEd25519 = PublicKeyEd25519([8; 32]);
const SERVICE_FEE_RECIPIENT_KEY: PublicKeyEd25519 = PublicKeyEd25519([9; 32]);

/// Initial balance of the accounts.
const ACC_INITIAL_BALANCE: Amount = Amount::from_ccd(10000);

const TOKEN_ID: TokenIdUnit = TokenIdUnit();
/// Airdrop amount = 100,000 * 1e6
const AIRDROP_TOKEN_AMOUNT: u64 = 100_000_000_000_000;
/// Pool token amount for rewards 500,000 * 1e6
const POOL_REWARD_AMOUNT: u64 = 500_000_000_000;
/// Amount to stake 50,000 * 1e6
const STAKE_AMOUNT: u64 = 50_000_000_000;
/// Half of the stake amount 25,000 * 1e6
const WITHDRAW_STAKE_AMOUNT: u64 = 25_000_000_000;
/// 100,000 * 1e6
const ALICE_KEY_AMOUNT: u64 = 100_000_000_000;
/// weight of rewards 8500 == 0.0085%
const WEIGHT: u32 = 8500;
/// Decimal of token: 6_u8
const DECIMALS: u8 = 6;
/// days of stake: 20_u64 days
const DAYS: u64 = 20;

const DUMMY_SIGNATURE: SignatureEd25519 = SignatureEd25519([
    68, 134, 96, 171, 184, 199, 1, 93, 76, 87, 144, 68, 55, 180, 93, 56, 107, 95, 127, 112, 24, 55,
    162, 131, 165, 91, 133, 104, 2, 5, 78, 224, 214, 21, 66, 0, 44, 108, 52, 4, 108, 10, 123, 75,
    21, 68, 42, 79, 106, 106, 87, 125, 122, 77, 154, 114, 208, 145, 171, 47, 108, 96, 221, 13,
]);

/// A signer for all the transactions.
const SIGNER: Signer = Signer::with_one_key();

#[derive(SchemaType, Serialize, PartialEq, Eq, Debug)]
pub struct MintParam {
    token_id: TokenIdUnit,
    amount: TokenAmountU64,
    owner: Address,
}

/// The withdraw message that is signed by the signer.
#[derive(Serialize, Clone, SchemaType)]
#[cfg_attr(feature = "serde", derive(SerdeSerialize, SerdeDeserialize))]
pub struct WithdrawMessage<T: SigningAmount> {
    /// The entry_point that the signature is intended for.
    pub entry_point: OwnedEntrypointName,
    /// A timestamp to make the signatures expire.
    pub expiry_time: Timestamp,
    /// A nonce to prevent replay attacks.
    pub nonce: u64,
    /// The recipient public key of the service fee.
    pub service_fee_recipient: PublicKeyEd25519,
    /// The amount of CCD or tokens to be received as a service fee.
    pub service_fee_amount: T,
    /// List of withdrawals.
    #[concordium(size_length = 2)]
    pub simple_withdraws: Vec<Withdraw<T>>,
}
pub trait SigningAmount: Deserial + Serial {}

#[derive(Serialize, Clone, SchemaType)]
#[cfg_attr(feature = "serde", derive(SerdeSerialize, SerdeDeserialize))]
pub struct Withdraw<T: SigningAmount> {
    /// The address receiving the CCD or tokens being withdrawn.
    pub to: Receiver,
    /// The amount being withdrawn.
    pub withdraw_amount: T,
    /// Some additional data for the receive hook function.
    pub data: AdditionalData,
}
/// `SigningAmount` trait definition for `Amount`.
impl SigningAmount for Amount {}
/// `SigningAmount` trait definition for `TokenAmount`.
impl SigningAmount for TokenAmount {}

/// The token amount signed in the message.
#[derive(Serialize, Clone, SchemaType)]
#[cfg_attr(feature = "serde", derive(SerdeSerialize, SerdeDeserialize))]
pub struct TokenAmount {
    /// The token amount signed in the message.
    pub token_amount: TokenAmountU256,
    /// The token id of the token signed in the message.
    pub token_id: TokenIdUnit,
    /// The token contract of the token signed in the message.
    pub cis2_token_contract_address: ContractAddress,
}
pub trait IsMessage {
    fn expiry_time(&self) -> Timestamp;
    fn nonce(&self) -> u64;
}

impl<T: SigningAmount> IsMessage for WithdrawMessage<T> {
    fn expiry_time(&self) -> Timestamp {
        self.expiry_time
    }

    fn nonce(&self) -> u64 {
        self.nonce
    }
}
/// A batch of withdrawals signed by a signer.
#[derive(Serialize, SchemaType)]
#[cfg_attr(feature = "serde", derive(SerdeSerialize, SerdeDeserialize))]
pub struct WithdrawBatch<T: SigningAmount> {
    /// The signer public key.
    pub signer: PublicKeyEd25519,
    /// The signature.
    pub signature: SignatureEd25519,
    /// The message being signed.
    pub message: WithdrawMessage<T>,
}

/// The parameter type for the contract functions
/// `withdrawCcd/withdrawCis2Tokens`.
#[derive(Serialize, SchemaType)]
#[cfg_attr(feature = "serde", derive(SerdeSerialize, SerdeDeserialize))]
#[concordium(transparent)]
#[repr(transparent)]
pub struct WithdrawParameter<T: SigningAmount> {
    /// List of withdraw batches.
    #[concordium(size_length = 2)]
    pub withdraws: Vec<WithdrawBatch<T>>,
}

pub type Sha256 = [u8; 32];
#[derive(Serialize, SchemaType, Clone, PartialEq, Eq, Debug)]
pub struct SetMetadataUrlParams {
    /// The URL following the specification RFC1738.
    pub url: String,
    /// The hash of the document stored at the above URL.
    pub hash: Option<Sha256>,
}

/// Test withdrawing of cis2 tokens.
#[test]
fn test_stake_cis2_tokens() {
    let (mut chain, smart_contract_wallet, cis2_token_contract_address, gona_stake_address) =
        initialize_chain_and_contract();

    use ed25519_dalek::{Signer, SigningKey};

    let rng = &mut rand::thread_rng();

    // Construct signing key.
    let signing_key = SigningKey::generate(rng);
    let alice_public_key = PublicKeyEd25519(signing_key.verifying_key().to_bytes());

    alice_deposits_cis2_tokens_and_fund_pool(
        &mut chain,
        smart_contract_wallet,
        cis2_token_contract_address,
        alice_public_key,
        gona_stake_address,
    );

    let service_fee_amount: TokenAmountU256 = TokenAmountU256(0.into());
    let withdraw_amount: TokenAmountU256 = TokenAmountU256(U256::from(STAKE_AMOUNT));

    let message = WithdrawMessage {
        entry_point: OwnedEntrypointName::new_unchecked("withdrawCis2Tokens".to_string()),
        expiry_time: Timestamp::now(),
        nonce: 0u64,
        service_fee_recipient: SERVICE_FEE_RECIPIENT_KEY,
        simple_withdraws: vec![Withdraw {
            to: Receiver::Contract(
                gona_stake_address,
                OwnedEntrypointName::new("stake".to_owned()).unwrap(),
            ),
            withdraw_amount: TokenAmount {
                token_amount: withdraw_amount,
                token_id: TOKEN_ID,
                cis2_token_contract_address,
            },
            data: AdditionalData::from(to_bytes(&alice_public_key)),
        }],
        service_fee_amount: TokenAmount {
            token_amount: service_fee_amount,
            token_id: TOKEN_ID,
            cis2_token_contract_address,
        },
    };

    let mut withdraw = WithdrawBatch {
        signer: alice_public_key,
        signature: DUMMY_SIGNATURE,
        message: message.clone(),
    };
    // Get the message hash to be signed.
    let invoke = chain
        .contract_invoke(
            ALICE,
            ALICE_ADDR,
            Energy::from(10000),
            UpdateContractPayload {
                amount: Amount::zero(),
                address: smart_contract_wallet,
                receive_name: OwnedReceiveName::new_unchecked(
                    "smart_contract_wallet.getCis2WithdrawMessageHash".to_string(),
                ),
                message: OwnedParameter::from_serial(&message)
                    .expect("Should be a valid inut parameter"),
            },
        )
        .expect("Should be able to query getCis2WithdrawMessageHash");

    let signature = signing_key.sign(&invoke.return_value);

    withdraw.signature = SignatureEd25519(signature.to_bytes());

    let withdraw_param = WithdrawParameter {
        withdraws: vec![withdraw],
    };

    let _update = chain
        .contract_update(
            SIGNER,
            CHARLIE,
            CHARLIE_ADDR,
            Energy::from(10000),
            UpdateContractPayload {
                amount: Amount::zero(),
                receive_name: OwnedReceiveName::new_unchecked(
                    "smart_contract_wallet.withdrawCis2Tokens".to_string(),
                ),
                address: smart_contract_wallet,
                message: OwnedParameter::from_serial(&withdraw_param)
                    .expect("Withdraw cis2 tokens params"),
            },
        )
        .expect("Should be able to withdraw cis2 tokens");

    let stake = get_stake_query(&mut chain, gona_stake_address, alice_public_key);
    println!("{:?}", stake);
    assert_eq!(stake.is_some(), true, "Stake did not return");

    // ff block time by 20 days and stake again
    chain.tick_block_time(Duration::from_days(DAYS)).unwrap();

    // calculate the reward time and amount
    // this algorithm should be determistic and rewards can always be calculated
    // after a given amount of time in `DAYS`
    let reward = calculate_reward(&mut chain, gona_stake_address, alice_public_key);
    let reward_for_1st_stake = calculate_percent(STAKE_AMOUNT, WEIGHT, DECIMALS) * reward.days;
    println!(
        "amount:{}, days: {}, reward:{}",
        reward.days, reward.rewards, reward.amount_staked
    );
    assert_eq!(reward.days, DAYS, "Days should equal 20");
    assert_eq!(
        reward_for_1st_stake, reward.rewards,
        "reward amount should be deterministic"
    );
}

#[test]
fn test_unstake_cis2_tokens_of_chaperone() {
    let (mut chain, smart_contract_wallet, cis2_token_contract_address, gona_stake_address) =
        initialize_chain_and_contract();

    use ed25519_dalek::{Signer, SigningKey};

    let rng = &mut rand::thread_rng();

    // Construct signing key.
    let signing_key = SigningKey::generate(rng);
    let alice_public_key = PublicKeyEd25519(signing_key.verifying_key().to_bytes());

    alice_deposits_cis2_tokens_and_fund_pool(
        &mut chain,
        smart_contract_wallet,
        cis2_token_contract_address,
        alice_public_key,
        gona_stake_address,
    );

    let service_fee_amount: TokenAmountU256 = TokenAmountU256(0.into());
    let withdraw_amount: TokenAmountU256 = TokenAmountU256(U256::from(STAKE_AMOUNT));

    let message = WithdrawMessage {
        entry_point: OwnedEntrypointName::new_unchecked("withdrawCis2Tokens".to_string()),
        expiry_time: Timestamp::now(),
        nonce: 0u64,
        service_fee_recipient: SERVICE_FEE_RECIPIENT_KEY,
        simple_withdraws: vec![Withdraw {
            to: Receiver::Contract(
                gona_stake_address,
                OwnedEntrypointName::new("stake".to_owned()).unwrap(),
            ),
            withdraw_amount: TokenAmount {
                token_amount: withdraw_amount,
                token_id: TOKEN_ID,
                cis2_token_contract_address,
            },
            data: AdditionalData::from(to_bytes(&alice_public_key)),
        }],
        service_fee_amount: TokenAmount {
            token_amount: service_fee_amount,
            token_id: TOKEN_ID,
            cis2_token_contract_address,
        },
    };

    let mut withdraw = WithdrawBatch {
        signer: alice_public_key,
        signature: DUMMY_SIGNATURE,
        message: message.clone(),
    };
    // Get the message hash to be signed.
    let invoke = chain
        .contract_invoke(
            ALICE,
            ALICE_ADDR,
            Energy::from(10000),
            UpdateContractPayload {
                amount: Amount::zero(),
                address: smart_contract_wallet,
                receive_name: OwnedReceiveName::new_unchecked(
                    "smart_contract_wallet.getCis2WithdrawMessageHash".to_string(),
                ),
                message: OwnedParameter::from_serial(&message)
                    .expect("Should be a valid inut parameter"),
            },
        )
        .expect("Should be able to query getCis2WithdrawMessageHash");

    let signature = signing_key.sign(&invoke.return_value);

    withdraw.signature = SignatureEd25519(signature.to_bytes());

    let withdraw_param = WithdrawParameter {
        withdraws: vec![withdraw],
    };

    // send tokens from smart wallet to stake contract
    // this is the act of staking
    let _update = chain
        .contract_update(
            SIGNER,
            CHARLIE,
            CHARLIE_ADDR,
            Energy::from(10000),
            UpdateContractPayload {
                amount: Amount::zero(),
                receive_name: OwnedReceiveName::new_unchecked(
                    "smart_contract_wallet.withdrawCis2Tokens".to_string(),
                ),
                address: smart_contract_wallet,
                message: OwnedParameter::from_serial(&withdraw_param)
                    .expect("Withdraw cis2 tokens params"),
            },
        )
        .expect("Should be able to withdraw cis2 tokens");

    // assert if the stake was successful
    let stake = get_stake_query(&mut chain, gona_stake_address, alice_public_key);
    assert_eq!(stake.is_some(), true, "Stake did not return");

    // assert stake amount should match amount that was staked
    assert_eq!(
        stake.unwrap().amount.0,
        STAKE_AMOUNT,
        "Stake State Balance should match the balance"
    );

    chain
        .tick_block_time(Duration::from_days(DAYS))
        .expect("days should be ticked");

    // calculate the reward time and amount
    // this algorithm should be determistic and rewards can always be calculated
    // after a given amount of time in `DAYS`
    let reward = calculate_reward(&mut chain, gona_stake_address, alice_public_key);
    let reward_for_1st_stake = calculate_percent(STAKE_AMOUNT, WEIGHT, DECIMALS) * reward.days;
    println!(
        "amount:{}, days: {}, reward:{}",
        reward.days, reward.rewards, reward.amount_staked
    );
    assert_eq!(reward.days, DAYS, "Days should equal 20");
    assert_eq!(
        reward_for_1st_stake, reward.rewards,
        "reward amount should be deterministic"
    );

    release_stake(
        &mut chain,
        gona_stake_address,
        alice_public_key,
        signing_key,
        WITHDRAW_STAKE_AMOUNT - 10_000_000_000,
    );

    let reward_after_release = calculate_reward(&mut chain, gona_stake_address, alice_public_key);
    println!(
        "reward after release: {}",
        reward_after_release.amount_staked
    );

    let stake = get_stake_query(&mut chain, gona_stake_address, alice_public_key)
        .expect("stake should exist");
    println!("the stake: {:?}", stake);

    let res = view_reward_amount(&mut chain, gona_stake_address);
    assert_ne!(
        res, POOL_REWARD_AMOUNT,
        "pool reward should be depleted since an amount was paid out"
    )
}

/// Setup chain and contract.
///
/// Also creates the three accounts, Alice, Bob, and Charlie.
///
/// Alice is the owner of the contract.
fn initialize_chain_and_contract() -> (Chain, ContractAddress, ContractAddress, ContractAddress) {
    let mut chain = Chain::new();

    // Create some accounts on the chain.
    chain.create_account(Account::new(ALICE, ACC_INITIAL_BALANCE));
    chain.create_account(Account::new(BOB, ACC_INITIAL_BALANCE));
    chain.create_account(Account::new(CHARLIE, ACC_INITIAL_BALANCE));

    let metadata = SetMetadataUrlParams {
        url: "https://www.example.come".to_string(),
        hash: None,
    };
    // Load and deploy cis2 token module.
    let module = module_load_v1("tests/cis2_token/module.wasm.v1").expect("Module exists");
    let deployment = chain
        .module_deploy_v1_debug(SIGNER, ALICE, module, true)
        .expect("Deploy valid module");

    // Initialize the token contract.
    let cis2_token_contract_init = chain
        .contract_init(
            SIGNER,
            ALICE,
            Energy::from(10000),
            InitContractPayload {
                amount: Amount::zero(),
                mod_ref: deployment.module_reference,
                init_name: OwnedContractName::new_unchecked("init_gona_token".to_string()),
                param: OwnedParameter::from_serial(&metadata).expect("Token amount params"),
            },
        )
        .expect("Initialize contract");

    // Load and deploy the smart wallet module.
    let module = module_load_v1("tests/chaperone/module.wasm.v1").expect("Module exists");
    let deployment = chain
        .module_deploy_v1_debug(SIGNER, ALICE, module, true)
        .expect("Deploy valid module");

    // Initialize the smart contract wallet.
    let smart_contract_wallet_init = chain
        .contract_init(
            SIGNER,
            ALICE,
            Energy::from(10000),
            InitContractPayload {
                amount: Amount::zero(),
                mod_ref: deployment.module_reference,
                init_name: OwnedContractName::new_unchecked(
                    "init_smart_contract_wallet".to_string(),
                ),
                param: OwnedParameter::empty(),
            },
        )
        .expect("Initialize contract");

    // Load and deploy the gona stake module.
    let module = module_load_v1("dist/stake.wasm.v1").expect("Module exists");
    let deployment = chain
        .module_deploy_v1_debug(SIGNER, ALICE, module, true)
        .expect("Deploy valid module");

    // Initialize the smart contract wallet.
    let param = InitParam {
        admin: Address::Account(ALICE),
        decimals: DECIMALS,
        token_address: cis2_token_contract_init.contract_address,
        weight: WEIGHT,
        smart_wallet: smart_contract_wallet_init.contract_address,
    };
    let param = OwnedParameter::from_serial(&param).unwrap();
    let gona_stake_init = chain
        .contract_init(
            SIGNER,
            ALICE,
            Energy::from(10000),
            InitContractPayload {
                amount: Amount::zero(),
                mod_ref: deployment.module_reference,
                init_name: OwnedContractName::new_unchecked("init_gona_stake".to_string()),
                param,
            },
        )
        .expect("Initialize contract");

    (
        chain,
        smart_contract_wallet_init.contract_address,
        cis2_token_contract_init.contract_address,
        gona_stake_init.contract_address,
    )
}

fn alice_deposits_cis2_tokens_and_fund_pool(
    chain: &mut Chain,
    smart_contract_wallet: ContractAddress,
    cis2_token_contract_address: ContractAddress,
    alice_public_key: PublicKeyEd25519,
    gona_stake_address: ContractAddress,
) {
    let mint_param: MintParam = MintParam {
        owner: Address::Account(ALICE),
        token_id: TOKEN_ID,
        amount: TokenAmountU64(AIRDROP_TOKEN_AMOUNT),
    };

    //Deposit tokens.
    let _update = chain
        .contract_update(
            SIGNER,
            ALICE,
            ALICE_ADDR,
            Energy::from(10000),
            UpdateContractPayload {
                amount: Amount::zero(),
                receive_name: OwnedReceiveName::new_unchecked("gona_token.mint".to_string()),
                address: cis2_token_contract_address,
                message: OwnedParameter::from_serial(&mint_param).expect("Mint cis2 tokens params"),
            },
        )
        .expect("Should be able to deposit cis2 tokens");

    // // Create a Transfer instance
    let transfer_payload = concordium_cis2::Transfer {
        token_id: TOKEN_ID,
        amount: TokenAmountU64(ALICE_KEY_AMOUNT),
        to: Receiver::Contract(
            smart_contract_wallet,
            OwnedEntrypointName::new_unchecked("depositCis2Tokens".into()),
        ),
        from: ALICE_ADDR,
        data: AdditionalData::from(to_bytes(&alice_public_key)),
    };
    // Create a Transfer instance
    let transfer_pool_payload = concordium_cis2::Transfer {
        token_id: TOKEN_ID,
        amount: TokenAmountU64(POOL_REWARD_AMOUNT),
        to: Receiver::Contract(
            gona_stake_address,
            OwnedEntrypointName::new_unchecked("depositCis2Tokens".into()),
        ),
        from: ALICE_ADDR,
        data: AdditionalData::empty(),
    };
    let mut transfers = Vec::new();
    transfers.push(transfer_payload);
    transfers.push(transfer_pool_payload);

    let payload = TransferParams::from(transfers);
    // Deposit tokens.
    let _update = chain
        .contract_update(
            SIGNER,
            ALICE,
            ALICE_ADDR,
            Energy::from(10000),
            UpdateContractPayload {
                amount: Amount::zero(),
                receive_name: OwnedReceiveName::new_unchecked("gona_token.transfer".to_string()),
                address: cis2_token_contract_address,
                message: OwnedParameter::from_serial(&payload).expect("Mint cis2 tokens params"),
            },
        )
        .expect("Should be able to deposit cis2 tokens");
}

fn get_stake_query(
    chain: &mut Chain,
    gona_stake: ContractAddress,
    alice_public_key: PublicKeyEd25519,
) -> StakeQuery {
    let staker = alice_public_key;
    let invoke = chain
        .contract_invoke(
            ALICE,
            ALICE_ADDR,
            Energy::from(10000),
            UpdateContractPayload {
                amount: Amount::zero(),
                receive_name: OwnedReceiveName::new_unchecked(
                    "gona_stake.get_stake_info".to_string(),
                ),
                address: gona_stake,
                message: OwnedParameter::from_serial(&staker).expect("Damn, wth happened"),
            },
        )
        .expect("Invoke Stake Query");
    let sq: StakeQuery = invoke
        .parse_return_value()
        .expect("Damn, the hell happened");
    sq
}

fn view_reward_amount(chain: &mut Chain, gona_stake: ContractAddress) -> u64 {
    let invoke = chain
        .contract_invoke(
            ALICE,
            ALICE_ADDR,
            Energy::from(10000),
            UpdateContractPayload {
                amount: Amount::zero(),
                receive_name: OwnedReceiveName::new_unchecked(
                    "gona_stake.view_reward_volume".to_string(),
                ),
                address: gona_stake,
                message: OwnedParameter::empty(),
            },
        )
        .expect("Invoke Stake Query");
    let res: u64 = invoke
        .parse_return_value()
        .expect("Damn, the hell happened");
    res
}

fn calculate_reward(
    chain: &mut Chain,
    gona_stake: ContractAddress,
    alice_public_key: PublicKeyEd25519,
) -> RewardResult {
    let staker = alice_public_key;
    let invoke = chain
        .contract_invoke(
            ALICE,
            ALICE_ADDR,
            Energy::from(10000),
            UpdateContractPayload {
                amount: Amount::zero(),
                receive_name: OwnedReceiveName::new_unchecked(
                    "gona_stake.calculate_rewards".to_string(),
                ),
                address: gona_stake,
                message: OwnedParameter::from_serial(&staker)
                    .expect("Staker could not be serialized"),
            },
        )
        .expect("Invoke Stake Query");
    let res: RewardResult = invoke
        .parse_return_value()
        .expect("Damn, the hell happened");
    res
}

fn calculate_percent(amount: u64, weight: u32, decimals: u8) -> u64 {
    (amount * (weight as u64)) / (100 * (10_i32.pow(decimals as u32) as u64))
}


fn release_stake(
    chain: &mut Chain,
    gona_stake: ContractAddress,
    alice_public_key: PublicKeyEd25519,
    _signing_key: ed25519_dalek::SigningKey,
    amount: u64,
) {
    let staker = alice_public_key;

    let param = UnstakeParam {
        amount: TokenAmountU64(amount),
        staker: staker.clone(),
    };

    let _invoke = chain
        .contract_update(
            SIGNER,
            ALICE,
            ALICE_ADDR,
            Energy::from(10000),
            UpdateContractPayload {
                amount: Amount::zero(),
                receive_name: OwnedReceiveName::new_unchecked("gona_stake.unstake".to_string()),
                address: gona_stake,
                message: OwnedParameter::from_serial(&param).expect("Damn, wth happened"),
            },
        )
        .expect("Invoke Stake Query");
}
