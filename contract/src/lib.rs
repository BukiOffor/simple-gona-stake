use concordium_cis2::*;
use concordium_std::*;
use core::fmt::Debug;
pub mod types;
use types::*;
// ======== Type Definitions ========

#[derive(Serial, DeserialWithState)]
#[concordium(state_parameter = "S")]
pub struct State<S = StateApi> {
    pub stake_entries: StateMap<PublicKeyEd25519, StakeEntry, S>,
    pub decimals: u8,
    pub token_address: ContractAddress,
    pub weight: u32,
    pub paused: bool,
    pub admin: Address,
    pub smart_wallet: ContractAddress,
    pub reward_volume: u64,
}

impl State {
    fn empty(
        state_builder: &mut StateBuilder,
        token_address: ContractAddress,
        weight: u32,
        decimals: u8,
        admin: Address,
        smart_wallet: ContractAddress,
    ) -> Self {
        State {
            stake_entries: state_builder.new_map(),
            decimals,
            token_address,
            weight,
            paused: false,
            admin,
            smart_wallet,
            reward_volume: 0,
        }
    }

    fn set_paused(&mut self, paused: bool) {
        self.paused = paused;
    }

    fn change_weight(&mut self, weight: u32) {
        self.weight = weight;
    }
    fn deduct_volume(&mut self, amount: u64) {
        let volume = self.reward_volume.checked_sub(amount).unwrap_or_else(|| 0);
        self.reward_volume = volume;
    }
}

// ======== Contract Implementation ========

#[init(contract = "gona_stake", parameter = "InitParam")]
fn contract_init(ctx: &InitContext, state_builder: &mut StateBuilder) -> InitResult<State> {
    let param: InitParam = ctx.parameter_cursor().get()?;
    Ok(State::empty(
        state_builder,
        param.token_address,
        param.weight,
        param.decimals,
        param.admin,
        param.smart_wallet,
    ))
}

#[receive(
    contract = "gona_stake",
    name = "stake",
    error = "StakingError",
    parameter = "OnReceivingCis2DataParams<ContractTokenId,ContractTokenAmount,PublicKeyEd25519>",
    enable_logger,
    mutable
)]
fn stake(ctx: &ReceiveContext, host: &mut Host<State>, logger: &mut Logger) -> ReceiveResult<()> {
    let parameter: OnReceivingCis2DataParams<
        ContractTokenId,
        ContractTokenAmount,
        PublicKeyEd25519,
    > = ctx.parameter_cursor().get()?;

    let amount = parameter.amount;
    let token_id = parameter.token_id;
    let state = host.state_mut();
    let gona_token = state.token_address;

    let staker = parameter.data;

    // Ensures that only contracts can call this hook function.
    let sender_contract_address = match ctx.sender() {
        Address::Contract(sender_contract_address) => sender_contract_address,
        Address::Account(_) => bail!(StakingError::OnlyContractCanStake.into()),
    };
    // Cannot stake less than 0.001 of our token
    ensure!(
        amount.0.ge(&1000),
        StakingError::CannotStakeLessThanAllowAmount.into()
    );
    ensure_eq!(
        sender_contract_address,
        gona_token,
        StakingError::SenderContractAddressIsNotAllowedToStake.into()
    );
    let mut entry = StakeEntry {
        amount,
        time_of_stake: ctx.metadata().slot_time(),
        token_id,
    };
    if let Some(stake_entry) = state.stake_entries.remove_and_get(&staker) {
        let days_of_stake = ctx
            .metadata()
            .slot_time()
            .duration_since(stake_entry.time_of_stake)
            .ok_or(StakingError::DaysOfStakeCouldNotBeCalculated)?
            .days();
        let previous_amount = stake_entry.amount;
        let rewards = calculate_percent(previous_amount.0, state.weight, state.decimals);
        if days_of_stake > 0 {
            let rewards = rewards * days_of_stake;
            let new_amount = previous_amount + TokenAmountU64(rewards);
            entry.amount = new_amount;
        } else {
            entry.amount += previous_amount;
        }
        stake_entry.delete();
        state.stake_entries.entry(staker).or_insert(entry);
    } else {
        state.stake_entries.entry(staker).or_insert(entry);
    }
    logger.log(&StakingEvent::Staked {
        staker,
        amount,
        time: ctx.metadata().slot_time(),
    })?;

    Ok(())
}

#[receive(
    contract = "gona_stake",
    name = "depositCis2Tokens",
    parameter = "OnReceivingCis2Params<ContractTokenId,ContractTokenAmount>",
    error = "StakingError",
    enable_logger,
    mutable
)]
fn deposit_cis2_tokens(
    ctx: &ReceiveContext,
    host: &mut Host<State>,
    logger: &mut Logger,
) -> ReceiveResult<()> {
    let param: OnReceivingCis2Params<ContractTokenId, ContractTokenAmount> =
        ctx.parameter_cursor().get()?;

    // Ensures that only contracts can call this hook function.
    match ctx.sender() {
        Address::Contract(sender_contract_address) => sender_contract_address,
        Address::Account(_) => bail!(StakingError::OnlyContractCanStake.into()),
    };

    host.state_mut().reward_volume += param.amount.0;

    logger.log(&StakingEvent::TokenDeposit {
        sender: param.from,
        amount: param.amount,
    })?;

    Ok(())
}

/// Function to get stake information by ID
#[receive(
    contract = "gona_stake",
    name = "get_stake_info",
    parameter = "PublicKeyEd25519",
    return_value = "Option<StakeEntry>"
)]
fn get_stake_info(ctx: &ReceiveContext, host: &Host<State>) -> ReceiveResult<StakeQuery> {
    let param: PublicKeyEd25519 = ctx.parameter_cursor().get()?;
    let stake_entry_ref = host.state().stake_entries.get(&param);
    // Convert the StateRef to Option<StakeEntry>
    let stake_entry_option = stake_entry_ref.map(|entry_ref| entry_ref.to_owned());
    Ok(stake_entry_option)
}

#[receive(contract = "gona_stake", name = "set_paused", mutable)]
fn set_paused(ctx: &ReceiveContext, host: &mut Host<State>) -> ReceiveResult<()> {
    ensure_eq!(
        ctx.sender(),
        host.state.admin,
        StakingError::SenderIsNotAdmin.into()
    );
    host.state_mut().set_paused(true);
    Ok(())
}

#[receive(
    contract = "gona_stake",
    name = "change_weight",
    parameter = "u32",
    mutable
)]
fn change_weight(ctx: &ReceiveContext, host: &mut Host<State>) -> ReceiveResult<()> {
    let weight: u32 = ctx.parameter_cursor().get()?;
    ensure_eq!(
        ctx.sender(),
        host.state.admin,
        StakingError::SenderIsNotAdmin.into()
    );
    host.state_mut().change_weight(weight);

    Ok(())
}

#[receive(
    contract = "gona_stake",
    name = "view_reward_volume",
    return_value = "u64"
)]
fn view_reward(_ctx: &ReceiveContext, host: &Host<State>) -> ReceiveResult<u64> {
    Ok(host.state().reward_volume)
}

#[receive(
    contract = "gona_stake",
    name = "calculate_rewards",
    parameter = "PublicKeyEd25519",
    error = "StakingError"
)]
fn calculate_rewards(ctx: &ReceiveContext, host: &Host<State>) -> ReceiveResult<RewardResult> {
    let staker: PublicKeyEd25519 = ctx.parameter_cursor().get()?;
    if let Some(stake_entry) = host.state.stake_entries.get(&staker) {
        let days = ctx
            .metadata()
            .slot_time()
            .duration_since(stake_entry.time_of_stake)
            .ok_or(StakingError::DaysOfStakeCouldNotBeCalculated)?
            .days();
        let previous_amount = stake_entry.amount;
        let rewards = calculate_percent(previous_amount.0, host.state.weight, host.state.decimals);
        let rewards = rewards * days;
        Ok(RewardResult {
            days,
            rewards,
            amount_staked: stake_entry.amount.0,
        })
    } else {
        bail!(StakingError::StakingNotFound.into())
    }
}

// Helper Functions

/// calculate the reward of the stake for the current season.
/// the calculate is done using the decimals of the token.
/// this fn assumes that the amount and weight is `n * 10.pow(decimals)`
fn calculate_percent(amount: u64, weight: u32, decimals: u8) -> u64 {
    (amount * (weight as u64)) / (100 * (10_i32.pow(decimals as u32) as u64))
}

#[receive(
    contract = "gona_stake",
    name = "unstake",
    error = "StakingError",
    parameter = "UnstakeParam",
    enable_logger,
    mutable
)]
fn unstake(ctx: &ReceiveContext, host: &mut Host<State>, logger: &mut Logger) -> ReceiveResult<()> {
    let param: UnstakeParam = ctx.parameter_cursor().get()?;
    let state = host.state_mut();

    let weight = state.weight;
    let decimals = state.decimals;
    let reward_volume = state.reward_volume;

    let stake_entry = state
        .stake_entries
        .get(&param.staker)
        .ok_or(StakingError::StakingNotFound)?;

    let previous_amount = stake_entry.amount;
    ensure!(
        previous_amount.0.ge(&param.amount.0),
        StakingError::InsufficientFunds.into()
    );
    let days_of_stake = ctx
        .metadata()
        .slot_time()
        .duration_since(stake_entry.time_of_stake)
        .ok_or(StakingError::DaysOfStakeCouldNotBeCalculated)?
        .days();

    let mut amount = param.amount;
    let token_address = state.token_address;
    let smart_wallet = state.smart_wallet;

    // if days == 0 and you calculate reward. it will change balance to 0
    if days_of_stake > 0 {
        let rewards = calculate_percent(amount.0, weight, decimals);
        let cumulative_rewards = rewards * days_of_stake;
        ensure!(reward_volume >= rewards, StakingError::Overflow.into());
        state.reward_volume -= cumulative_rewards;
        amount += TokenAmountU64(cumulative_rewards);
        //bail!(StakingError::TransferError.into());
    }

    let owned_entry = OwnedEntrypointName::new_unchecked("depositCis2Tokens".into());
    // Create a Transfer instance
    let transfer_payload = Transfer {
        token_id: TOKEN_ID,
        amount,
        to: Receiver::Contract(smart_wallet, owned_entry),
        from: Address::Contract(ctx.self_address()),
        data: AdditionalData::from(to_bytes(&param.staker)),
    };
    let entry_point = EntrypointName::new_unchecked("transfer".into());

    let mut transfers = Vec::new();
    transfers.push(transfer_payload);
    let payload = TransferParams::from(transfers);
    // calculate transfer after withdrawal; if amount is less than 0.001 flush the account
    let balance = previous_amount.0 - param.amount.0;

    if balance < 1000 {
        state.stake_entries.remove(&param.staker);
    } else {
        state
            .stake_entries
            .entry(param.staker.clone())
            .and_modify(|stake| {
                stake.amount = TokenAmountU64(balance);
            });
    }

    host.invoke_contract(&token_address, &payload, entry_point, Amount::zero())?;

    logger.log(&StakingEvent::Unstaking {
        amount: param.amount,
        staker: param.staker,
        time: ctx.metadata().slot_time(),
    })?;
    Ok(())
}
