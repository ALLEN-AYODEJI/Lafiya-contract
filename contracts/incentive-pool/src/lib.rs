#![no_std]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(missing_docs)] // soroban macros generate undocumented public items

//! # Incentive Pool
//!
//! Bounded USDC payout/escrow contract for the M2 milestone.
//! Donors fund the pool, an approver authorizes work items, and
//! approved allowlisted attesters claim per-item payouts with
//! per-attestation replay protection.

use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype, token,
    Address, BytesN, Env, Symbol, Vec,
};

/// The subset of the `attester-registry` contract this crate calls.
/// Kept as a trait interface (rather than a direct crate dependency)
/// so that `attester-registry`'s own contract implementation never
/// links into this crate's wasm — only the typed cross-contract
/// call it generates does.
#[contractclient(name = "AttesterRegistryClient")]
pub trait AttesterRegistryInterface {
    fn is_attester(env: Env, attester: Address) -> bool;
}

const SCHEMA_VERSION: u32 = 1;

/// Instance storage TTL policy:
/// - Threshold: 30 days (17280 * 30 = 518400 ledgers)
/// - Extend to: 90 days (17280 * 90 = 1555200 ledgers)
const INSTANCE_BUMP_AMOUNT: u32 = 1_555_200;
const INSTANCE_LIFETIME_THRESHOLD: u32 = 518_400;

/// Persistent storage TTL policy for work items, claimed flags, attester
/// totals, programme balances and approver windows (same 30/90-day policy
/// as instance storage, mirroring `attester-registry`). See
/// `docs/storage-cost.md#incentive-pool` for the archival safety argument.
const PERSISTENT_BUMP_AMOUNT: u32 = 1_555_200;
const PERSISTENT_LIFETIME_THRESHOLD: u32 = 518_400;

/// Default quorum proposal lifetime: 7 days.
const DEFAULT_PROPOSAL_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Default per-approver rate limit: 100 approvals per 24h, value bounded
/// only by `MaxPerClaim` × count.
const DEFAULT_RATE_WINDOW_SECONDS: u64 = 24 * 60 * 60;
const DEFAULT_RATE_MAX_COUNT: u32 = 100;

/// Storage keys for the incentive pool.
///
/// UPGRADE SAFETY: `#[contracttype]` enums serialize variants by their
/// position index, so variant order and existing variants must never change
/// — append new variants at the end only. Reordering breaks decoding of
/// data written by earlier versions.
#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// The address authorized to manage pool funds, set configuration,
    /// and upgrade the contract.
    Admin,
    /// Pending admin address for two-step admin transfer.
    PendingAdmin,
    /// The address authorized to approve work items for payout.
    Approver,
    /// Whether state-changing operations are currently paused.
    Paused,
    /// The storage schema version of the contract.
    SchemaVersion,
    /// The USDC (or other soroban-token) contract address held by this pool.
    Token,
    /// The deployed `attester-registry` contract consulted on every `claim`.
    AttesterRegistry,
    /// Cumulative amount deposited into the pool (i128).
    TotalDeposited,
    /// Cumulative amount paid out from the pool (i128).
    TotalPaid,
    /// Per-claim payout cap. Default: i128::MAX (uncapped).
    MaxPerClaim,
    /// Per-attester cumulative claim cap. Default: i128::MAX (uncapped).
    MaxPerAttester,
    /// Work-item info: stores the approved attester, payout amount,
    /// and approval timestamp. Absent key means the item is not approved.
    WorkItem(BytesN<32>),
    /// Whether a work item has been claimed. Absent means not yet claimed.
    WorkItemClaimed(BytesN<32>),
    /// Cumulative amount paid to a given attester across all claims.
    AttesterTotalClaimed(Address),
    /// Quorum approver set (`Vec<Address>`). Absent ⇒ single-approver mode.
    Approvers,
    /// Quorum threshold (u32). `0` or absent ⇒ single-approver mode.
    ApprovalThreshold,
    /// Lifetime of quorum proposals in seconds (u64).
    ProposalTtl,
    /// Pending quorum proposal for a work item.
    Proposal(BytesN<32>),
    /// Per-approver rate-limit configuration (`RateLimit`).
    RateLimit,
    /// Per-approver fixed-window usage counter (`ApproverWindow`).
    ApproverWindow(Address),
    /// Programme a work item draws from. Absent ⇒ unallocated funds.
    WorkItemProgramme(BytesN<32>),
    /// Remaining (unspent) balance of an earmarked programme (i128).
    ProgrammeBalance(Symbol),
    /// Sum of all `ProgrammeBalance` entries (i128).
    TotalProgrammeBalance,
    /// Cumulative amount ever contributed by a donor, all programmes (i128).
    DonorContributed(Address),
    /// Donor's net (contributed minus refunded) amount in a programme (i128).
    DonorProgramme(Address, Symbol),
}

/// On-chain record of an approved work item.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkItem {
    /// The attester authorized to claim payout for this item.
    pub attester: Address,
    /// The payout amount for this item.
    pub payout_amount: i128,
    /// Ledger timestamp when the item was approved.
    pub approved_at: u64,
}

/// Pending M-of-N approval of a work item.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    pub attester: Address,
    pub payout_amount: i128,
    pub programme: Option<Symbol>,
    pub endorsements: Vec<Address>,
    pub expires_at: u64,
}

/// Per-approver rate limit applied to every approval or endorsement.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimit {
    pub window_seconds: u64,
    pub max_count: u32,
    pub max_value: i128,
}

/// One compact counter per approver; reset when the window rolls over,
/// so storage never grows beyond one entry per approver.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApproverWindow {
    pub window_start: u64,
    pub count: u32,
    pub value: i128,
}

/// Funding totals exposed for reconciliation. Invariant:
/// `custody == programmes_total + unallocated`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FundingTotals {
    pub deposited: i128,
    pub paid: i128,
    pub custody: i128,
    pub programmes_total: i128,
    pub unallocated: i128,
}

// ──────────────────────────── Events ────────────────────────────

#[contractevent]
#[derive(Clone, Debug)]
pub struct AdminTransferred {
    #[topic]
    pub previous_admin: Address,
    #[topic]
    pub new_admin: Address,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct Initialized {
    #[topic]
    pub admin: Address,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct PoolFunded {
    #[topic]
    pub funder: Address,
    pub amount: i128,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct PoolWithdrawn {
    #[topic]
    pub to: Address,
    pub amount: i128,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct WorkItemApproved {
    #[topic]
    pub work_item_id: BytesN<32>,
    pub attester: Address,
    pub payout_amount: i128,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct PayoutClaimed {
    #[topic]
    pub work_item_id: BytesN<32>,
    #[topic]
    pub attester: Address,
    pub amount: i128,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct AttesterRegistryRepointed {
    #[topic]
    pub previous: Address,
    #[topic]
    pub new: Address,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct ApproverSetChanged {
    #[topic]
    pub by: Address,
    pub approvers: Vec<Address>,
    pub threshold: u32,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct WorkItemProposed {
    #[topic]
    pub work_item_id: BytesN<32>,
    #[topic]
    pub proposer: Address,
    pub attester: Address,
    pub payout_amount: i128,
    pub expires_at: u64,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct WorkItemEndorsed {
    #[topic]
    pub work_item_id: BytesN<32>,
    #[topic]
    pub endorser: Address,
    pub endorsements: u32,
    pub threshold: u32,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct RateLimitSet {
    #[topic]
    pub by: Address,
    pub window_seconds: u64,
    pub max_count: u32,
    pub max_value: i128,
}

/// Published on the approval that fills an approver's window; later
/// attempts in the same window fail with `ApproverRateLimited`.
#[contractevent]
#[derive(Clone, Debug)]
pub struct ApproverRateLimitHit {
    #[topic]
    pub approver: Address,
    pub count: u32,
    pub value: i128,
    pub window_resets_at: u64,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct ProgrammeFunded {
    #[topic]
    pub donor: Address,
    #[topic]
    pub programme: Symbol,
    pub amount: i128,
}

/// Links an approved work item to the programme it draws from, so
/// indexers can attribute `payout_claimed` amounts to programmes.
#[contractevent]
#[derive(Clone, Debug)]
pub struct WorkItemProgrammeLinked {
    #[topic]
    pub work_item_id: BytesN<32>,
    #[topic]
    pub programme: Symbol,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct ProgrammeRefunded {
    #[topic]
    pub donor: Address,
    #[topic]
    pub programme: Symbol,
    pub amount: i128,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct Paused {
    #[topic]
    pub by: Address,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct Unpaused {
    #[topic]
    pub by: Address,
}

// ──────────────────────────── Errors ────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// The contract has not been initialized yet.
    NotInitialized = 1,
    /// The contract is already initialized; double-initialization is rejected.
    AlreadyInitialized = 2,
    /// No admin transfer is pending.
    NoPendingTransfer = 3,
    /// The contract is paused; state-changing calls are rejected until
    /// an admin calls `unpause`.
    ContractPaused = 4,
    /// The configured attester-registry address is invalid or unreachable.
    InvalidRegistryWiring = 5,
    /// The configured token address is invalid or unreachable.
    InvalidToken = 6,
    /// The pool does not hold enough tokens to cover the requested payout.
    InsufficientPoolBalance = 7,
    /// This work item has already been approved.
    WorkItemAlreadyApproved = 8,
    /// This work item has not been approved by the approver.
    WorkItemNotApproved = 9,
    /// This work item has already been claimed (replay protection).
    WorkItemAlreadyClaimed = 10,
    /// The claiming attester is not currently allowlisted.
    AttesterNotAllowlisted = 11,
    /// The payout would exceed the per-attester cumulative claim cap.
    AttesterClaimCapExceeded = 12,
    /// The payout would exceed the per-claim cap.
    PayoutCapExceeded = 13,
    /// The token transfer call returned an error.
    TransferFailed = 14,
    /// A non-positive amount was provided where a positive amount is required.
    NonPositiveAmount = 15,
    /// Quorum mode is active; use `propose_work_item` instead.
    QuorumRequired = 16,
    /// Quorum mode is not configured.
    QuorumNotConfigured = 17,
    /// The caller is not in the current approver set.
    NotAnApprover = 18,
    /// The approver already endorsed this proposal.
    DuplicateEndorsement = 19,
    /// No pending proposal exists for this work item.
    ProposalNotFound = 20,
    /// The proposal expired before reaching quorum.
    ProposalExpired = 21,
    /// Not enough current approvers have endorsed the proposal.
    QuorumNotReached = 22,
    /// Invalid approver set or threshold.
    InvalidQuorumConfig = 23,
    /// The approver exhausted its rate-limit window.
    ApproverRateLimited = 24,
    /// The programme does not hold enough unspent funds.
    InsufficientProgrammeBalance = 25,
    /// Refund exceeds the donor's net contribution to the programme.
    DonorRefundExceeded = 26,
    /// A proposal for this work item is already pending.
    ProposalAlreadyExists = 27,
}

// ──────────────────────────── Contract ────────────────────────────

#[contract]
pub struct IncentivePool;

#[contractimpl]
impl IncentivePool {
    /// Initialize the pool. Sets the admin, approver, token contract,
    /// attester-registry contract, and default caps. Can only be called once.
    ///
    /// The caller must authorize as `admin`. A best-effort interface check
    /// is performed against both `attester_registry` and `token`.
    pub fn initialize(
        env: Env,
        admin: Address,
        approver: Address,
        token: Address,
        attester_registry: Address,
        max_per_claim: i128,
        max_per_attester: i128,
    ) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();

        // Best-effort sanity check: verify attester_registry implements
        // the is_attester interface.
        let registry = AttesterRegistryClient::new(&env, &attester_registry);
        let throwaway = env.current_contract_address();
        if registry.try_is_attester(&throwaway).is_err() {
            return Err(Error::InvalidRegistryWiring);
        }

        // Best-effort sanity check: verify token implements the token interface
        // by calling balance with the current contract address.
        let token_client = token::Client::new(&env, &token);
        let self_addr = env.current_contract_address();
        if token_client.try_balance(&self_addr).is_err() {
            return Err(Error::InvalidToken);
        }

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Approver, &approver);
        env.storage().instance().set(&DataKey::Token, &token);
        env.storage()
            .instance()
            .set(&DataKey::AttesterRegistry, &attester_registry);
        env.storage()
            .instance()
            .set(&DataKey::MaxPerClaim, &max_per_claim);
        env.storage()
            .instance()
            .set(&DataKey::MaxPerAttester, &max_per_attester);
        env.storage()
            .instance()
            .set(&DataKey::TotalDeposited, &0_i128);
        env.storage().instance().set(&DataKey::TotalPaid, &0_i128);
        env.storage()
            .instance()
            .set(&DataKey::SchemaVersion, &SCHEMA_VERSION);

        Initialized { admin }.publish(&env);
        Ok(())
    }

    // ── Configuration getters ──

    /// Return the current admin address.
    pub fn get_admin(env: Env) -> Result<Address, Error> {
        Self::admin(&env)
    }

    /// Return the current approver address.
    pub fn get_approver(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Approver)
            .ok_or(Error::NotInitialized)
    }

    /// Return the configured token contract address.
    pub fn get_token(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(Error::NotInitialized)
    }

    /// Return the configured attester-registry contract address.
    pub fn get_attester_registry(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::AttesterRegistry)
            .ok_or(Error::NotInitialized)
    }

    /// Return the per-claim payout cap.
    pub fn get_max_per_claim(env: Env) -> Result<i128, Error> {
        Ok(env
            .storage()
            .instance()
            .get(&DataKey::MaxPerClaim)
            .unwrap_or(i128::MAX))
    }

    /// Return the per-attester cumulative claim cap.
    pub fn get_max_per_attester(env: Env) -> Result<i128, Error> {
        Ok(env
            .storage()
            .instance()
            .get(&DataKey::MaxPerAttester)
            .unwrap_or(i128::MAX))
    }

    /// Return the cumulative amount deposited into the pool.
    pub fn get_total_deposited(env: Env) -> Result<i128, Error> {
        Ok(env
            .storage()
            .instance()
            .get(&DataKey::TotalDeposited)
            .unwrap_or(0))
    }

    /// Return the cumulative amount paid out from the pool.
    pub fn get_total_paid(env: Env) -> Result<i128, Error> {
        Ok(env
            .storage()
            .instance()
            .get(&DataKey::TotalPaid)
            .unwrap_or(0))
    }

    /// Whether a work item has been approved.
    pub fn is_work_item_approved(env: Env, work_item_id: BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::WorkItem(work_item_id))
    }

    /// Whether a work item has been claimed.
    pub fn is_work_item_claimed(env: Env, work_item_id: BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::WorkItemClaimed(work_item_id))
            .unwrap_or(false)
    }

    /// Return the work item details, if approved.
    pub fn get_work_item(env: Env, work_item_id: BytesN<32>) -> Option<WorkItem> {
        env.storage()
            .persistent()
            .get(&DataKey::WorkItem(work_item_id))
    }

    /// Return the cumulative amount claimed by an attester.
    pub fn get_attester_total_claimed(env: Env, attester: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::AttesterTotalClaimed(attester))
            .unwrap_or(0)
    }

    // ── Admin: two-step transfer ──

    /// Propose a new admin address. Requires admin auth.
    pub fn propose_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        let current_admin = Self::admin(&env)?;
        current_admin.require_auth();
        env.storage()
            .instance()
            .set(&DataKey::PendingAdmin, &new_admin);
        Ok(())
    }

    /// Accept the proposed admin transfer. Requires pending-admin auth.
    pub fn accept_admin(env: Env) -> Result<(), Error> {
        let previous_admin = Self::admin(&env)?;
        let pending_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::PendingAdmin)
            .ok_or(Error::NoPendingTransfer)?;

        pending_admin.require_auth();

        env.storage()
            .instance()
            .set(&DataKey::Admin, &pending_admin);
        env.storage().instance().remove(&DataKey::PendingAdmin);

        AdminTransferred {
            previous_admin,
            new_admin: pending_admin,
        }
        .publish(&env);

        Ok(())
    }

    // ── Admin: approver management ──

    /// Set the approver address authorized to approve work items.
    /// Requires admin auth.
    pub fn set_approver(env: Env, new_approver: Address) -> Result<(), Error> {
        Self::admin(&env)?.require_auth();
        env.storage()
            .instance()
            .set(&DataKey::Approver, &new_approver);
        Ok(())
    }

    // ── Admin: registry repointing ──

    /// Change the attester-registry contract. Requires admin auth.
    pub fn set_attester_registry(env: Env, new_registry: Address) -> Result<(), Error> {
        let admin = Self::admin(&env)?;
        admin.require_auth();

        let previous = Self::attester_registry(&env)?;

        env.storage()
            .instance()
            .set(&DataKey::AttesterRegistry, &new_registry);

        AttesterRegistryRepointed {
            previous,
            new: new_registry,
        }
        .publish(&env);

        Ok(())
    }

    // ── Admin: cap configuration ──

    /// Set the per-claim payout cap. Requires admin auth.
    pub fn set_max_per_claim(env: Env, max: i128) -> Result<(), Error> {
        Self::admin(&env)?.require_auth();
        env.storage().instance().set(&DataKey::MaxPerClaim, &max);
        Ok(())
    }

    /// Set the per-attester cumulative claim cap. Requires admin auth.
    pub fn set_max_per_attester(env: Env, max: i128) -> Result<(), Error> {
        Self::admin(&env)?.require_auth();
        env.storage().instance().set(&DataKey::MaxPerAttester, &max);
        Ok(())
    }

    // ── Admin: fund / withdraw ──

    /// Deposit `amount` tokens from the caller into the pool.
    /// Requires admin auth. The admin must have previously approved
    /// the pool contract to spend their tokens, or the transaction
    /// must include the inner `token.transfer` in the authorization tree.
    pub fn fund(env: Env, amount: i128) -> Result<(), Error> {
        let admin = Self::admin(&env)?;
        admin.require_auth();
        Self::require_not_paused(&env)?;

        if amount <= 0 {
            return Err(Error::NonPositiveAmount);
        }

        let token_addr = Self::token(&env)?;
        let pool_addr = env.current_contract_address();
        let token_client = token::Client::new(&env, &token_addr);

        token_client.transfer(&admin, &pool_addr, &amount);

        let deposited: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalDeposited)
            .unwrap_or(0);
        env.storage()
            .instance()
            .set(&DataKey::TotalDeposited, &(deposited + amount));

        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);

        PoolFunded {
            funder: admin,
            amount,
        }
        .publish(&env);

        Ok(())
    }

    /// Withdraw `amount` tokens from the pool to `to`. Requires admin auth.
    /// This is the recovery mechanism for excess or misallocated funds.
    pub fn withdraw(env: Env, to: Address, amount: i128) -> Result<(), Error> {
        Self::admin(&env)?.require_auth();
        Self::require_not_paused(&env)?;

        if amount <= 0 {
            return Err(Error::NonPositiveAmount);
        }

        let total_paid: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalPaid)
            .unwrap_or(0);
        let total_deposited: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalDeposited)
            .unwrap_or(0);
        // Earmarked programme funds are donor-restricted; only the
        // unallocated remainder can be withdrawn (see `refund_programme`).
        let available = total_deposited
            - total_paid
            - Self::get_instance_i128(&env, &DataKey::TotalProgrammeBalance);
        if amount > available {
            return Err(Error::InsufficientPoolBalance);
        }

        let token_addr = Self::token(&env)?;
        let pool_addr = env.current_contract_address();
        let token_client = token::Client::new(&env, &token_addr);

        token_client.transfer(&pool_addr, &to, &amount);

        // Withdrawn funds leave the pool, so count them against the
        // deposited balance; otherwise `claim` would believe they are still
        // available and fail at the token transfer.
        env.storage()
            .instance()
            .set(&DataKey::TotalPaid, &(total_paid + amount));

        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);

        PoolWithdrawn { to, amount }.publish(&env);

        Ok(())
    }

    // ── Approver: approve work items ──

    /// Approve a work item for payout from unallocated funds (single-
    /// approver mode). Requires the approver's auth. The `payout_amount`
    /// must be positive and must not exceed the per-claim cap. The
    /// attester must be allowlisted.
    pub fn approve_work_item(
        env: Env,
        work_item_id: BytesN<32>,
        attester: Address,
        payout_amount: i128,
    ) -> Result<(), Error> {
        Self::approve_single(env, work_item_id, attester, payout_amount, None)
    }

    /// Like `approve_work_item`, but the payout draws from `programme`'s
    /// earmarked balance.
    pub fn approve_work_item_from(
        env: Env,
        work_item_id: BytesN<32>,
        attester: Address,
        payout_amount: i128,
        programme: Symbol,
    ) -> Result<(), Error> {
        Self::approve_single(env, work_item_id, attester, payout_amount, Some(programme))
    }

    // ── Quorum (M-of-N) approvals ──

    /// Configure the quorum approver set. `threshold == 0` with an empty
    /// set returns the pool to single-approver mode. Requires admin auth.
    /// Pending proposals are re-evaluated against the new set and
    /// threshold at execution time.
    pub fn set_approver_set(
        env: Env,
        approvers: Vec<Address>,
        threshold: u32,
    ) -> Result<(), Error> {
        let admin = Self::admin(&env)?;
        admin.require_auth();
        if threshold == 0 {
            if !approvers.is_empty() {
                return Err(Error::InvalidQuorumConfig);
            }
            env.storage().instance().remove(&DataKey::Approvers);
            env.storage().instance().remove(&DataKey::ApprovalThreshold);
        } else {
            if threshold > approvers.len() {
                return Err(Error::InvalidQuorumConfig);
            }
            for (i, a) in approvers.iter().enumerate() {
                if approvers.first_index_of(&a) != Some(i as u32) {
                    return Err(Error::InvalidQuorumConfig);
                }
            }
            env.storage()
                .instance()
                .set(&DataKey::Approvers, &approvers);
            env.storage()
                .instance()
                .set(&DataKey::ApprovalThreshold, &threshold);
        }
        ApproverSetChanged {
            by: admin,
            approvers,
            threshold,
        }
        .publish(&env);
        Ok(())
    }

    /// Set the lifetime of new quorum proposals. Requires admin auth.
    pub fn set_proposal_ttl(env: Env, seconds: u64) -> Result<(), Error> {
        Self::admin(&env)?.require_auth();
        if seconds == 0 {
            return Err(Error::InvalidQuorumConfig);
        }
        env.storage()
            .instance()
            .set(&DataKey::ProposalTtl, &seconds);
        Ok(())
    }

    /// Return `(approvers, threshold)`; threshold 0 means single-approver mode.
    pub fn get_approver_set(env: Env) -> (Vec<Address>, u32) {
        (
            env.storage()
                .instance()
                .get(&DataKey::Approvers)
                .unwrap_or(Vec::new(&env)),
            Self::threshold(&env),
        )
    }

    /// Return a pending proposal, if any.
    pub fn get_proposal(env: Env, work_item_id: BytesN<32>) -> Option<Proposal> {
        env.storage()
            .persistent()
            .get(&DataKey::Proposal(work_item_id))
    }

    /// Propose a work item for M-of-N approval. The proposer must be in
    /// the approver set and counts as the first endorsement.
    pub fn propose_work_item(
        env: Env,
        proposer: Address,
        work_item_id: BytesN<32>,
        attester: Address,
        payout_amount: i128,
        programme: Option<Symbol>,
    ) -> Result<(), Error> {
        proposer.require_auth();
        Self::require_not_paused(&env)?;
        Self::require_approver_member(&env, &proposer)?;
        Self::validate_approval(&env, &work_item_id, &attester, payout_amount, &programme)?;
        let key = DataKey::Proposal(work_item_id.clone());
        if let Some(p) = env.storage().persistent().get::<_, Proposal>(&key) {
            if env.ledger().timestamp() < p.expires_at {
                return Err(Error::ProposalAlreadyExists);
            }
        }
        Self::charge_rate_limit(&env, &proposer, payout_amount)?;
        let ttl: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ProposalTtl)
            .unwrap_or(DEFAULT_PROPOSAL_TTL_SECONDS);
        let expires_at = env.ledger().timestamp().saturating_add(ttl);
        let mut endorsements = Vec::new(&env);
        endorsements.push_back(proposer.clone());
        let proposal = Proposal {
            attester: attester.clone(),
            payout_amount,
            programme,
            endorsements,
            expires_at,
        };
        env.storage().persistent().set(&key, &proposal);
        Self::bump_persistent(&env, &key);
        Self::bump_instance(&env);
        WorkItemProposed {
            work_item_id: work_item_id.clone(),
            proposer: proposer.clone(),
            attester,
            payout_amount,
            expires_at,
        }
        .publish(&env);
        WorkItemEndorsed {
            work_item_id,
            endorser: proposer,
            endorsements: 1,
            threshold: Self::threshold(&env),
        }
        .publish(&env);
        Ok(())
    }

    /// Endorse a pending proposal. Rejects duplicates and expired proposals.
    pub fn endorse_work_item(
        env: Env,
        endorser: Address,
        work_item_id: BytesN<32>,
    ) -> Result<(), Error> {
        endorser.require_auth();
        Self::require_not_paused(&env)?;
        Self::require_approver_member(&env, &endorser)?;
        let key = DataKey::Proposal(work_item_id.clone());
        let mut p: Proposal = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::ProposalNotFound)?;
        if env.ledger().timestamp() >= p.expires_at {
            return Err(Error::ProposalExpired);
        }
        if p.endorsements.contains(&endorser) {
            return Err(Error::DuplicateEndorsement);
        }
        Self::charge_rate_limit(&env, &endorser, p.payout_amount)?;
        p.endorsements.push_back(endorser.clone());
        env.storage().persistent().set(&key, &p);
        Self::bump_persistent(&env, &key);
        WorkItemEndorsed {
            work_item_id,
            endorser,
            endorsements: Self::valid_endorsements(&env, &p),
            threshold: Self::threshold(&env),
        }
        .publish(&env);
        Ok(())
    }

    /// Execute a proposal once endorsements by *current* approvers meet the
    /// *current* threshold. Permissionless: authority comes from the
    /// recorded endorsements.
    pub fn execute_work_item(env: Env, work_item_id: BytesN<32>) -> Result<(), Error> {
        Self::require_not_paused(&env)?;
        let threshold = Self::threshold(&env);
        if threshold == 0 {
            return Err(Error::QuorumNotConfigured);
        }
        let key = DataKey::Proposal(work_item_id.clone());
        let p: Proposal = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::ProposalNotFound)?;
        if env.ledger().timestamp() >= p.expires_at {
            return Err(Error::ProposalExpired);
        }
        if Self::valid_endorsements(&env, &p) < threshold {
            return Err(Error::QuorumNotReached);
        }
        Self::validate_approval(
            &env,
            &work_item_id,
            &p.attester,
            p.payout_amount,
            &p.programme,
        )?;
        env.storage().persistent().remove(&key);
        Self::store_approval(&env, work_item_id, p.attester, p.payout_amount, p.programme);
        Ok(())
    }

    // ── Per-approver rate limits ──

    /// Configure the per-approver rate limit. Requires admin auth.
    pub fn set_rate_limit(
        env: Env,
        window_seconds: u64,
        max_count: u32,
        max_value: i128,
    ) -> Result<(), Error> {
        let admin = Self::admin(&env)?;
        admin.require_auth();
        if window_seconds == 0 || max_count == 0 || max_value <= 0 {
            return Err(Error::NonPositiveAmount);
        }
        env.storage().instance().set(
            &DataKey::RateLimit,
            &RateLimit {
                window_seconds,
                max_count,
                max_value,
            },
        );
        RateLimitSet {
            by: admin,
            window_seconds,
            max_count,
            max_value,
        }
        .publish(&env);
        Ok(())
    }

    /// Return the effective per-approver rate limit.
    pub fn get_rate_limit(env: Env) -> RateLimit {
        Self::rate_limit(&env)
    }

    /// Return an approver's usage in its current window (zeroed if rolled over).
    pub fn get_approver_usage(env: Env, approver: Address) -> ApproverWindow {
        Self::current_window(&env, &approver, &Self::rate_limit(&env))
    }

    // ── Programme-earmarked funding ──

    /// Donate `amount` earmarked for `programme`. Requires donor auth.
    pub fn fund_for(
        env: Env,
        donor: Address,
        programme: Symbol,
        amount: i128,
    ) -> Result<(), Error> {
        donor.require_auth();
        Self::require_not_paused(&env)?;
        if amount <= 0 {
            return Err(Error::NonPositiveAmount);
        }
        let token_client = token::Client::new(&env, &Self::token(&env)?);
        token_client.transfer(&donor, env.current_contract_address(), &amount);

        Self::add_instance_i128(&env, &DataKey::TotalDeposited, amount);
        Self::add_instance_i128(&env, &DataKey::TotalProgrammeBalance, amount);
        Self::add_persistent_i128(&env, &DataKey::ProgrammeBalance(programme.clone()), amount);
        Self::add_persistent_i128(&env, &DataKey::DonorContributed(donor.clone()), amount);
        Self::add_persistent_i128(
            &env,
            &DataKey::DonorProgramme(donor.clone(), programme.clone()),
            amount,
        );
        Self::bump_instance(&env);
        ProgrammeFunded {
            donor,
            programme,
            amount,
        }
        .publish(&env);
        Ok(())
    }

    /// Refund donor-restricted programme funds. Restricted funds never
    /// leave a programme except as a payout or as a refund to the donor
    /// who contributed them, bounded by both the donor's net contribution
    /// and the programme's unspent balance. Requires admin auth.
    pub fn refund_programme(
        env: Env,
        donor: Address,
        programme: Symbol,
        amount: i128,
    ) -> Result<(), Error> {
        Self::admin(&env)?.require_auth();
        Self::require_not_paused(&env)?;
        if amount <= 0 {
            return Err(Error::NonPositiveAmount);
        }
        let dp_key = DataKey::DonorProgramme(donor.clone(), programme.clone());
        if Self::get_persistent_i128(&env, &dp_key) < amount {
            return Err(Error::DonorRefundExceeded);
        }
        let pb_key = DataKey::ProgrammeBalance(programme.clone());
        if Self::get_persistent_i128(&env, &pb_key) < amount {
            return Err(Error::InsufficientProgrammeBalance);
        }
        let token_client = token::Client::new(&env, &Self::token(&env)?);
        token_client.transfer(&env.current_contract_address(), &donor, &amount);

        Self::add_persistent_i128(&env, &dp_key, -amount);
        Self::add_persistent_i128(&env, &pb_key, -amount);
        Self::add_instance_i128(&env, &DataKey::TotalProgrammeBalance, -amount);
        Self::add_instance_i128(&env, &DataKey::TotalPaid, amount);
        Self::bump_instance(&env);
        ProgrammeRefunded {
            donor,
            programme,
            amount,
        }
        .publish(&env);
        Ok(())
    }

    /// Unspent balance of a programme.
    pub fn get_programme_balance(env: Env, programme: Symbol) -> i128 {
        Self::get_persistent_i128(&env, &DataKey::ProgrammeBalance(programme))
    }

    /// Cumulative amount contributed by a donor across all programmes.
    pub fn get_donor_contributed(env: Env, donor: Address) -> i128 {
        Self::get_persistent_i128(&env, &DataKey::DonorContributed(donor))
    }

    /// Donor's net (contributed minus refunded) amount in a programme.
    pub fn get_donor_programme(env: Env, donor: Address, programme: Symbol) -> i128 {
        Self::get_persistent_i128(&env, &DataKey::DonorProgramme(donor, programme))
    }

    /// Programme a work item draws from (`None` ⇒ unallocated).
    pub fn get_work_item_programme(env: Env, work_item_id: BytesN<32>) -> Option<Symbol> {
        env.storage()
            .persistent()
            .get(&DataKey::WorkItemProgramme(work_item_id))
    }

    /// Funding totals for reconciliation.
    pub fn get_funding_totals(env: Env) -> FundingTotals {
        let deposited = Self::get_instance_i128(&env, &DataKey::TotalDeposited);
        let paid = Self::get_instance_i128(&env, &DataKey::TotalPaid);
        let programmes_total = Self::get_instance_i128(&env, &DataKey::TotalProgrammeBalance);
        let custody = deposited - paid;
        FundingTotals {
            deposited,
            paid,
            custody,
            programmes_total,
            unallocated: custody - programmes_total,
        }
    }

    /// Whether accounted custody splits into programmes plus a
    /// non-negative unallocated remainder and is backed by the pool's
    /// actual token balance.
    pub fn totals_consistent(env: Env) -> Result<bool, Error> {
        let t = Self::get_funding_totals(env.clone());
        let balance =
            token::Client::new(&env, &Self::token(&env)?).balance(&env.current_contract_address());
        Ok(t.unallocated >= 0
            && t.programmes_total >= 0
            && t.custody == t.programmes_total + t.unallocated
            && balance >= t.custody)
    }

    // ── TTL maintenance ──

    /// Permissionlessly extend the TTL of a work item's persistent entries
    /// (approval, claimed flag, programme link) so long-lived approvals
    /// are never archived. The caller pays the rent.
    pub fn bump_work_item(env: Env, work_item_id: BytesN<32>) -> Result<(), Error> {
        let key = DataKey::WorkItem(work_item_id.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::WorkItemNotApproved);
        }
        Self::bump_persistent(&env, &key);
        Self::bump_if_present(&env, &DataKey::WorkItemClaimed(work_item_id.clone()));
        Self::bump_if_present(&env, &DataKey::WorkItemProgramme(work_item_id));
        Ok(())
    }

    // ── Attester: claim payout ──

    /// Claim payout for an approved work item. Requires the approved
    /// attester's auth. Enforces replay protection, per-attester cap,
    /// and pool balance checks. Transfers tokens on success.
    pub fn claim(env: Env, work_item_id: BytesN<32>) -> Result<(), Error> {
        Self::require_not_paused(&env)?;

        let work_item: WorkItem = env
            .storage()
            .persistent()
            .get(&DataKey::WorkItem(work_item_id.clone()))
            .ok_or(Error::WorkItemNotApproved)?;
        let programme: Option<Symbol> = env
            .storage()
            .persistent()
            .get(&DataKey::WorkItemProgramme(work_item_id.clone()));

        let claimed: bool = env
            .storage()
            .persistent()
            .get(&DataKey::WorkItemClaimed(work_item_id.clone()))
            .unwrap_or(false);
        if claimed {
            return Err(Error::WorkItemAlreadyClaimed);
        }

        let attester = work_item.attester.clone();
        attester.require_auth();

        // Verify attester is still allowlisted (may have been suspended
        // since approval).
        let registry_id = Self::attester_registry(&env)?;
        let registry = AttesterRegistryClient::new(&env, &registry_id);
        if !registry.is_attester(&attester) {
            return Err(Error::AttesterNotAllowlisted);
        }

        // Enforce per-attester cumulative cap.
        let max_per_attester: i128 = env
            .storage()
            .instance()
            .get(&DataKey::MaxPerAttester)
            .unwrap_or(i128::MAX);
        let attester_claimed: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::AttesterTotalClaimed(attester.clone()))
            .unwrap_or(0);
        if attester_claimed + work_item.payout_amount > max_per_attester {
            return Err(Error::AttesterClaimCapExceeded);
        }

        // Verify pool has sufficient unallocated balance.
        let total_paid: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalPaid)
            .unwrap_or(0);
        let total_deposited: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalDeposited)
            .unwrap_or(0);
        match &programme {
            Some(p) => {
                if Self::get_persistent_i128(&env, &DataKey::ProgrammeBalance(p.clone()))
                    < work_item.payout_amount
                {
                    return Err(Error::InsufficientProgrammeBalance);
                }
            }
            None => {
                let programmes_total =
                    Self::get_instance_i128(&env, &DataKey::TotalProgrammeBalance);
                if total_paid + programmes_total + work_item.payout_amount > total_deposited {
                    return Err(Error::InsufficientPoolBalance);
                }
            }
        }

        // Execute token transfer. On failure the transaction is
        // rolled back, preserving consistent state.
        let token_addr = Self::token(&env)?;
        let pool_addr = env.current_contract_address();
        let token_client = token::Client::new(&env, &token_addr);

        token_client.transfer(&pool_addr, &attester, &work_item.payout_amount);

        // Persist state updates after successful transfer.
        env.storage()
            .persistent()
            .set(&DataKey::WorkItemClaimed(work_item_id.clone()), &true);
        env.storage()
            .instance()
            .set(&DataKey::TotalPaid, &(total_paid + work_item.payout_amount));
        env.storage().persistent().set(
            &DataKey::AttesterTotalClaimed(attester.clone()),
            &(attester_claimed + work_item.payout_amount),
        );
        if let Some(p) = programme {
            Self::add_persistent_i128(
                &env,
                &DataKey::ProgrammeBalance(p),
                -work_item.payout_amount,
            );
            Self::add_instance_i128(
                &env,
                &DataKey::TotalProgrammeBalance,
                -work_item.payout_amount,
            );
        }

        // The claimant pays to keep replay-protection and cap entries live.
        Self::bump_persistent(&env, &DataKey::WorkItem(work_item_id.clone()));
        Self::bump_persistent(&env, &DataKey::WorkItemClaimed(work_item_id.clone()));
        Self::bump_persistent(&env, &DataKey::AttesterTotalClaimed(attester.clone()));
        Self::bump_instance(&env);

        PayoutClaimed {
            work_item_id,
            attester,
            amount: work_item.payout_amount,
        }
        .publish(&env);

        Ok(())
    }

    // ── Pause / unpause ──

    /// Pause the contract, blocking `fund`, `withdraw`,
    /// `approve_work_item`, and `claim` until `unpause` is called.
    /// Requires admin auth.
    pub fn pause(env: Env) -> Result<(), Error> {
        let admin = Self::admin(&env)?;
        admin.require_auth();
        env.storage().instance().set(&DataKey::Paused, &true);
        Paused { by: admin }.publish(&env);
        Ok(())
    }

    /// Resume normal operation after a `pause`. Requires admin auth.
    pub fn unpause(env: Env) -> Result<(), Error> {
        let admin = Self::admin(&env)?;
        admin.require_auth();
        env.storage().instance().set(&DataKey::Paused, &false);
        Unpaused { by: admin }.publish(&env);
        Ok(())
    }

    /// Whether the contract is currently paused.
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    // ── Private helpers ──

    fn admin(env: &Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)
    }

    fn approver(env: &Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Approver)
            .ok_or(Error::NotInitialized)
    }

    fn token(env: &Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(Error::NotInitialized)
    }

    fn attester_registry(env: &Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::AttesterRegistry)
            .ok_or(Error::NotInitialized)
    }

    fn bump_instance(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }

    fn bump_persistent(env: &Env, key: &DataKey) {
        env.storage().persistent().extend_ttl(
            key,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }

    fn bump_if_present(env: &Env, key: &DataKey) {
        if env.storage().persistent().has(key) {
            Self::bump_persistent(env, key);
        }
    }

    fn get_instance_i128(env: &Env, key: &DataKey) -> i128 {
        env.storage().instance().get(key).unwrap_or(0)
    }

    fn add_instance_i128(env: &Env, key: &DataKey, delta: i128) {
        let v = Self::get_instance_i128(env, key) + delta;
        env.storage().instance().set(key, &v);
    }

    fn get_persistent_i128(env: &Env, key: &DataKey) -> i128 {
        env.storage().persistent().get(key).unwrap_or(0)
    }

    fn add_persistent_i128(env: &Env, key: &DataKey, delta: i128) {
        let v = Self::get_persistent_i128(env, key) + delta;
        env.storage().persistent().set(key, &v);
        Self::bump_persistent(env, key);
    }

    fn threshold(env: &Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::ApprovalThreshold)
            .unwrap_or(0)
    }

    fn approver_set(env: &Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::Approvers)
            .unwrap_or(Vec::new(env))
    }

    fn require_approver_member(env: &Env, who: &Address) -> Result<(), Error> {
        if Self::threshold(env) == 0 {
            return Err(Error::QuorumNotConfigured);
        }
        if !Self::approver_set(env).contains(who) {
            return Err(Error::NotAnApprover);
        }
        Ok(())
    }

    /// Endorsements by addresses still in the current approver set, so a
    /// removed approver's endorsement stops counting immediately.
    fn valid_endorsements(env: &Env, p: &Proposal) -> u32 {
        let set = Self::approver_set(env);
        p.endorsements.iter().filter(|e| set.contains(e)).count() as u32
    }

    fn rate_limit(env: &Env) -> RateLimit {
        env.storage()
            .instance()
            .get(&DataKey::RateLimit)
            .unwrap_or(RateLimit {
                window_seconds: DEFAULT_RATE_WINDOW_SECONDS,
                max_count: DEFAULT_RATE_MAX_COUNT,
                max_value: i128::MAX,
            })
    }

    fn current_window(env: &Env, approver: &Address, limit: &RateLimit) -> ApproverWindow {
        let now = env.ledger().timestamp();
        let w: Option<ApproverWindow> = env
            .storage()
            .persistent()
            .get(&DataKey::ApproverWindow(approver.clone()));
        match w {
            Some(w) if now < w.window_start.saturating_add(limit.window_seconds) => w,
            _ => ApproverWindow {
                window_start: now,
                count: 0,
                value: 0,
            },
        }
    }

    /// Charge one approval of `value` to `approver`'s window. Enforced
    /// before any pool-wide budget check (see docs/storage-cost.md).
    fn charge_rate_limit(env: &Env, approver: &Address, value: i128) -> Result<(), Error> {
        let limit = Self::rate_limit(env);
        let mut w = Self::current_window(env, approver, &limit);
        let count = w.count.saturating_add(1);
        let total = w.value.saturating_add(value);
        if count > limit.max_count || total > limit.max_value {
            return Err(Error::ApproverRateLimited);
        }
        w.count = count;
        w.value = total;
        let key = DataKey::ApproverWindow(approver.clone());
        env.storage().persistent().set(&key, &w);
        Self::bump_persistent(env, &key);
        if count == limit.max_count || total == limit.max_value {
            ApproverRateLimitHit {
                approver: approver.clone(),
                count,
                value: total,
                window_resets_at: w.window_start.saturating_add(limit.window_seconds),
            }
            .publish(env);
        }
        Ok(())
    }

    fn approve_single(
        env: Env,
        work_item_id: BytesN<32>,
        attester: Address,
        payout_amount: i128,
        programme: Option<Symbol>,
    ) -> Result<(), Error> {
        let approver = Self::approver(&env)?;
        approver.require_auth();
        Self::require_not_paused(&env)?;
        if Self::threshold(&env) > 0 {
            return Err(Error::QuorumRequired);
        }
        Self::validate_approval(&env, &work_item_id, &attester, payout_amount, &programme)?;
        Self::charge_rate_limit(&env, &approver, payout_amount)?;
        Self::store_approval(&env, work_item_id, attester, payout_amount, programme);
        Ok(())
    }

    fn validate_approval(
        env: &Env,
        work_item_id: &BytesN<32>,
        attester: &Address,
        payout_amount: i128,
        programme: &Option<Symbol>,
    ) -> Result<(), Error> {
        if payout_amount <= 0 {
            return Err(Error::NonPositiveAmount);
        }
        if env
            .storage()
            .persistent()
            .has(&DataKey::WorkItem(work_item_id.clone()))
        {
            return Err(Error::WorkItemAlreadyApproved);
        }
        let registry = AttesterRegistryClient::new(env, &Self::attester_registry(env)?);
        if !registry.is_attester(attester) {
            return Err(Error::AttesterNotAllowlisted);
        }
        let max_per_claim: i128 = env
            .storage()
            .instance()
            .get(&DataKey::MaxPerClaim)
            .unwrap_or(i128::MAX);
        if payout_amount > max_per_claim {
            return Err(Error::PayoutCapExceeded);
        }
        if let Some(p) = programme {
            if Self::get_persistent_i128(env, &DataKey::ProgrammeBalance(p.clone())) < payout_amount
            {
                return Err(Error::InsufficientProgrammeBalance);
            }
        }
        Ok(())
    }

    /// The approver (or quorum executor) pays to keep the approval live.
    fn store_approval(
        env: &Env,
        work_item_id: BytesN<32>,
        attester: Address,
        payout_amount: i128,
        programme: Option<Symbol>,
    ) {
        let key = DataKey::WorkItem(work_item_id.clone());
        let work_item = WorkItem {
            attester: attester.clone(),
            payout_amount,
            approved_at: env.ledger().timestamp(),
        };
        env.storage().persistent().set(&key, &work_item);
        Self::bump_persistent(env, &key);
        if let Some(p) = programme {
            let pk = DataKey::WorkItemProgramme(work_item_id.clone());
            env.storage().persistent().set(&pk, &p);
            Self::bump_persistent(env, &pk);
            WorkItemProgrammeLinked {
                work_item_id: work_item_id.clone(),
                programme: p,
            }
            .publish(env);
        }
        Self::bump_instance(env);
        WorkItemApproved {
            work_item_id,
            attester,
            payout_amount,
        }
        .publish(env);
    }

    fn require_not_paused(env: &Env) -> Result<(), Error> {
        let paused: bool = env
            .storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false);
        if paused {
            return Err(Error::ContractPaused);
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod test;
