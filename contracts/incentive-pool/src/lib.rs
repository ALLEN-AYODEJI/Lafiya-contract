#![no_std]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
#![allow(missing_docs)] // soroban macros generate undocumented public items

//! # Incentive Pool
//!
//! Bounded USDC payout/escrow contract for the M2 milestone.
//! Donors fund the pool, an approver authorizes work items, and
//! approved allowlisted attesters claim per-item payouts with
//! per-attestation replay protection.

use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype, token,
    Address, BytesN, Env,
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

/// Default approval lifetime: 90 days, in seconds of ledger time.
/// Also applied to work items approved before expiry existed (see ADR 0018).
pub const DEFAULT_APPROVAL_TTL_SECS: u64 = 90 * 24 * 60 * 60;
/// Default upper bound on any approval lifetime: 365 days.
pub const DEFAULT_MAX_APPROVAL_TTL_SECS: u64 = 365 * 24 * 60 * 60;

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
    /// Default approval TTL in seconds (u64).
    DefaultApprovalTtl,
    /// Maximum approval TTL in seconds (u64); bounds per-approval overrides.
    MaxApprovalTtl,
    /// Work-item record carrying `expires_at`. Items approved before the
    /// expiry upgrade remain under `WorkItem` in the legacy shape.
    WorkItemV2(BytesN<32>),
    /// Tombstone: reason code of a cancelled work item. Never removed, so a
    /// cancelled id cannot be re-approved.
    WorkItemCancelled(BytesN<32>),
    /// Tombstone: the work item expired and its reservation was swept.
    WorkItemSwept(BytesN<32>),
    /// Sum of payout amounts of approved, unclaimed, live work items (i128).
    TotalReserved,
    /// Set when a token balance mismatch was observed; blocks `claim`
    /// until the admin calls `resolve_drift`.
    DriftDetected,
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
    /// Ledger timestamp after which the item can no longer be claimed.
    /// The item is claimable while `now < expires_at`.
    pub expires_at: u64,
}

/// Pre-expiry work-item shape, still stored under `DataKey::WorkItem` for
/// items approved before the upgrade. Read-only.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
struct LegacyWorkItem {
    attester: Address,
    payout_amount: i128,
    approved_at: u64,
}

/// Result of `reconcile`: internal accounting versus custody.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reconciliation {
    /// `total_deposited - total_paid`: what the pool believes it holds.
    pub accounted: i128,
    /// The pool's actual token balance.
    pub actual_balance: i128,
    /// `actual_balance - accounted`. Negative means custody shortfall.
    pub drift: i128,
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
pub struct WorkItemCancelled {
    #[topic]
    pub work_item_id: BytesN<32>,
    pub cancelled_by: Address,
    pub reason_code: u32,
    pub amount: i128,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct WorkItemExpired {
    #[topic]
    pub work_item_id: BytesN<32>,
    pub attester: Address,
    pub amount: i128,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct BalanceMismatch {
    #[topic]
    pub expected: i128,
    pub observed: i128,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct DriftResolved {
    #[topic]
    pub by: Address,
    pub drift: i128,
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
    /// A cumulative counter update would overflow or underflow `i128`.
    /// @severity bug
    ArithmeticOverflow = 16,
    /// The work item's approval has expired; it can only be swept.
    WorkItemExpired = 17,
    /// `sweep_expired` was called on a work item that has not expired yet.
    WorkItemNotExpired = 18,
    /// The work item was cancelled; it cannot be claimed or re-approved.
    WorkItemCancelled = 19,
    /// The requested approval TTL is zero or exceeds the configured maximum.
    InvalidApprovalTtl = 20,
    /// The caller is neither the approver nor the admin.
    Unauthorized = 21,
    /// The pool's token balance diverged from internal accounting;
    /// `claim` is blocked until the admin calls `resolve_drift`.
    /// @severity operator
    ReconciliationRequired = 22,
    /// A token transfer moved a different amount than requested.
    /// @severity operator
    TokenBalanceMismatch = 23,
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
        Self::has_work_item(&env, &work_item_id)
    }

    /// Whether a work item has been claimed.
    pub fn is_work_item_claimed(env: Env, work_item_id: BytesN<32>) -> bool {
        Self::is_claimed(&env, &work_item_id)
    }

    /// Return the work item details, if approved. Legacy items report
    /// `expires_at = approved_at + DEFAULT_APPROVAL_TTL_SECS`.
    pub fn get_work_item(env: Env, work_item_id: BytesN<32>) -> Option<WorkItem> {
        Self::load_work_item(&env, &work_item_id).ok()
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
    ///
    /// Only the observed change in the pool's token balance is credited,
    /// so fee-on-transfer tokens cannot inflate `TotalDeposited`. If the
    /// observed delta differs from `amount`, a `BalanceMismatch` event is
    /// emitted and `claim` is blocked until the admin calls `resolve_drift`.
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

        let before = token_client.balance(&pool_addr);
        token_client.transfer(&admin, &pool_addr, &amount);
        let after = token_client.balance(&pool_addr);
        let received = after.checked_sub(before).ok_or(Error::ArithmeticOverflow)?;
        if received <= 0 {
            return Err(Error::TokenBalanceMismatch);
        }
        if received != amount {
            env.storage().instance().set(&DataKey::DriftDetected, &true);
            BalanceMismatch {
                expected: amount,
                observed: received,
            }
            .publish(&env);
        }

        let deposited = Self::total_deposited(&env)
            .checked_add(received)
            .ok_or(Error::ArithmeticOverflow)?;
        env.storage()
            .instance()
            .set(&DataKey::TotalDeposited, &deposited);

        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);

        PoolFunded {
            funder: admin,
            amount: received,
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

        let total_paid = Self::total_paid(&env);
        let available = Self::total_deposited(&env)
            .checked_sub(total_paid)
            .ok_or(Error::ArithmeticOverflow)?;
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
        let new_paid = total_paid
            .checked_add(amount)
            .ok_or(Error::ArithmeticOverflow)?;
        env.storage().instance().set(&DataKey::TotalPaid, &new_paid);

        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);

        PoolWithdrawn { to, amount }.publish(&env);

        Ok(())
    }

    // ── Admin: reconciliation ──

    /// Compare internal accounting with the pool's actual token balance.
    pub fn reconcile(env: Env) -> Result<Reconciliation, Error> {
        Self::reconciliation(&env)
    }

    /// Whether a balance mismatch is blocking `claim`.
    pub fn is_drift_detected(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::DriftDetected)
            .unwrap_or(false)
    }

    /// Accept the observed token balance as the new accounting baseline and
    /// unblock `claim`. Positive drift (e.g. a direct transfer) is credited
    /// as a deposit; negative drift (e.g. clawback) is debited. Requires
    /// admin auth. Fails if the debit would make `total_paid` exceed
    /// `total_deposited`.
    pub fn resolve_drift(env: Env) -> Result<Reconciliation, Error> {
        let admin = Self::admin(&env)?;
        admin.require_auth();

        let rec = Self::reconciliation(&env)?;
        let deposited = Self::total_deposited(&env)
            .checked_add(rec.drift)
            .ok_or(Error::ArithmeticOverflow)?;
        if deposited < Self::total_paid(&env) {
            return Err(Error::InsufficientPoolBalance);
        }
        env.storage()
            .instance()
            .set(&DataKey::TotalDeposited, &deposited);
        env.storage()
            .instance()
            .set(&DataKey::DriftDetected, &false);

        DriftResolved {
            by: admin,
            drift: rec.drift,
        }
        .publish(&env);

        Ok(rec)
    }

    // ── Admin: approval TTL configuration ──

    /// Return `(default_ttl_secs, max_ttl_secs)` for work-item approvals.
    pub fn get_approval_ttl(env: Env) -> (u64, u64) {
        (Self::default_ttl(&env), Self::max_ttl(&env))
    }

    /// Set the default and maximum approval TTL in seconds. Requires admin
    /// auth. Both must be positive and `default_ttl <= max_ttl`. Applies to
    /// new approvals only; existing items keep their `expires_at`.
    pub fn set_approval_ttl(env: Env, default_ttl: u64, max_ttl: u64) -> Result<(), Error> {
        Self::admin(&env)?.require_auth();
        if default_ttl == 0 || default_ttl > max_ttl {
            return Err(Error::InvalidApprovalTtl);
        }
        env.storage()
            .instance()
            .set(&DataKey::DefaultApprovalTtl, &default_ttl);
        env.storage()
            .instance()
            .set(&DataKey::MaxApprovalTtl, &max_ttl);
        Ok(())
    }

    // ── Approver: approve work items ──

    /// Approve a work item for payout with the default TTL. Requires the
    /// approver's auth. The `payout_amount` must be positive and must not
    /// exceed the per-claim cap. The attester must be allowlisted.
    pub fn approve_work_item(
        env: Env,
        work_item_id: BytesN<32>,
        attester: Address,
        payout_amount: i128,
    ) -> Result<(), Error> {
        let ttl = Self::default_ttl(&env);
        Self::approve(&env, work_item_id, attester, payout_amount, ttl)
    }

    /// Like `approve_work_item`, with an explicit approval lifetime in
    /// seconds. `ttl_secs` must be positive and at most the configured max.
    pub fn approve_work_item_with_ttl(
        env: Env,
        work_item_id: BytesN<32>,
        attester: Address,
        payout_amount: i128,
        ttl_secs: u64,
    ) -> Result<(), Error> {
        if ttl_secs == 0 || ttl_secs > Self::max_ttl(&env) {
            return Err(Error::InvalidApprovalTtl);
        }
        Self::approve(&env, work_item_id, attester, payout_amount, ttl_secs)
    }

    /// Cancel an approved, unclaimed work item. `caller` must be the approver
    /// or the admin and must authorize. The record is kept as a tombstone so
    /// the id cannot be re-approved, and its reservation is released.
    ///
    /// Same-ledger race with `claim`: Soroban applies transactions in a
    /// ledger sequentially, so whichever is applied first wins. A claim
    /// applied first makes the cancel fail with `WorkItemAlreadyClaimed`; a
    /// cancel applied first makes the claim fail with `WorkItemCancelled`.
    pub fn cancel_work_item(
        env: Env,
        caller: Address,
        work_item_id: BytesN<32>,
        reason_code: u32,
    ) -> Result<(), Error> {
        caller.require_auth();
        if caller != Self::approver(&env)? && caller != Self::admin(&env)? {
            return Err(Error::Unauthorized);
        }

        let work_item = Self::open_work_item(&env, &work_item_id)?;

        env.storage().persistent().set(
            &DataKey::WorkItemCancelled(work_item_id.clone()),
            &reason_code,
        );
        Self::release_reservation(&env, work_item.payout_amount)?;

        WorkItemCancelled {
            work_item_id,
            cancelled_by: caller,
            reason_code,
            amount: work_item.payout_amount,
        }
        .publish(&env);

        Ok(())
    }

    /// Return the cancellation reason code, if the work item was cancelled.
    pub fn get_cancel_reason(env: Env, work_item_id: BytesN<32>) -> Option<u32> {
        env.storage()
            .persistent()
            .get(&DataKey::WorkItemCancelled(work_item_id))
    }

    /// Release the reservation of an expired, unclaimed work item.
    /// Permissionless. Idempotent: sweeping an already-swept item is a no-op
    /// returning `Ok` without an event. Never releases a claimed or
    /// cancelled item.
    pub fn sweep_expired(env: Env, work_item_id: BytesN<32>) -> Result<(), Error> {
        if Self::is_swept(&env, &work_item_id) {
            return Ok(());
        }
        let work_item = Self::load_work_item(&env, &work_item_id)?;
        if Self::is_claimed(&env, &work_item_id) {
            return Err(Error::WorkItemAlreadyClaimed);
        }
        if Self::is_cancelled(&env, &work_item_id) {
            return Err(Error::WorkItemCancelled);
        }
        if env.ledger().timestamp() < work_item.expires_at {
            return Err(Error::WorkItemNotExpired);
        }

        env.storage()
            .persistent()
            .set(&DataKey::WorkItemSwept(work_item_id.clone()), &true);
        Self::release_reservation(&env, work_item.payout_amount)?;

        WorkItemExpired {
            work_item_id,
            attester: work_item.attester,
            amount: work_item.payout_amount,
        }
        .publish(&env);

        Ok(())
    }

    /// Whether an expired work item's reservation has been swept.
    pub fn is_work_item_swept(env: Env, work_item_id: BytesN<32>) -> bool {
        Self::is_swept(&env, &work_item_id)
    }

    /// Return the sum of payouts of approved, unclaimed, live work items.
    /// Items approved before reservation tracking existed are not counted.
    pub fn get_total_reserved(env: Env) -> i128 {
        Self::total_reserved(&env)
    }

    // ── Attester: claim payout ──

    /// Claim payout for an approved work item. Requires the approved
    /// attester's auth. Enforces replay protection, expiry, per-attester
    /// cap, pool balance and custody checks. Transfers tokens on success.
    pub fn claim(env: Env, work_item_id: BytesN<32>) -> Result<(), Error> {
        Self::require_not_paused(&env)?;

        let work_item = Self::open_work_item(&env, &work_item_id)?;

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
        let new_attester_claimed = attester_claimed
            .checked_add(work_item.payout_amount)
            .ok_or(Error::ArithmeticOverflow)?;
        if new_attester_claimed > max_per_attester {
            return Err(Error::AttesterClaimCapExceeded);
        }

        // Verify pool has sufficient unallocated balance.
        let total_paid = Self::total_paid(&env);
        let new_paid = total_paid
            .checked_add(work_item.payout_amount)
            .ok_or(Error::ArithmeticOverflow)?;
        if new_paid > Self::total_deposited(&env) {
            return Err(Error::InsufficientPoolBalance);
        }

        // Custody check: refuse to pay out while accounting and the actual
        // token balance disagree (fee-on-transfer, clawback, rebasing).
        let rec = Self::reconciliation(&env)?;
        if Self::is_drift_detected(env.clone()) || rec.drift < 0 {
            return Err(Error::ReconciliationRequired);
        }

        // Execute token transfer and verify the observed balance delta.
        // On failure the transaction is rolled back.
        let token_addr = Self::token(&env)?;
        let pool_addr = env.current_contract_address();
        let token_client = token::Client::new(&env, &token_addr);

        token_client.transfer(&pool_addr, &attester, &work_item.payout_amount);
        let sent = rec
            .actual_balance
            .checked_sub(token_client.balance(&pool_addr))
            .ok_or(Error::ArithmeticOverflow)?;
        if sent != work_item.payout_amount {
            return Err(Error::TokenBalanceMismatch);
        }

        // Persist state updates after successful transfer.
        env.storage()
            .persistent()
            .set(&DataKey::WorkItemClaimed(work_item_id.clone()), &true);
        env.storage().instance().set(&DataKey::TotalPaid, &new_paid);
        env.storage().persistent().set(
            &DataKey::AttesterTotalClaimed(attester.clone()),
            &new_attester_claimed,
        );
        if env
            .storage()
            .persistent()
            .has(&DataKey::WorkItemV2(work_item_id.clone()))
        {
            Self::release_reservation(&env, work_item.payout_amount)?;
        }

        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);

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

    fn approve(
        env: &Env,
        work_item_id: BytesN<32>,
        attester: Address,
        payout_amount: i128,
        ttl_secs: u64,
    ) -> Result<(), Error> {
        Self::approver(env)?.require_auth();
        Self::require_not_paused(env)?;

        if payout_amount <= 0 {
            return Err(Error::NonPositiveAmount);
        }

        // Reject duplicate approval; cancelled records stay in storage as
        // tombstones, so a cancelled id is rejected here too.
        if Self::is_cancelled(env, &work_item_id) {
            return Err(Error::WorkItemCancelled);
        }
        if Self::has_work_item(env, &work_item_id) {
            return Err(Error::WorkItemAlreadyApproved);
        }

        // Verify attester is currently allowlisted.
        let registry_id = Self::attester_registry(env)?;
        let registry = AttesterRegistryClient::new(env, &registry_id);
        if !registry.is_attester(&attester) {
            return Err(Error::AttesterNotAllowlisted);
        }

        // Enforce per-claim cap at approval time.
        let max_per_claim: i128 = env
            .storage()
            .instance()
            .get(&DataKey::MaxPerClaim)
            .unwrap_or(i128::MAX);
        if payout_amount > max_per_claim {
            return Err(Error::PayoutCapExceeded);
        }

        let approved_at = env.ledger().timestamp();
        let work_item = WorkItem {
            attester: attester.clone(),
            payout_amount,
            approved_at,
            expires_at: approved_at
                .checked_add(ttl_secs)
                .ok_or(Error::ArithmeticOverflow)?,
        };

        env.storage()
            .persistent()
            .set(&DataKey::WorkItemV2(work_item_id.clone()), &work_item);

        let reserved = Self::total_reserved(env)
            .checked_add(payout_amount)
            .ok_or(Error::ArithmeticOverflow)?;
        env.storage()
            .instance()
            .set(&DataKey::TotalReserved, &reserved);

        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);

        WorkItemApproved {
            work_item_id,
            attester,
            payout_amount,
        }
        .publish(env);

        Ok(())
    }

    fn has_work_item(env: &Env, id: &BytesN<32>) -> bool {
        let store = env.storage().persistent();
        store.has(&DataKey::WorkItemV2(id.clone())) || store.has(&DataKey::WorkItem(id.clone()))
    }

    /// Load a work item, upgrading a legacy record on read.
    fn load_work_item(env: &Env, id: &BytesN<32>) -> Result<WorkItem, Error> {
        let store = env.storage().persistent();
        if let Some(item) = store.get::<_, WorkItem>(&DataKey::WorkItemV2(id.clone())) {
            return Ok(item);
        }
        let legacy: LegacyWorkItem = store
            .get(&DataKey::WorkItem(id.clone()))
            .ok_or(Error::WorkItemNotApproved)?;
        Ok(WorkItem {
            attester: legacy.attester,
            payout_amount: legacy.payout_amount,
            approved_at: legacy.approved_at,
            expires_at: legacy.approved_at.saturating_add(DEFAULT_APPROVAL_TTL_SECS),
        })
    }

    /// Load a work item that is still claimable or cancellable: approved,
    /// not claimed, not cancelled, not expired.
    fn open_work_item(env: &Env, id: &BytesN<32>) -> Result<WorkItem, Error> {
        let item = Self::load_work_item(env, id)?;
        if Self::is_claimed(env, id) {
            return Err(Error::WorkItemAlreadyClaimed);
        }
        if Self::is_cancelled(env, id) {
            return Err(Error::WorkItemCancelled);
        }
        if Self::is_swept(env, id) || env.ledger().timestamp() >= item.expires_at {
            return Err(Error::WorkItemExpired);
        }
        Ok(item)
    }

    fn is_claimed(env: &Env, id: &BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::WorkItemClaimed(id.clone()))
            .unwrap_or(false)
    }

    fn is_cancelled(env: &Env, id: &BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::WorkItemCancelled(id.clone()))
    }

    fn is_swept(env: &Env, id: &BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::WorkItemSwept(id.clone()))
            .unwrap_or(false)
    }

    /// Decrease `TotalReserved`, flooring at zero: legacy items were never
    /// added to the reservation counter.
    fn release_reservation(env: &Env, amount: i128) -> Result<(), Error> {
        let reserved = Self::total_reserved(env)
            .checked_sub(amount)
            .ok_or(Error::ArithmeticOverflow)?
            .max(0);
        env.storage()
            .instance()
            .set(&DataKey::TotalReserved, &reserved);
        Ok(())
    }

    fn reconciliation(env: &Env) -> Result<Reconciliation, Error> {
        let accounted = Self::total_deposited(env)
            .checked_sub(Self::total_paid(env))
            .ok_or(Error::ArithmeticOverflow)?;
        let token_client = token::Client::new(env, &Self::token(env)?);
        let actual_balance = token_client.balance(&env.current_contract_address());
        let drift = actual_balance
            .checked_sub(accounted)
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(Reconciliation {
            accounted,
            actual_balance,
            drift,
        })
    }

    fn total_deposited(env: &Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::TotalDeposited)
            .unwrap_or(0)
    }

    fn total_paid(env: &Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::TotalPaid)
            .unwrap_or(0)
    }

    fn total_reserved(env: &Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::TotalReserved)
            .unwrap_or(0)
    }

    fn default_ttl(env: &Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::DefaultApprovalTtl)
            .unwrap_or(DEFAULT_APPROVAL_TTL_SECS)
    }

    fn max_ttl(env: &Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::MaxApprovalTtl)
            .unwrap_or(DEFAULT_MAX_APPROVAL_TTL_SECS)
    }

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
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
mod test;
