# Graceful Refresh-Token Rotation — Architecture Design

**Branch:** `gracefulToken`  
**Component:** `identity-inbound-auth-oauth`  
**Audience:** Architecture review

---

## 1. Overview

Standard OAuth refresh-token rotation immediately revokes the previous token the instant a rotation succeeds. This causes a client availability problem in distributed or mobile scenarios: if the rotated token is lost in transit (network failure, parallel request racing, client crash before persist), the client has no valid refresh token and must re-authenticate.

**Graceful rotation** introduces a temporary overlap window — the old refresh token transitions into a new state (`GRACEFULLY_ROTATED`) and remains redeemable for a short, bounded period after a new token has already been issued. This gives distributed clients a safe replay window without abandoning the security guarantees of rotation.

The core new concept is one new token lifecycle state:

```
TOKEN_STATE_GRACEFULLY_ROTATED = "GRACEFULLY_ROTATED"
```

The feature is opt-in at the per-application level and off by default. All security limits (grace window duration, maximum reuse count) are server-side sealed — clients cannot extend them.

---

## 2. Goals & Non-Goals

### Goals

- Allow a rotated refresh token to remain redeemable for a bounded grace window (default 30 s, max 60 s).
- Limit the number of times a gracefully-rotated token may be reused (default 5, max 5, min 1).
- Detect and prevent grace-window extension: a replayed token must not reset the deadline.
- Enforce reuse limits safely under concurrent requests (race guard inside the DB write transaction).
- Preserve full backward compatibility: apps that do not opt in continue on the existing `ACTIVE → INACTIVE` path without any behavioral change.
- Keep the schema change additive only — no migration of the main `IDN_OAUTH2_ACCESS_TOKEN` table.

### Non-Goals

- Global server-level toggle (per-app opt-in is the only surface).
- Extending the grace window dynamically based on client signals.
- Persisting a dedicated `previous_token_id` foreign-key column on the main token table.
- Changes to the access-token (AT) lifetime — only the refresh-token validity of the old row is shortened to the grace deadline; access-token validity on the old row is unaffected in this iteration (see §14).

---

## 3. High-Level Architecture

The feature spans four layers. Each layer has a clearly scoped responsibility:

```
┌─────────────────────────────────────────────────────────────┐
│  Admin API / Config Layer                                    │
│  OAuthAppDO / OAuthConsumerAppDTO / OAuthAppDAO              │
│  ─ 3 new per-app config knobs                               │
│  ─ Persisted as OIDC SP properties                          │
└──────────────────────┬──────────────────────────────────────┘
                       │ OAuthAppDO loaded at grant time
┌──────────────────────▼──────────────────────────────────────┐
│  Grant Flow Layer                                            │
│  DefaultRefreshTokenGrantProcessor                           │
│  ─ Decides: graceful path vs legacy path                    │
│  ─ Computes grace deadline, detects replays, enforces limit │
│  RefreshGrantHandler                                         │
│  ─ Ensures new refresh token gets full, not shortened, TTL  │
└──────────────────────┬──────────────────────────────────────┘
                       │ DAO method calls
┌──────────────────────▼──────────────────────────────────────┐
│  DAO Layer                                                   │
│  AccessTokenDAO (interface) / AccessTokenDAOImpl             │
│  ─ 3 new methods (rotate, sibling-list, attr-lookup)        │
│  TokenManagementDAOImpl                                      │
│  ─ Routes validation queries to consented-token-aware       │
│    dialect variants                                          │
│  SQLQueries                                                  │
│  ─ New query constants + 12 new dialect-specific variants   │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│  Persistence / Schema                                        │
│  IDN_OAUTH2_ACCESS_TOKEN  (mutated — no new columns)        │
│  IDN_OAUTH2_ACCESS_TOKEN_ATTRIBUTES  (new sidecar table)    │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Token Lifecycle State Machine

### Legacy path (graceful rotation disabled)

```
  ACTIVE
    │
    │  refresh-token grant
    ▼
  INACTIVE ──────────────── (terminal)
```

### Graceful path (graceful rotation enabled, renew-refresh-token on)

```
  ACTIVE
    │
    │  first refresh (no prior rotation for this token)
    │  ─ compute shortened validity  = elapsed_since_RT_issued + grace_period
    │  ─ save original validity in ATTRIBUTES
    │  ─ revoke all other ACTIVE siblings
    ▼
  GRACEFULLY_ROTATED  ◄──────────────────────────────────────────────────┐
    │                                                                     │
    │  replay within grace window  (reuseCount < limit)                  │
    │  ─ detect "newer sibling exists" → hasNewerSibling = true          │
    │  ─ increment reuseCount in ATTRIBUTES (only if hasNewerSibling)    │
    │  ─ DO NOT recompute shortened validity (non-extension invariant)   │
    └─────────────────────────────────────────────────────────────────────┘
    │
    │  replay, but reuseCount >= limit
    ▼
  REJECTED  (IdentityOAuth2Exception: reuse limit reached)

    │  grace window elapses
    ▼
  treated as EXPIRED by existing validity checks (no state change needed)
```

### State decision at validation time

Before hitting the grant flow, `validateRefreshTokenReuseLimit` performs an in-memory translation:

```
DB state == GRACEFULLY_ROTATED  &&  grace enabled?
  ─ treat as ACTIVE for downstream validators
  ─ enforce reuse limit (throw if exceeded)
```

This keeps all downstream validation code unmodified — they continue to check for `ACTIVE` only.

---

## 5. Configuration Surface

All three knobs are scoped per application and stored as OIDC SP properties in `IDN_SP_AUTH_STEP_PROP` (via the existing `IOAuthAppDAO` property storage mechanism).

| Knob | Type | Default | Min | Max (sealed) | OIDC SP property key |
|---|---|---|---|---|---|
| `gracefulRefreshTokenRotationEnabled` | boolean | `false` | — | — | `isGracefulRefreshTokenRotationEnabled` |
| `gracefulRefreshTokenRotationValidityPeriod` | int (seconds) | `30` | `> 0` (else reset to 30) | `60` | `gracefulRefreshTokenRotationValidityPeriod` |
| `gracefulRefreshTokenReuseLimit` | int (count) | `5` | `1` | `5` | `gracefulRefreshTokenReuseLimit` |

**Sealing (clamping) is enforced at write time in `OAuthAppDAO`** — both on create and on update. Values outside bounds are silently clamped with a debug-level log. The clamped value is written back to `OAuthAppDO` so the in-memory object stays consistent with what is persisted.

The feature is fully gated by the boolean flag: all other knobs are only consulted when `gracefulRefreshTokenRotationEnabled = true`.

---

## 6. Persistence Model — Design Decision: No New Columns

### Decision

Graceful rotation state is encoded using three existing columns on `IDN_OAUTH2_ACCESS_TOKEN` plus a new generic key-value sidecar table. No new columns are added to the main token table.

### How existing columns are repurposed

When the old token row is transitioned into `GRACEFULLY_ROTATED`:

| Column | Normal meaning | Grace use |
|---|---|---|
| `TOKEN_STATE` | `'ACTIVE'` | Set to `'GRACEFULLY_ROTATED'` |
| `TOKEN_STATE_ID` | Unique constraint component | Reassigned to a fresh `UUID.randomUUID()` so the new ACTIVE row and the old GRACEFULLY_ROTATED row can coexist under the same composite unique constraint |
| `REFRESH_TOKEN_VALIDITY_PERIOD` | Configured app TTL (ms) | Shortened to `elapsed_since_RT_issuance + grace_period_ms` |
| `REFRESH_TOKEN_HASH` | Lookup key | Left unchanged — the old row retains the old refresh token's hash; the new ACTIVE row carries the new refresh token's hash (different, since `renew_refresh_token = true` is required) |

### Why reassign `TOKEN_STATE_ID`

The unique constraint on `IDN_OAUTH2_ACCESS_TOKEN` includes `TOKEN_STATE_ID` to allow a single consumer/user/scope combination to have at most one ACTIVE token at a time. When graceful rotation is active, two rows for the same combination briefly coexist: one `ACTIVE` (new) and one `GRACEFULLY_ROTATED` (old). Assigning the old row a fresh random `TOKEN_STATE_ID` at the moment of transition is the minimally-invasive way to satisfy the constraint without altering the schema.

### Sidecar table: `IDN_OAUTH2_ACCESS_TOKEN_ATTRIBUTES`

```sql
CREATE TABLE IDN_OAUTH2_ACCESS_TOKEN_ATTRIBUTES (
    TOKEN_ID         VARCHAR(255)  NOT NULL,
    TOKEN_ATTR_NAME  VARCHAR(255)  NOT NULL,
    TOKEN_ATTR_VALUE VARCHAR(2048),
    PRIMARY KEY (TOKEN_ID, TOKEN_ATTR_NAME),
    FOREIGN KEY (TOKEN_ID)
        REFERENCES IDN_OAUTH2_ACCESS_TOKEN(TOKEN_ID) ON DELETE CASCADE
);
```

This table is a generic key-value store for token-level metadata. Two attributes are written by graceful rotation (on the **old** token row only):

| Attribute key constant | Value | Purpose |
|---|---|---|
| `GRACEFUL_REFRESH_TOKEN_REUSE_COUNT` | Integer string (e.g. `"2"`) | Current number of times this GRACEFULLY_ROTATED token has been replayed |
| `GRACEFUL_REFRESH_TOKEN_ORIGINAL_VALIDITY_IN_MILLIS` | Long string | The original `REFRESH_TOKEN_VALIDITY_PERIOD` before it was shortened, preserved so the new token receives the full-lifetime value |

These attributes are explicitly **stripped** before copying `tokenReq.getAccessTokenExtendedAttributes()` onto the newly minted token — they are bookkeeping on the old row only.

---

## 7. Grant Flow Decision Tree

The central decision point is `DefaultRefreshTokenGrantProcessor.persistNewToken(...)`.

```
persistNewToken
  │
  ├─ oAuthAppDO != null
  │   && isRenewRefreshToken(appDO.getRenewRefreshTokenEnabled())
  │   && appDO.isGracefulRefreshTokenRotationEnabled()
  │         │ YES → GRACEFUL PATH
  │         │ NO  → legacy invalidateAndCreateNewAccessToken()  (ACTIVE → INACTIVE)
  │
  ├─ [GRACEFUL PATH]
  │   │
  │   ├─ RACE GUARD: fresh DB read of reuseCount inside sync block
  │   │   freshCount >= reuseLimit?  → throw (reuse limit exceeded)
  │   │
  │   ├─ revokeStaleSiblings(clientId, user, scope, binding)
  │   │   returns: hasNewerSibling (bool) — true if a sibling
  │   │            with a later issuedTime already exists
  │   │
  │   ├─ newReuseCount = hasNewerSibling ? currentCount + 1 : 0
  │   │
  │   ├─ newReuseCount == 0 (FIRST ROTATION)
  │   │   ├─ shortenedValidity = elapsed_since_RT_issued + grace_period_ms
  │   │   ├─ newStateId = UUID.randomUUID()
  │   │   ├─ newState   = TOKEN_STATE_GRACEFULLY_ROTATED
  │   │   └─ extendedAttrs = { ORIGINAL_VALIDITY: oldValidityMs,
  │   │                        REUSE_COUNT: "0" }
  │   │
  │   └─ newReuseCount > 0 (SUBSEQUENT REUSE)
  │       ├─ shortenedValidity = 0L    (no-op: DB row not updated)
  │       ├─ newStateId = null         (no-op: TOKEN_STATE_ID not updated)
  │       ├─ newState   = null         (no-op: TOKEN_STATE not updated)
  │       └─ extendedAttrs = { REUSE_COUNT: newReuseCount }
  │
  └─ gracefullyRotateAndCreateNewAccessToken(
         oldTokenId, oldIssuedTime, shortenedValidity,
         newStateId, newState, clientId, newTokenDO,
         userStoreDomain, grantType, extendedAttrs)
```

### Grant-cache behavior

On **first rotation only**, the `AuthorizationGrantCacheEntry` for the old access-token key is re-inserted with `validityPeriod = elapsedSinceRefreshIssued + graceMillis` (nanoseconds). This ensures cached introspection of the old AT remains valid for the grace window. On subsequent reuses this cache write is skipped to prevent extension of the cached window.

---

## 8. Validation Flow: Preserving New-Token TTL

### The problem

When the old row transitions to `GRACEFULLY_ROTATED`, its `REFRESH_TOKEN_VALIDITY_PERIOD` is shortened to the grace deadline. If `RefreshGrantHandler.setRefreshTokenData` naively propagated that shortened value to the new token (needed when renewal is off, or extend-expiry is off), the new refresh token would inherit the truncated grace window rather than the application-configured full lifetime.

### The solution: `resolveOldRefreshValidity`

```
resolveOldRefreshValidity(validationBean, oAuthAppDO)
  ├─ graceful rotation disabled? → return validationBean.getValidityPeriodInMillis()  [legacy]
  └─ graceful rotation enabled?
      ├─ read GRACEFUL_REFRESH_TOKEN_ORIGINAL_VALIDITY_IN_MILLIS from validationBean
      │   extended attributes
      ├─ parseable long found? → return it  [original full TTL]
      └─ fallback: return validationBean.getValidityPeriodInMillis()
```

All three code paths in `setRefreshTokenData` (renewal off, renewal on / no extend-expiry, extended token) now route through this helper.

---

## 9. DAO Layer Changes

Three new methods were added to the `AccessTokenDAO` interface (with `default` implementations that fall back to legacy behaviour when not overridden by the extended DAO).

### `gracefullyRotateAndCreateNewAccessToken(...)`

Single JDBC transaction that:
1. If `oldTokenNewStateId != null`: runs `UPDATE_REFRESH_TOKEN_VALIDITY_STATE_AND_STATE_ID` — sets `REFRESH_TOKEN_VALIDITY_PERIOD`, `TOKEN_STATE`, `TOKEN_STATE_ID` on the old row.
2. If `oldTokenExtendedAttributeUpdates` non-empty and extended-attributes table exists: upserts via UPDATE-then-INSERT pattern on `IDN_OAUTH2_ACCESS_TOKEN_ATTRIBUTES`.
3. Inserts the new access-token row as `ACTIVE`.
4. Posts a `postRefreshAccessToken` event (broadcasted state is `TOKEN_STATE_INACTIVE` — the event bus is unaware of the new DB state; this is an intentional simplification to avoid event-listener regressions).

Passing `oldTokenNewStateId = null` (reuse path) short-circuits step 1, preserving the grace deadline already written on first rotation.

### `getActiveAccessTokensByConsumerUserScopeBinding(...)`

Returns `List<AccessTokenDO>` for all tokens matching `(consumerKey, authorizedUser, userStoreDomain, scopeHash, tokenBindingRef, authorizedOrg)` filtered by:

```sql
TOKEN_STATE IN ('ACTIVE', 'GRACEFULLY_ROTATED')
```

Used by `revokeStaleSiblings` to detect whether any sibling with a later `issuedTime` already exists. Returns minimal columns: `ACCESS_TOKEN, TOKEN_ID, TIME_CREATED, REFRESH_TOKEN_TIME_CREATED, VALIDITY_PERIOD, REFRESH_TOKEN_VALIDITY_PERIOD`.

### `getAccessTokenExtendedAttributeValue(tokenId, attributeName)`

Single-attribute lookup from `IDN_OAUTH2_ACCESS_TOKEN_ATTRIBUTES`. Used for the race-guard read of `GRACEFUL_REFRESH_TOKEN_REUSE_COUNT` inside the synchronized write block.

---

## 10. SQL Surface

### New query constants in `SQLQueries.java`

| Constant | Operation | Notes |
|---|---|---|
| `UPDATE_REFRESH_TOKEN_VALIDITY_STATE_AND_STATE_ID` | UPDATE `IDN_OAUTH2_ACCESS_TOKEN` (sets `REFRESH_TOKEN_VALIDITY_PERIOD`, `TOKEN_STATE`, `TOKEN_STATE_ID` by `TOKEN_ID`) | Core mutation for first rotation |
| `UPDATE_ACCESS_TOKEN_VALIDITY_BY_TOKEN_ID` | UPDATE `IDN_OAUTH2_ACCESS_TOKEN` (`VALIDITY_PERIOD` by `TOKEN_ID`) | Currently unreferenced live (reserved — see §14) |
| `RETRIEVE_ACTIVE_ACCESS_TOKENS_BY_CONSUMER_USER_SCOPE_BINDING` | SELECT from `IDN_OAUTH2_ACCESS_TOKEN` with `TOKEN_STATE IN ('ACTIVE', 'GRACEFULLY_ROTATED')` | Sibling discovery; compatible across all 6 DB dialects |
| `UPDATE_OAUTH2_ACCESS_TOKEN_ATTRIBUTE_VALUE` | UPDATE on `IDN_OAUTH2_ACCESS_TOKEN_ATTRIBUTES` by `(TOKEN_ID, TOKEN_ATTR_NAME)` | Upsert step 1 |
| `GET_ACCESS_TOKEN_EXTENDED_ATTRIBUTE_VALUE` | SELECT `TOKEN_ATTR_VALUE` by `(TOKEN_ID, TOKEN_ATTR_NAME)` | Race-guard attribute read |
| `RefreshTokenSQLQueries.UPDATE_REFRESH_TOKEN_VALIDITY_PERIOD` | UPDATE on `IDN_OAUTH2_REFRESH_TOKEN` by `REFRESH_TOKEN_ID` | For the newer, separate refresh-token table variant |

### 12 new dialect-specific validation queries

Twelve constants (6 databases × 2 variants) were added to support `CONSENTED_TOKEN`-aware refresh-token validation. The naming follows the existing dialect-per-constant pattern:

```
RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_IDP_NAME_WITH_CONSENTED_TOKEN_{MYSQL,DB2SQL,ORACLE,MSSQL,POSTGRESQL,INFORMIX}
RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_WITH_EXTENDED_ATTRIBUTES_CONSENTED_{MYSQL,DB2SQL,ORACLE,MSSQL,POSTGRESQL,INFORMIX}
```

These are needed to project the `CONSENTED_TOKEN` column alongside the existing validation data. The `ORDER BY TIME_CREATED DESC, TOKEN_STATE LIMIT 1` tie-breaker is a **pre-existing pattern** already present in the non-consented MySQL variant before this feature — the new consented variants simply carry it over unchanged.

The tie-breaker is not related to graceful rotation. Because `renew_refresh_token = true` is required for graceful rotation, each rotation produces a new refresh token with a different hash — the old `GRACEFULLY_ROTATED` row and the new `ACTIVE` row have distinct `REFRESH_TOKEN_HASH` values and are never in competition in a single lookup. The `LIMIT 1` is a general safety measure for historical data where multiple rows with the same hash may exist (e.g., old INACTIVE rows from prior grant cycles).

`TokenManagementDAOImpl` routes to the appropriate dialect variant based on two feature flags: `isConsentedTokenColumnEnabled()` and `isAccessTokenExtendedTableExist()`.

---

## 11. Cross-DB Compatibility

The `IN ('ACTIVE', 'GRACEFULLY_ROTATED')` filter used in `RETRIEVE_ACTIVE_ACCESS_TOKENS_BY_CONSUMER_USER_SCOPE_BINDING` is standard SQL-92 and requires no dialect-specific handling. All six supported databases (MySQL, PostgreSQL, MSSQL, DB2, Oracle, H2) support:

- Subquery in `WHERE` clause — supported everywhere via JDBC
- `?` positional parameters — JDBC standard
- `IN (string-literal, string-literal)` — standard SQL-92

No per-dialect variant is needed for this query.

---

## 12. Security Considerations

| Concern | Mitigation |
|---|---|
| Unlimited reuse of rotated token | Reuse counter enforced server-side; hard cap = 5 |
| Unlimited grace window | Validity period sealed to 60 s server-side in `OAuthAppDAO` on write |
| Grace window extension via repeated replays | Grace deadline written once on first rotation; not recomputed on subsequent replays (pass `0L`/`null` to DAO) |
| Race condition on reuse limit (concurrent requests) | Fresh DB re-read of `reuseCount` inside synchronized write transaction; second throw if limit reached |
| Stale sibling tokens accumulating | `revokeStaleSiblings` revokes all other ACTIVE tokens in same `(client, user, scope, binding)` chain on every first rotation |
| Event-listener disruption | `postRefreshAccessToken` event broadcasts `TOKEN_STATE_INACTIVE`, preserving existing listener contracts; DB state carries `GRACEFULLY_ROTATED` independently |
| New state bypasses validation | `validateRefreshTokenReuseLimit` translates `GRACEFULLY_ROTATED → ACTIVE` in memory only, after enforcing the reuse limit — downstream validators see a clean `ACTIVE` state |

---

## 13. Backward Compatibility & Migration

- **No breaking change to existing apps.** The feature is disabled by default (`gracefulRefreshTokenRotationEnabled = false`). All apps that have not explicitly opted in continue on the existing `invalidateAndCreateNewAccessToken` path with no behavioral difference.
- **OIDC SP properties are optional.** The read path in `OAuthAppDAO` checks for property existence before parsing; missing properties default to `false`/`0`/`0` in Java, equivalent to feature-off.
- **Schema is additive.** The only schema change is the addition of `IDN_OAUTH2_ACCESS_TOKEN_ATTRIBUTES`. No columns are added to or removed from `IDN_OAUTH2_ACCESS_TOKEN`. The table is guarded by a feature flag (`OAuth2ServiceComponentHolder.isTokenExtendedTableExist()`), so deployments that have not run the migration script continue to function (the graceful-rotation path simply skips attribute persistence).
- **Event contracts preserved.** The `postRefreshAccessToken` event continues to broadcast `TOKEN_STATE_INACTIVE` rather than `TOKEN_STATE_GRACEFULLY_ROTATED`, ensuring existing event listeners require no changes.
- **Legacy DAO fallback.** The three new `AccessTokenDAO` interface methods have `default` implementations that fall through to the legacy `invalidateAndCreateNewAccessToken`. Deployments using a custom DAO extension will silently fall back.

---

## 14. Open Questions / Future Work

| Item | Detail |
|---|---|
| `GRACEFULLY_ROTATED` state in token-cleanup jobs | Scheduled jobs that scan `IDN_OAUTH2_ACCESS_TOKEN` for expired/inactive tokens may need to be updated to handle the `GRACEFULLY_ROTATED` state explicitly (e.g., treat it equivalently to INACTIVE for cleanup purposes). Currently not addressed. |
| Token-listing APIs | Admin or end-user token listing queries that filter by `TOKEN_STATE = 'ACTIVE'` will not surface GRACEFULLY_ROTATED tokens. Depending on product requirements, these may need to include the new state or exclude it intentionally. |
