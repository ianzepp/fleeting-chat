# Factory delivery: store-governed room safety

Status: active

Created: 2026-09-16

Owning repositories: `fleeting-chat`, `fleeting-chat-ios`

Future consumer: `fleeting-chat-android`

Release posture: defer release and deployment

## Interpreted Unit

Implement a no-login safety contract for rooms used by store-distributed clients. The contract must be enforced by the server for every participant and client in a governed room. Mobile clients expose consent, reporting, and blocking controls and refuse rooms whose advertised server guarantees are insufficient.

The work preserves unrestricted rooms for non-store clients. It does not introduce user accounts, email, phone numbers, passwords, real-world identity verification, deployment, or an Android repository.

Settled product decisions:

- Room safety is an immutable, versioned server contract, not a client label.
- The first governed profile is `store-v1` revision `1`.
- Existing and unspecified rooms are `unrestricted`; they are never silently promoted.
- Store clients create and join only compatible governed rooms and fail closed on absent, unknown, malformed, or insufficient capabilities.
- Stable identity is derived from the normalized Ed25519 public key. Nicknames and seat numbers are not moderation identities.
- User blocking is directional and server-enforced. Operator bans are a separate moderation action.
- A governed room cannot exist unless the server has an active content scanner. Missing scanner configuration makes governed-room creation fail closed.
- Reports retain the minimum encrypted evidence needed for moderation after ordinary room expiry. Default retention is seven days and remains bounded/configurable.
- Terms are versioned by the safety profile. Acceptance is local and no-login, but the server requires the accepted version before binding a governed seat.

## Normalized Spec

### Server contract

`store-v1` revision `1` guarantees:

1. Every message is scanned before it receives an ID, is stored, advances a cursor, or wakes a waiter.
2. Every message carries a stable pseudonymous author identifier derived from its public key.
3. Authenticated participants can report a message and its author.
4. Authenticated participants can block and unblock another stable identity within the room.
5. Poll/read results exclude messages authored by identities blocked by the requesting identity.
6. Operator moderation can inspect and resolve reports and apply or revoke room/global key bans through authority separate from participant bearers.
7. The room advertises its profile, revision, required terms version, and capabilities through preflight and all creation/join responses.
8. The profile cannot be mutated or downgraded after room creation.
9. Reports preserve bounded encrypted evidence independently of ordinary transcript and room expiry.

The initial scanner is deterministic and configured by the operator. The server exposes `store-v1` only when configuration produces an active scanner. Tests use injected rules. Production rules and deployment configuration are a later operational gate, not fabricated by this implementation.

### Client contract

The iOS client:

1. Requests `store-v1` when minting.
2. Preflights a code before joining or consuming a seat.
3. Refuses any room below its required profile/revision/capabilities.
4. Presents and records acceptance of the exact terms version before binding a governed seat.
5. Provides accessible Report, Block, and Unblock actions using stable author identity.
6. Handles filtered-message, blocked-participant, incompatible-room, report, and block errors without opening an unsafe session or losing a draft.

The future Android client consumes the same wire contract. Android-specific Play Console age controls and declarations remain outside this implementation.

## Repo-Aware Baseline

### `fleeting-chat`

- `src/store.ts` owns in-memory channels, seats, messages, expiry, and dirty-state persistence.
- `src/app.ts` owns reserve/create/join, bearer admission, send/poll, files, and public API responses.
- `src/auth.ts` already normalizes Ed25519 keys and owns token/challenge identity.
- `src/persist.ts` recreates SQLite on save and loads legacy JSON/SQLite; it currently lacks a general column-migration layer.
- Behavioral tests live in `test/auth.test.ts`; persistence tests in `test/persist.test.ts`; adversarial checks in `test/security.test.ts`.
- The repository is clean at base `ab1fe633803f4c352e305a4e86dcf442323f2289`.

### `fleeting-chat-ios`

- `Fleeting/Services/FleetingAPI.swift` and `Fleeting/Models/APIModels.swift` own the wire contract.
- `Fleeting/App/AppModel.swift` owns mint/join admission and must preflight before opening or remembering a room.
- `Fleeting/Services/RoomSession.swift` owns send/poll lifecycle and participant actions.
- `Fleeting/Views/TranscriptPane.swift` renders message actions; `RoomChrome.swift` and `HandoffPane.swift` render participant state.
- `RecentsStore`/`UserDefaults` can persist profile terms acceptance without accounts; Keychain continues to hold device identity and bearers.
- Tests use mock API clients and must move with protocol changes.
- The repository is clean at base `069776981261dbc668a57bd2e5eb7321f99405d2`.

## Stage Graph

```text
S0 durable contract
 ├─ S1 server profile + scanner + admission
 ├─ S2 server stable identity + directional blocks
 └─ S3 server reports + moderation persistence/authority
          │
          └─ S4 integrated server contract and docs
                    │
                    └─ I1 iOS wire models + preflight/terms
                              │
                              └─ I2 iOS report/block UX
                                        │
                                        └─ G1 cross-repo verification and review
```

S1–S3 may be implemented in parallel only when workers use disjoint new modules and tests. `src/app.ts`, `src/store.ts`, `src/persist.ts`, and shared test fixtures are integration-owned hot files and must be changed by one server integrator.

## Implementation Work

### S0 — durable contract

- Write scope: this document only.
- Done when: every admitted behavior, boundary, gate, and deferral is durable.
- Checkpoint: commit before product edits.

### S1 — safety profile and content scanner

- Repository: `fleeting-chat`.
- Primary edit: new safety-profile/scanner module plus server-integrator wiring.
- Behavior:
  - strict parse of `unrestricted` and `store-v1` revision `1`;
  - preflight endpoint that does not bind a seat;
  - immutable profile on reserve/create;
  - profile/capabilities/terms echoed from reserve/create/join;
  - governed creation fails when the scanner is unavailable;
  - governed send scans before mutation and returns `content_rejected` on denial.
- Done when: unknown profiles and downgrade attempts fail; rejected content produces no message, cursor, waiter wakeup, or persisted row.

### S2 — stable participant identity and directional blocks

- Repository: `fleeting-chat`.
- Primary edit: public-key fingerprint helper and room block model/API.
- Behavior:
  - stable opaque author ID on new messages and responses;
  - authenticated block/unblock endpoints accept opaque author identity, never nick or seat;
  - server filters reads and long-poll delivery per requesting identity;
  - blocked state persists across token refresh, rejoin, restart, and client changes;
  - operator bans remain distinct and may prevent admission/send/read.
- Done when: a blocked identity remains blocked under a new bearer while unrelated participants and unrestricted rooms behave unchanged.

### S3 — reports and moderator authority

- Repository: `fleeting-chat`.
- Primary edit: report model/store, encrypted persistence, and operator-only routes.
- Behavior:
  - report endpoint captures bounded reason plus immutable message/author evidence;
  - report survives transcript eviction and room expiry until its own bounded expiry;
  - encrypted rooms never persist plaintext report bodies;
  - operator routes require a separately configured moderation credential;
  - normal participant and agent bearers cannot access moderation routes;
  - resolve/dismiss and operator ban/unban actions are recorded.
- Done when: persistence round trips, expiry purges reports, and adversarial authorization tests pass.

### S4 — server integration and public contract

- Repository: `fleeting-chat`.
- Write scope: hot files, migrations, fixtures, `llms.txt`, README/API documentation.
- Done when: S1–S3 are wired atomically, legacy data loads as unrestricted, API docs match live routes, and the full server suite/typecheck pass.

### I1 — iOS admission and terms

- Repository: `fleeting-chat-ios`.
- Primary edit: wire safety models, preflight, required-profile policy, and local terms-version acceptance.
- Behavior:
  - mint requests `store-v1`;
  - join preflights before bind;
  - incompatible rooms never save a token, create a recent, or open a session;
  - exact terms version is accepted before first governed bind and re-presented when it changes;
  - unknown or incomplete capability responses fail closed.
- Done when: focused tests prove compatible mint/join and every mismatch path.

### I2 — iOS report/block UX

- Repository: `fleeting-chat-ios`.
- Primary edit: message/participant actions and session API calls.
- Behavior:
  - accessible, clearly labeled Report and Block actions;
  - explicit confirmation and result/error state;
  - block targets stable author identity and updates the transcript from authoritative server results;
  - unblock is available;
  - rejected sends retain the draft and explain the rejection.
- Done when: unit/view-model tests cover action payloads, failures, and local state transitions; manual simulator inspection confirms reachable controls.

### G1 — integration, review, and checkpoint

- Run server and iOS full suites and builds.
- Review changed tests for weakening.
- Verify public contracts agree field-for-field.
- Run a local two-identity governed-room integration test without production mutation.
- Commit coherent phases in each repository.
- Record deployment and Android implementation as deferred release work.

## Checkpoints And Gates

1. **Contract gate:** S0 committed before implementation.
2. **Migration gate:** legacy SQLite and JSON load as `unrestricted`; no destructive reset or silent promotion.
3. **Enforcement gate:** direct API clients cannot bypass scanner or blocks.
4. **Evidence gate:** reports remain encrypted and bounded; ordinary rooms retain their current expiry behavior.
5. **Admission gate:** store clients fail before binding on insufficient profile/capabilities/terms.
6. **Compatibility gate:** existing callers remain unrestricted unless they explicitly request `store-v1`.
7. **Review gate:** no P0/P1 correctness finding, no weakened test, and no unreviewed persistence/auth boundary.
8. **External-effect gate:** do not deploy, create production reports, configure production moderation secrets, or submit either app.

## Validation

### Server

```bash
npm run typecheck
npm test
```

Add focused tests for profile parsing/admission, scanner non-mutation, preflight, stable identity, directional block filtering, restart/rejoin, report evidence/expiry/encryption, moderator authorization, migration, and unrestricted regressions.

### iOS

```bash
xcodebuild -project Fleeting.xcodeproj -scheme Fleeting \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
  CODE_SIGNING_ALLOWED=NO test
xcodebuild -project Fleeting.xcodeproj -scheme Fleeting -configuration Release \
  -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
```

Add focused tests for fail-closed preflight, terms revision, mint/join requests, rejected send draft retention, report/block payloads, and authoritative transcript refresh.

### Cross-repository

- Compare JSON keys and error codes between TypeScript responses and Swift Codable models.
- Exercise governed reserve → preflight → terms-bearing join → send/filter → report → block → poll with fresh local identities.
- Confirm unrestricted room behavior is unchanged.

## Companion Skill Plan

- `correctness`: auth, persistence, expiry, filtering-before-mutation, and lifecycle review.
- `auditor`: independent frozen-range review after integration.
- `zombie-docs`: verify `llms.txt`, README, and Apple-readiness claims against implemented routes.
- `housekeeping`: formatter/typecheck/build only after behavioral gates are green.

## Open Questions

No question blocks local implementation. The following remain explicit release gates:

- Production scanner implementation/rules and operational ownership.
- Production moderator credential provisioning and rotation.
- Final Terms of Use, privacy policy, community standards, support contacts, and legal review.
- Production report-retention value if different from the seven-day default.
- Google Play classification, age restriction, and child-safety declarations at Android release time.
- Deployment sequence and backward-compatible rollout across public clients.

This factory run does not resolve legal compliance by code alone and does not claim App Store or Play approval.

## Execution Record

Status: implementation complete; production rollout and store submission remain deferred.

Completed on 2026-09-16:

- S1-S4: server profile admission, pre-storage scanning, canonical public-key identity, directional blocks and recovery inventory, retained encrypted reports, separate moderator authority, persistence, migration, and public API documentation.
- I1-I2: iOS fail-closed preflight and terms acceptance, governed mint/join, report/block/unblock actions, authoritative block recovery, rejected-draft retention, and stale-poll protection.
- G1: TypeScript typecheck, 98 server tests, 50 iOS tests, unsigned iOS Release build, field/error/path comparison, and local two-identity governed-room integration coverage in `test/safety.test.ts`.

Implementation commits:

- `f28d6e6` — Add store-governed room safety.
- `3e8e8c6` — Close governed safety audit findings.
- iOS `5b715c8` — Require governed safety for iOS rooms.
- iOS `5a9e89d` — Make block recovery authoritative.
- iOS `36c7e6a` — Stop retrying terminal safety failures.

Independent frozen-range audits initially found canonical-key, persisted-profile downgrade, durable-unblock, stale-poll, and terminal-retry defects. Each received a regression test and a follow-up commit. Final server and iOS audits returned `clean_pass` with no P0-P2 findings.

No deployment, production configuration, production moderation action, external test, or store submission occurred. Production scanner ownership/rules, moderator-secret operations, final legal/support documents, retention policy approval, live rollout, physical-device testing, and store-console work remain release gates.
