# Spec–Code Reconciliation Plan
date: 2026-05-19
branch: feat/local-port-forwarding

---

## Changelog

### iter 1 → iter 2 (2026-05-19)

- **D-04 extended:** added `line` to the proposed integer-field list (emitted by `PubkeyParseError` and `PubkeyOptionIgnored`).
- **D-05 extended:** audited every `strField(` call in `logging.go`; the proposed string-field list now covers all missing fields: `method`, `dest_host`, `originator_host`, `path`, `option`, `error` (in addition to `auth_methods`).
- **OQ-3 rewritten:** removed the false claim that §9 was found accurate; the entry now honestly states §9 type tables are incomplete and points to D-04/D-05.
- **D-07 prose tightened:** clarified that `ok := userOK && keyOK` lives in `internal/server/auth.go`, not inside the `credentials` or `pubkey` packages; updated proposed spec wording to name the correct package boundary.

---

## Summary

A full audit of §2–§13 against the implementation found **9 drift items, all SPEC UPDATE**.
No code bugs were identified. The code's behavior is correct throughout; the spec text has
stale examples, missing fields in the type table, one dangling cross-reference, and two
imprecise prose descriptions.

---

## Drift inventory

### D-01 — §9 examples: `auth-ok` missing `method` field

| Field | Value |
|---|---|
| Location | §9 example block, logfmt line ~478 and JSON line ~490 |
| Spec says | `auth-ok remote=… user=alice` (logfmt); `{"event":"auth-ok","remote":"…","user":"alice"}` (JSON) |
| Code does | `logging.go:AuthOK` correctly emits `method=password` (or `method=publickey`) |
| Disposition | **SPEC UPDATE** — the field is already in the §9 event table; only the examples lag behind |
| Proposed change | Add `method=password` to the logfmt example; add `"method":"password"` to the JSON example |

---

### D-02 — §9 examples: `auth-fail` missing `method` field

| Field | Value |
|---|---|
| Location | §9 example block, logfmt line ~483 and JSON line ~492 |
| Spec says | `auth-fail remote=… user=alice reason=…` with no method field |
| Code does | `logging.go:AuthFail` correctly emits `method=password` (or `method=publickey`) |
| Disposition | **SPEC UPDATE** — same pattern as D-01 |
| Proposed change | Add `method=password` to both the logfmt and JSON auth-fail examples |

---

### D-03 — §9 examples: `listening` missing `auth_methods` and `pubkey_count`

| Field | Value |
|---|---|
| Location | §9 example block, logfmt line ~477 and JSON line ~488 |
| Spec says | `listening bind=0.0.0.0 port=2222 fingerprint=SHA256:… user=alice pid=4711` |
| Code does | `logging.go:Listening` emits two additional fields: `auth_methods=password` and `pubkey_count=0` (or `auth_methods=password,publickey pubkey_count=N`) |
| Disposition | **SPEC UPDATE** — these fields were added during the pubkey-auth PR and the examples were not updated |
| Proposed change | Update both examples to append `auth_methods=password pubkey_count=0` (logfmt) and `"auth_methods":"password","pubkey_count":0` (JSON) |

---

### D-04 — §9 JSON type table: incomplete integer field list

| Field | Value |
|---|---|
| Location | §9 type table preamble, line ~444 |
| Spec says | JSON integer fields: `port, pid, attempt, pgid, bytes_dropped` |
| Code does | `logging.go` also emits as integer (via `intField` / inline `fieldInt` literals): `bytes_in`, `bytes_out`, `dest_port`, `originator_port`, `pubkey_count`, `line` |
| Disposition | **SPEC UPDATE** — fields added during the JSON-logging, pubkey, and port-forwarding PRs were not back-filled into the table; `line` is emitted by `PubkeyParseError` and `PubkeyOptionIgnored` |
| Proposed change | Extend the integer list to: `port, pid, attempt, pgid, bytes_dropped, bytes_in, bytes_out, dest_port, originator_port, pubkey_count, line` |

---

### D-05 — §9 JSON type table: multiple string fields not listed

| Field | Value |
|---|---|
| Location | §9 type table preamble, line ~441–443 |
| Spec says | String fields: `bind`, `fingerprint`, `user`, `remote`, `reason`, `kind`, `what`, `sig`, `message` |
| Code does | `logging.go` also emits as string (via `strField`): `auth_methods`, `method`, `dest_host`, `originator_host`, `path`, `option`, `error` |
| Disposition | **SPEC UPDATE** — full audit of every `strField(` call in `logging.go` reveals seven fields absent from the §9 type table; these were introduced across the pubkey-auth, SFTP/path, and port-forwarding PRs |
| Proposed change | Extend the string field list to cover all fourteen fields: `bind`, `fingerprint`, `user`, `remote`, `reason`, `kind`, `what`, `sig`, `message`, `auth_methods`, `method`, `dest_host`, `originator_host`, `path`, `option`, `error`; note that `auth_methods` is a comma-separated list (e.g. `"password,publickey"`) |

---

### D-06 — §4 dangling `§6.1` cross-reference

| Field | Value |
|---|---|
| Location | §4 publickey authentication, step 1, line ~173 |
| Spec says | "the authorized-keys file (§2 step 2c, see also §6.1)" |
| Code does | §6 covers host-key management and has no subsections; §6.1 does not exist |
| Disposition | **SPEC UPDATE** — stale reference from a draft revision |
| Proposed change | Change "§6.1" → "§6" |

---

### D-07 — §4 publickey step 3: "bitwise AND of the two int results" imprecise

| Field | Value |
|---|---|
| Location | §4 publickey authentication, step 3 |
| Spec says | "the combined ok is the bitwise AND of the two int results from `CheckUsername` and `Check`" |
| Code does | `internal/server/auth.go:publickeyCallback` materializes both results onto separate bool variables on separate lines (`userOK := creds.CheckUsername(…)`, `keyOK, … := source.Current().Check(…)`), then combines with `ok := userOK && keyOK` — both calls complete before the combining expression. The constant-time work happens inside `credentials.go:checkUsernameWith` (subtle.ConstantTimeCompare) and `pubkey.go:Keyset.Check` respectively; the `&&` at the callback layer is safe only because both calls are pre-materialized. |
| Disposition | **SPEC UPDATE** — the security invariant is preserved; the spec prose mis-describes where the combining step occurs (it's in `internal/server/auth.go`, not inside the auth/pubkey packages themselves) |
| Proposed change | Revise step 3 to say: both `CheckUsername` and `Check` are called and their results captured in separate variables before any combination; the combining expression `ok := userOK && keyOK` lives in `internal/server/auth.go` and is safe to use `&&` only because both calls have already completed; the constant-time guarantee is enforced inside each called function |

---

### D-08 — §8 drain-timeout: spec implies actual dropped-byte count; code always logs 0

| Field | Value |
|---|---|
| Location | §8.1 step 5 / §8.2 step 4; §9 `drain-timeout` event row |
| Spec says | "logged with the number of dropped bytes" |
| Code does | `session/service.go:drain()` always passes `bytesDropped=0` to `log.DrainTimeout`; code comment: "do not have a cheap way to count" — the channel pipe has already been handed to io.Copy goroutines and there is no practical interception point |
| Disposition | **SPEC UPDATE** — counting unread bytes on a live goroutine-driven io.Copy is impractical; the field is always 0 when the session-level drain fires |
| Proposed change | Update §8 and the §9 `drain-timeout` event description to note that `bytes_dropped` reflects unread bytes remaining in the channel buffer at the time the drain fires, and that the current implementation always reports 0 because exact counting would require wrapping the io.Copy path |

---

### D-09 — §13.6 `make test-race` description vs Makefile `-short` flag

| Field | Value |
|---|---|
| Location | §13.6 make targets table; Makefile `test-race` target |
| Spec says | `make test-race   # unit + integration under -race` (no mention of `-short`) |
| Code does | `$(GO) test -short -race ./...` — applies `-short` to skip the 16-second exponential-backoff integration test under race, which would be prohibitively slow |
| Disposition | **SPEC UPDATE** (preferred) or CODE UPDATE (if the intent was to cover slow tests under race) — see Open questions |
| Proposed change (preferred) | Update §13.6 description to `make test-race   # unit + integration under -race (-short skips slow timing-dependent tests)` |

---

## Code change set

**None.** All 9 drift items are documentation/spec inaccuracies. The implementation is
correct. No code changes are required.

---

## Spec change set

All changes are in `docs/specs/00-minisshd-spec.md`.

| # | Section | Change |
|---|---|---|
| D-01 | §9 logfmt + JSON examples | Add `method=password` / `"method":"password"` to auth-ok examples |
| D-02 | §9 logfmt + JSON examples | Add `method=password` / `"method":"password"` to auth-fail examples |
| D-03 | §9 logfmt + JSON examples | Add `auth_methods=password pubkey_count=0` to listening examples |
| D-04 | §9 type table | Extend integer field list with `bytes_in, bytes_out, dest_port, originator_port, pubkey_count, line` |
| D-05 | §9 type table | Add `auth_methods`, `method`, `dest_host`, `originator_host`, `path`, `option`, `error` (string) to the string field list; note `auth_methods` is comma-separated |
| D-06 | §4 step 1 | Change "§6.1" → "§6" |
| D-07 | §4 step 3 | Clarify bitwise-AND requirement applies inside the auth package; outer callback may use `&&` after both calls are materialized |
| D-08 | §8.1/§8.2 + §9 drain-timeout | Note that `bytes_dropped` is always 0 in the current implementation; exact count is impractical |
| D-09 | §13.6 | Add `-short` caveat to `make test-race` description (or resolve via CODE UPDATE per open question) |

---

## Tests

No new tests are required. All drift items are spec documentation corrections.

If D-09 is resolved as a CODE UPDATE (remove `-short` from `test-race`), verify that
`make test-race` completes in CI within the runner time budget — the
`TestRateLimitBackoff*` integration tests take ~16 s per run, which under `-race` will
be roughly the same wall time since the timing test uses `time.Sleep` and is not
CPU-bound.

---

## Definition of done

- [ ] All 9 spec edits applied to `docs/specs/00-minisshd-spec.md`
- [ ] D-09 disposition confirmed (SPEC UPDATE or CODE UPDATE) and applied
- [ ] `gofmt -l .` prints nothing (no Go files changed, so this is trivially satisfied)
- [ ] `go vet ./...` clean (no Go files changed)
- [ ] `make test` passes
- [ ] PR opened, `copilot-pull-request-reviewer` requested

---

## Open questions / risks

**OQ-1 (D-09): Should `make test-race` run slow tests?**

The `-short` flag on `test-race` was added deliberately to keep CI fast; the slow
integration tests (exponential-backoff, 16 s) are already covered by `make test-slow`
and `make coverage`. The spec comment does not mention `-short`, which may mislead
contributors into thinking race detection covers the slow paths. Options:

- **Option A (preferred):** Update §13.6 to document the `-short` flag explicitly.
- **Option B:** Add a separate `test-race-slow` target and note it in §13.6.
- **Option C:** Remove `-short` from `test-race` and accept slower CI.

Recommend Option A unless the project wants full slow-path race coverage on demand.

**OQ-2 (D-08): Should `bytes_dropped` ever be accurate?**

If future work wraps the io.Copy goroutines with a counting reader/writer, `drain-timeout`
could report real bytes. For now the field is a placeholder. The spec note proposed in
D-08 should clearly say this is a known limitation so contributors do not add a regression
test for a non-zero value.

**OQ-3: §9 type tables (integer and string) are incomplete — addressed by D-04 and D-05**

The §9 JSON type table was found to be incomplete, not accurate. D-04 enumerates six
integer fields missing from the spec (`bytes_in`, `bytes_out`, `dest_port`,
`originator_port`, `pubkey_count`, `line`). D-05 enumerates seven string fields missing
from the spec (`auth_methods`, `method`, `dest_host`, `originator_host`, `path`,
`option`, `error`). Both entries carry SPEC UPDATE dispositions and are included in the
change set above. Sections §2, §3, §5, §6, §10, §11, and §12 were checked and found
accurate.

---

## Adversarial review responses (iter 1)

### D-04 incomplete — `line` missing from integer-field list

**Disposition: AGREE — fixed.**

Grepped `logging.go` for all `intField(` and inline `fieldInt` literal calls. Confirmed
`line` is emitted as an integer by both `PubkeyParseError` (line 312) and
`PubkeyOptionIgnored` (line 322). Added `line` to the proposed integer list in D-04 and
to the Spec change set table.

Complete proposed integer-field list after fix:
`port`, `pid`, `attempt`, `pgid`, `bytes_dropped`, `bytes_in`, `bytes_out`, `dest_port`, `originator_port`, `pubkey_count`, `line`

---

### D-05 incomplete — only `auth_methods` added to string-field list

**Disposition: AGREE — fixed comprehensively.**

Audited every `strField(` call in `logging.go`. Fields present in code but absent from
the prior D-05 entry: `method`, `dest_host`, `originator_host`, `path`, `option`,
`error`. All seven missing string fields are now enumerated in D-05. The Spec change set
table and proposed spec wording have been updated accordingly.

Complete proposed string-field list after fix:
`bind`, `fingerprint`, `user`, `remote`, `reason`, `kind`, `what`, `sig`, `message`,
`auth_methods`, `method`, `dest_host`, `originator_host`, `path`, `option`, `error`

---

### OQ-3 contradicts D-04/D-05

**Disposition: AGREE — rewritten.**

The original OQ-3 text claimed §9 was found accurate. That was directly contradicted by
the existence of D-04 and D-05 in the same document. OQ-3 has been rewritten to state
the truth: §9 type tables are incomplete, and D-04/D-05 enumerate the missing fields.
The accurate-sections claim (§2, §3, §5, §6, §10, §11, §12) is retained.

---

### D-07 — "bitwise AND happens inside credentials.go and pubkey.go" misrepresents location

**Disposition: AGREE — prose tightened.**

Verified in `internal/server/auth.go` lines 137–140: `userOK` and `keyOK` are captured
on separate lines before `ok := userOK && keyOK`. The constant-time operations occur
inside `checkUsernameWith` (credentials package) and `Keyset.Check` (pubkey package);
the combining `&&` is in `internal/server/auth.go`. Updated D-07's "Code does" and
"Proposed change" rows to name the correct file and accurately describe the package
boundary, without weakening the security invariant statement.
