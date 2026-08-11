# AGENTS.md

Guidance for AI agents working in this repository.

## What this is

`exonet/securemessage` is a framework-agnostic PHP library (with an optional
Laravel integration) for encrypting messages using libsodium secretbox. The
32-byte encryption key is deliberately split into three parts stored in
different places, so a single compromised store never yields a complete key:

- **database key** — 11 random bytes, stored in a database.
- **storage key** — 11 random bytes, stored on a disk/filesystem.
- **verification code** — 10 characters, never stored; sent to the recipient.

The message meta data (expiry timestamp, remaining "hit points" = allowed
failed decrypt attempts) is encrypted separately with a **meta key**: an
application-wide 10-character key concatenated with the database and storage
keys (10 + 11 + 11 = 32 bytes).

## Layout

- `src/Crypto.php` — sodium encrypt/decrypt, hit-point reduction, key validation.
- `src/Factory.php` — creates messages, generates the three key parts.
- `src/SecureMessage.php` — value object holding content, keys and meta; has
  `wipe*FromMemory()` methods built on `sodium_memzero()`.
- `src/Exceptions/` — all extend `SecureMessageException`; `ExpiredException`
  and `HitPointLimitReachedException` extend `DecryptException`.
- `src/Laravel/` — service provider, facade, Eloquent model + migration,
  config, events and the `secure_message:housekeeping` command. Persists the
  storage key via a Laravel filesystem disk and the rest in the database, each
  wrapped in Laravel's own `Encrypter` as a second layer.
- `tests/` — PHPUnit tests for the core library; `tests/Laravel/` — tests for
  the Laravel integration, running on orchestra/testbench (in-memory sqlite).
- `docs/` — usage documentation and a runnable example.

## Commands

- `composer test` — runs the whole suite (testsuites `Core` and `Laravel`,
  PHPUnit 11). Requires PHP with the `sodium` extension (available locally).
- `composer analyse` — PHPStan level 6 (with larastan and phpstan-mockery),
  configured in `phpstan.neon.dist`. Keep it clean.
- Code style is enforced by php-cs-fixer using `.php-cs-fixer.php`
  (`@PSR2` + `@Symfony` + `@PhpCsFixer` plus overrides, including
  `declare_strict_types`). CI runs it on every PR **and auto-commits the
  fixes to the PR branch**, so don't be surprised by extra commits; running
  the fixer locally before pushing avoids them.

## Constraints and gotchas

- **PHP compatibility: `^8.2`** (v2). CI tests 8.2, 8.3 and 8.4, against both
  Laravel 12 (testbench `^10.0`) and Laravel 13 (testbench `^11.0`). Typed
  properties, promotion, readonly and match are in use; typed class constants
  are NOT (8.3+ feature).
- **Everything is `declare(strict_types=1)`.** When adding code paths, mind
  implicit coercions that no longer happen (e.g. `SecureMessage::setMeta()`
  deliberately casts `hit_points`/`expires_at` to int for this reason).
- **No production dependencies** other than `php` and `ext-sodium`. The
  Laravel classes reference `illuminate/*` and `nesbot/carbon`, which resolve
  via orchestra/testbench in dev and via the host app in production. Don't
  add them to `require`.
- **`sodium_memzero()` nulls its by-reference argument.** Every property that
  gets wiped in `SecureMessage::wipe*FromMemory()` must stay nullable
  (`?string = null`) and must never be `readonly`, or wiping throws a
  `TypeError` in the security-critical path.
- **Don't add native types to inherited Laravel properties** (`$table`,
  `$incrementing`, `$keyType`, `$signature`, `$description`) — the parents
  declare them untyped, so typing them is a fatal error.
- **The migration filename must never change.** Laravel records migrations by
  filename; renaming re-runs it and crashes existing installs.
- **Key lengths are load-bearing.** `Factory::setMetaKey()` requires exactly
  10 characters; `Crypto` requires the *combined* keys to be exactly 32 bytes
  (11-byte database key + 11-byte storage key + 10-char verification code).
- **Security invariants — preserve them when touching `Crypto`/`SecureMessage`:**
  nonces are randomly generated per encryption and never reused; failed or
  invalid decrypt attempts must keep reducing hit points (this is the
  brute-force protection); plaintext, keys and decrypted meta are wiped with
  `sodium_memzero()` after use. Don't weaken or reorder these paths.
- Changing the encrypted wire format (`Crypto::toString()`/`fromString()`:
  base64 of a JSON array of base64 nonce + ciphertext) breaks decryption of
  all previously stored messages — treat it as a breaking change.

## Conventions

- Every method has a full PHPDoc block (`@param`/`@throws`/`@return` with
  descriptions) — match this style; php-cs-fixer enforces the ordering.
- Setters return `$this` (fluent); properties are `private` with getters/setters.
- Follow SemVer. PRs need tests, documentation updates for behaviour changes,
  and **exactly the labels CI expects** (`bugfix`, `new-feature`,
  `breaking-change`, `enhancement`, `documentation`, `dependencies`,
  `maintenance`, `ci`, …) — the `verify-pr-labels` workflow blocks unlabeled
  PRs, and release-drafter builds the changelog and version bump from labels.
- Security issues go to development@exonet.nl, never the public issue tracker.
