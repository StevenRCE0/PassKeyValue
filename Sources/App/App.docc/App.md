# ``App``

PassKeyValue is a Vapor server that combines passkey-based authentication (WebAuthn) with per-user key/value storage.

## Overview

The executable target boots in ``Entrypoint`` and configures the server in ``configure(_:)``.

At startup, the app:

- configures CORS and static file middleware
- enables Fluent-backed sessions
- configures SQLite
- runs migrations
- starts in-process queues and scheduled jobs
- configures WebAuthn relying-party settings
- registers routes

## Components

- ``PasskeyController`` handles passkey registration, authentication, listing, deletion, and account-merge flows.
- ``KVController`` provides authenticated CRUD endpoints for user storage.
- ``WellKnownController`` serves Apple association metadata from `/.well-known/apple-app-site-association`.
- ``User`` stores username, timestamps, and a string-based key/value dictionary.
- ``WebAuthnCredential`` stores passkey credentials and sign counters.

## API Surface

### Passkey API

- `POST /begin`
  - Starts either `registration` or `authentication` using ``BeginPasskeyRequest``.
  - Returns ``BeginPasskeyResponse`` with either creation options or request options.
- `POST /continue`
  - Completes the passkey flow using credential payloads.
  - Returns ``ContinuePasskeyResponse`` with status and current passkeys.
- `GET /passkeys`
  - Lists passkeys for the authenticated session user.
- `DELETE /passkeys/:credentialID`
  - Deletes one passkey, while preventing deletion of the last passkey.

### Key/Value API

All KV routes require an authenticated user session.

- `GET /api/kv` returns all keys (`KVListResponse`)
- `GET /api/kv/:key` returns one key (`KVGetResponse`)
- `POST /api/kv/:key` upserts key from ``KVUpsertRequest``
- `DELETE /api/kv/:key` removes key and returns ``KVDeleteResponse``

## Data Model

The app applies these migrations:

- ``CreateUser`` creates `users`
- ``CreateWebAuthnCredential`` creates `webauth_credentals`
- queue/session migrations are also registered during configure

## Runtime Configuration

Environment variables used by the app:

- `SQLITE_DATABASE_PATH` (default: `db.sqlite`)
- `RP_ID` (default: `localhost`)
- `RP_DISPLAY_NAME` (default: `Vapor Passkey Demo`)
- `RP_ORIGIN` (default: `http://localhost:8080`)
- `APPLE_APP_IDENTIFIER` (optional, enables `/.well-known` response)

## Local Run

```bash
swift run
```

Then visit `http://localhost:8080`.

## Generating Documentation

If you have the Swift DocC plugin available in your package/toolchain, generate docs for this target with:

```bash
swift package --allow-writing-to-directory ./docs \
  generate-documentation --target App \
  --output-path ./docs
```
