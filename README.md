# PassKeyValue

PassKeyValue is a Vapor app that combines WebAuthn passkey authentication with per-user key/value storage.

It includes:
- passkey registration and sign-in flows
- passkey management (list/delete)
- account merge flow using a second passkey
- authenticated KV CRUD endpoints
- Leaf views for quick manual testing

## Quick Start

1. Create your local env file:
   ```bash
   cp .env.example .env
   ```
2. Start the server:
   ```bash
   swift run
   ```
3. Open:
   - `http://localhost:8080`

## Runtime Configuration

Environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SQLITE_DATABASE_PATH` | `db.sqlite` | SQLite file path |
| `RP_ID` | `localhost` | WebAuthn relying party ID |
| `RP_ORIGIN` | `http://localhost:8080` | WebAuthn relying party origin |
| `RP_DISPLAY_NAME` | `Vapor Passkey Demo` | Display name shown in authenticators |
| `APPLE_APP_IDENTIFIER` | `com.example.app` | Enables `/.well-known/apple-app-site-association` response |

## Endpoint Reference (Latest)

All routes are currently registered in `Sources/App/routes.swift` via:
- `TestViewController`
- `PasskeyController`
- `KVController`
- `WellKnownController`

### UI and Session Routes

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/` | No | Home page. If already signed in, redirects to `/private`. |
| `GET` | `/private` | Yes | Private page with passkey management actions. |
| `GET` | `/kv` | Yes | KV manager UI page. |
| `POST` | `/logout` | Yes | Clears session and redirects to `/`. |

### Passkey API

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `POST` | `/begin` | Optional | Starts `registration` or `authentication`. Returns WebAuthn options. |
| `POST` | `/continue` | Optional/Contextual | Completes the started passkey flow and logs in the user when successful. |
| `GET` | `/passkeys` | Yes | Lists passkeys for current session user. |
| `DELETE` | `/passkeys/:credentialID` | Yes | Deletes one passkey (cannot delete the last remaining passkey). |

`/begin` request body:

```json
{
  "stage": "registration",
  "isMerging": false,
  "passkeyName": "My Passkey"
}
```

- `stage`: `registration` or `authentication`
- `isMerging`: whether flow is part of merge workflow
- `passkeyName`: required for registration

`/continue` request body (registration):

```json
{
  "credential": { "...": "RegistrationCredential payload" },
  "passkeyName": "My Passkey"
}
```

`/continue` request body (authentication):

```json
{
  "credential": { "...": "AuthenticationCredential payload" },
  "mergeMode": "keepCurrentUser"
}
```

- `mergeMode` is optional and only used in merge flow.
- allowed values: `keepCurrentUser`, `keepProvidedUser`

`/continue` response includes:
- `status`: one of `registered`, `authenticated`, `merged`
- `userID`
- `passkeys`: current passkey list for the signed-in user

### KV API

All KV routes require an authenticated session.

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/kv` | List all KV entries |
| `GET` | `/api/kv/:key` | Fetch one KV entry |
| `POST` | `/api/kv/:key` | Upsert one KV entry |
| `DELETE` | `/api/kv/:key` | Delete one KV entry |

Upsert request body:

```json
{
  "value": "some string value"
}
```

Response shapes:
- list: `{ "items": [{ "key": "...", "value": "..." }] }`
- get: `{ "item": { "key": "...", "value": "..." } }`
- upsert: `{ "item": { "key": "...", "value": "..." } }`
- delete: `{ "deletedKey": "...", "present": { "remainingKey": "value" } }`

### Well-Known Route

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/.well-known/apple-app-site-association` | Returns Apple association JSON when `APPLE_APP_IDENTIFIER` is set; otherwise `404`. |

## Notes on Auth and API Clients

- Session auth is cookie-based (`Fluent` session backend).
- Session key is set to "passkv_session" by default.
- For non-browser clients, preserve and resend cookies between requests for authenticated routes.
- WebAuthn payloads are expected in the JSON shapes produced by browser WebAuthn APIs.

## Development

Run tests:

```bash
swift test
```

Rebuild Tailwind CSS during UI work:

```bash
./tailwindcss -i Resources/Utils/styles.css -o Public/styles/tailwind.css --watch
```

Do not edit `Public/styles/tailwind.css` manually.

## Documentation

DocC catalog:
- `Sources/App/App.docc/App.md`

Generate static docs (if your toolchain supports it):

```bash
swift package --allow-writing-to-directory ./docs \
  generate-documentation --target App \
  --output-path ./docs
```
