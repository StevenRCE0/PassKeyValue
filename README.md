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
| `APN_HANDLE_SECRET` | none | 32-byte-plus secret used to seal opaque APN wake handles |
| `APN_KEY_ID` | none | Apple APNs auth key ID |
| `APN_TEAM_ID` | none | Apple Developer team ID |
| `APN_PRIVATE_KEY_PATH` | none | Preferred filesystem path to `AuthKey_<KEYID>.p8` |
| `APN_PRIVATE_KEY_PEM` | none | Fallback inline PEM for the APNs auth key |
| `APPLE_APP_IDENTIFIER` | `com.example.app` | Enables `/.well-known/apple-app-site-association` response |
| `THIRD_PARTY_SIGNING_KEY` | none | PEM P-256 private key that signs third-party assertions; also publishes `/.well-known/jwks.json` |
| `FIRST_PARTY_DOMAINS` | none | Comma-separated domains whose apps are this instance's own, e.g. `keeptalking.dev` (subdomains included) |

### Third-party access

PassKeyValue is an OAuth 2.0 authorisation server for any service: the
authorisation code flow with PKCE (`S256`), one grant per device. There is
no list of services to configure. A service's `client_id` is the https URL
of a JSON document it hosts:

```json
{
  "client_id": "https://service.example/passkv/client.json",
  "client_name": "Example",
  "redirect_uris": ["example://authorized"],
  "scope_descriptions": {"notes:read": "Read your notes"},
  "revocation_notice_uri": "https://service.example/passkv/revocations"
}
```

`client_id` must match the URL, the redirect URI must be listed, every
requested scope must be described (PassKeyValue describes its own `kv`
scopes), and the revocation URL must be on the same host. The consent page
shows the service's name and domain; the grant keeps what the user approved.

An instance belongs to whoever hosts it, and apps on `FIRST_PARTY_DOMAINS`
are its own. Skipping consent depends on how the answer comes back, not only
on the domain: an allowlisted app that answers the passkey challenge natively
(the Authorization Challenge Endpoint, which needs the app in
`webcredentials`) gets no consent page, because the OS hands the result straight back to it. On the web page
an allowlisted app still asks, with every scope required, since any program
on the device could have started that request. Every other app gets the consent page, where shared data is
optional. Either way, an app gets a scoped grant it can lose, never a
session.

First-party apps follow the Authorization Challenge Endpoint of
[OAuth 2.0 for First-Party Applications](https://datatracker.ietf.org/doc/draft-ietf-oauth-first-party-apps/),
a form `POST /oauth/authorize-challenge` made in steps:

1. `client_id`, `scope`, `code_challenge`, `code_challenge_method=S256`:
   answered with `insufficient_authorization`, an `auth_session` and a
   `passkey` request.
2. `auth_session` and `passkey` (the assertion as JSON): answered with
   `authorization_code`, traded at `/oauth/token` without a `redirect_uri`.

A new person sends `auth_session` and `name` instead, gets a
`signup_session` and a `passkey_registration` request, and finishes with
`auth_session`, `signup_session` and `passkey_registration` (the new
credential). Other apps are told `redirect_to_web`. These answers set no
session cookie.

Loopback redirect URIs (`http://127.0.0.1/callback`, `http://[::1]/…`) match
on any port, as RFC 8252 §7.3 asks.

| Endpoint | Purpose |
| --- | --- |
| `GET /authorize?response_type=code&client_id&redirect_uri&scope&state&code_challenge&code_challenge_method=S256` | Consent page |
| `POST /authorize` | The page's answer: Allow with a passkey, or Don't Allow |
| `POST /authorize/signup` `{"ticket","name"}` | The page starts a new account and passkey for this request |
| `POST /authorize/signup/finish` `{"ticket","signup","credential","scopes"}` | Creates them and approves the request |
| `POST /oauth/authorize-challenge` | A first-party app signs in without a browser (below) |
| `POST /oauth/token` `grant_type=authorization_code` | Trades the code (60 seconds, single use) for tokens |
| `POST /oauth/token` `grant_type=refresh_token` | A new access token and refresh token |
| `POST /oauth/revoke` `token&client_id` | The device gives its grant back |
| `GET /.well-known/jwks.json` | Keys that verify access tokens and revocation notices |

The consent page carries a signed, five-minute ticket holding the request
and a fresh passkey challenge. Allowing means answering that challenge with
a passkey, which also signs the browser in as that account.

An access token is a five-minute ES256 JWT carrying `iss` (the instance),
`sub` (account ID), `aud` (the service), `scope`, `grant`, `iat`, `exp` and
`jti`. A refresh
token works once; presenting a spent one revokes the grant.

Users see and revoke their grants at `/access`, or through
`GET /api/access/grants` and `DELETE /api/access/grants/:id` with the session
cookie. When a grant ends, PassKeyValue posts a signed `application/jwt`
notice (`sub`, `aud`, `scope`, `grant`, `revoked_at`) to the service's
`revocation_notice_uri`, retrying for a few minutes.

### Data

Each account's key-value data lives in namespaces: `shared`, and one per
app (its `client_id`). `/api/kv` serves both kinds of caller:

- the website's session reads and writes `shared`, and can reach any
  namespace with `?namespace=`;
- an app sends `Authorization: Bearer <access token>`. With `kv` it gets its
  own namespace by default; `kv:shared:read` and `kv:shared:write` open
  `?namespace=shared`. Other apps choose those two on the consent page and
  can leave them out. A revoked grant's token stops working at once.

`/access` lists the data each app keeps, and deletes it once the app has no
access left.

### Website sessions

A sign-in lasts twelve hours, in an HTTP-only `SameSite=Strict` cookie.
Revoking a grant, deleting an app's data and adding a passkey each need a
fresh passkey answer: `POST /confirm` `{"action"}` returns a challenge, and
the action's request carries the answer as `confirmation`.

Generate a key with
`openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt`.

## Docker

Build the image:

```bash
docker build -t passkeyvalue:latest .
```

Run it with runtime env passed from Compose or your orchestrator, not baked into the image:

```bash
docker compose up --build app
```

Notes:
- `docker-compose.yml` reads `.env` with `env_file` and passes the full runtime env through to the container.
- the image stays generic; no app secrets are copied into it.
- the default Compose setup stores SQLite at `/data/db.sqlite` on the `sqlite-data` volume.
- if you need APNs, mount the `.p8` file read-only and set `APN_PRIVATE_KEY_PATH` to that mounted path.

Example Compose mount for the APNs key:

```yaml
services:
  app:
    volumes:
      - sqlite-data:/data
      - ./secrets/AuthKey_ABC123XYZ.p8:/run/secrets/passkeyvalue/AuthKey_ABC123XYZ.p8:ro
    environment:
      APN_PRIVATE_KEY_PATH: /run/secrets/passkeyvalue/AuthKey_ABC123XYZ.p8
```

## GitHub Actions

The repo now uses two minimal workflows:
- `CI` runs `swift test` on pushes to `main` and on pull requests.
- `Docker Hub` builds and pushes `passkeyvalue` to Docker Hub on pushes to `main`, on version tags like `v1.0.0`, and on manual dispatch.

Set these GitHub repository secrets before enabling the Docker publish workflow:
- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN`

The published image name defaults to:

```text
DOCKERHUB_USERNAME/passkeyvalue
```

## Kubernetes

Create a Secret from the APNs `.p8` file:

```bash
kubectl create secret generic passkeyvalue-apn-key \
  --from-file=AuthKey_ABC123XYZ.p8=/absolute/path/to/AuthKey_ABC123XYZ.p8
```

Then mount it and point `APN_PRIVATE_KEY_PATH` at the mounted file:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: passkeyvalue
spec:
  replicas: 1
  selector:
    matchLabels:
      app: passkeyvalue
  template:
    metadata:
      labels:
        app: passkeyvalue
    spec:
      containers:
        - name: app
          image: passkeyvalue:latest
          env:
            - name: SQLITE_DATABASE_PATH
              value: /data/db.sqlite
            - name: RP_ID
              value: example.com
            - name: RP_ORIGIN
              value: https://example.com
            - name: RP_DISPLAY_NAME
              value: PassKeyValue
            - name: APN_HANDLE_SECRET
              valueFrom:
                secretKeyRef:
                  name: passkeyvalue-env
                  key: APN_HANDLE_SECRET
            - name: APN_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: passkeyvalue-env
                  key: APN_KEY_ID
            - name: APN_TEAM_ID
              valueFrom:
                secretKeyRef:
                  name: passkeyvalue-env
                  key: APN_TEAM_ID
            - name: APN_PRIVATE_KEY_PATH
              value: /var/run/secrets/passkeyvalue-apn/AuthKey_ABC123XYZ.p8
          volumeMounts:
            - name: sqlite-data
              mountPath: /data
            - name: apn-private-key
              mountPath: /var/run/secrets/passkeyvalue-apn
              readOnly: true
      volumes:
        - name: sqlite-data
          persistentVolumeClaim:
            claimName: passkeyvalue-sqlite
        - name: apn-private-key
          secret:
            secretName: passkeyvalue-apn-key
```

If you want the mounted filename to stay stable, create the Secret with the exact `.p8` filename you plan to reference, or use `items` under the Secret volume to rename it explicitly.

## Endpoint Reference (Latest)

All routes are currently registered in `Sources/App/routes.swift` via:
- `TestViewController`
- `PasskeyController`
- `KVController`
- `APNController`
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
| `GET` | `/verify` | Yes | Verifies that the current session cookie is still authenticated. |
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

### APN API

The APN wake routes are stateless capability endpoints.

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `POST` | `/api/apn/mint` | No | Mint opaque wake handles from an APNs token and scopes |
| `POST` | `/api/apn/send` | No | Decrypt a wake handle and forward its `wake`: `context` or `action` as a visible APNs notification, `revocation` as a silent background push that takes back notifications for deleted messages |

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
