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
| `POST` | `/api/apn/send` | No | Decrypt a wake handle and forward a visible APNs wake notification |

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
