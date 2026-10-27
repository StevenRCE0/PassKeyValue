import Crypto
import Fluent
import JWT
import NIOConcurrencyHelpers
import Testing
import VaporTesting
import WebAuthn

@testable import App

@Suite("Third-party access", .serialized)
struct ThirdPartyAccessTests {
    static let service = "https://gateway.test/passkv/client.json"
    static let redirectURI = "ktpasskv://authorized"
    static let revocationURL = "https://gateway.test/v1/passkv/revocations"

    static func document(clientID: String = service, revocation: String? = revocationURL) throws -> String {
        let client = ThirdPartyClient(
            clientID: clientID, clientName: "KeepTalking Plan", redirectURIs: [redirectURI],
            scopeDescriptions: ["plan:link": "Link your subscription", "plan:access": "Use your plan on this device"],
            revocationNoticeURI: revocation)
        return String(decoding: try JSONEncoder().encode(client), as: UTF8.self)
    }

    final class Browser: @unchecked Sendable {
        var user: User?
        var passkey = Passkey()
        var cookie: HTTPCookies.Value?
    }

    private func withAccess(_ body: (Application, Browser, Delivered) async throws -> Void) async throws {
        try await withApp(configure: configure) { app in
            let delivered = Delivered()
            delivered.documents[Self.service] = try Self.document()
            app.clients.use { app in RecordingClient(eventLoop: app.eventLoopGroup.next(), delivered: delivered) }
            app.revocationRetries = [.milliseconds(10), .milliseconds(10)]
            let key = ES256PrivateKey()
            await app.jwt.keys.add(ecdsa: key, kid: ThirdPartyAccessController.kid)
            let routes = app.grouped("t")
            try routes.register(collection: ThirdPartyAccessController(publicKey: key.publicKey))
            try routes.register(collection: AuthorisationController())
            let browser = Browser()
            browser.user = try await account("ada", passkey: browser.passkey, on: app.db)
            try await body(app, browser, delivered)
        }
    }

    private func account(_ username: String, passkey: Passkey, on db: any Database) async throws -> User {
        let user = User(username: username)
        try await user.save(on: db)
        try await passkey.register(for: user, on: db)
        return user
    }

    // MARK: - Helpers

    @discardableResult
    private func send(
        _ app: Application, _ method: HTTPMethod, _ path: String, browser: Browser,
        form: (any Content)? = nil
    ) async throws -> TestingHTTPResponse {
        var result: TestingHTTPResponse?
        try await app.testing().test(
            method, path,
            beforeRequest: { req in
                if let cookie = browser.cookie { req.headers.cookie = ["passkv_session": cookie] }
                if let form { try req.content.encode(form, as: .urlEncodedForm) }
            },
            afterResponse: { res in
                if let cookie = res.headers.setCookie?["passkv_session"] { browser.cookie = cookie }
                result = res
            }
        )
        return try #require(result)
    }

    struct PKCE {
        let verifier = OpaqueToken.generate()
        var challenge: String { Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncodedString() }
    }

    private func authorizePath(
        service: String = Self.service, scope: String = "plan:link", redirectURI: String = Self.redirectURI,
        challenge: String, method: String = "S256"
    ) -> String {
        var components = URLComponents(string: "t/authorize")!
        components.queryItems = [
            .init(name: "response_type", value: "code"),
            .init(name: "client_id", value: service),
            .init(name: "redirect_uri", value: redirectURI),
            .init(name: "scope", value: scope),
            .init(name: "state", value: "xyz"),
            .init(name: "code_challenge", value: challenge),
            .init(name: "code_challenge_method", value: method),
        ]
        return components.string!
    }

    private func query(of response: TestingHTTPResponse) throws -> [String: String] {
        let location = try #require(response.headers.first(name: .location))
        let items = URLComponents(string: location)?.queryItems ?? []
        return Dictionary(uniqueKeysWithValues: items.map { ($0.name, $0.value ?? "") })
    }

    private func consent(
        _ app: Application, _ browser: Browser, scope: String = "plan:link", pkce: PKCE = PKCE()
    ) async throws -> (page: String, ticket: String) {
        let page = try await send(app, .GET, authorizePath(scope: scope, challenge: pkce.challenge), browser: browser)
        let html = page.body.string
        let ticket = try #require(html.firstMatch(of: /name="ticket" value="([^"]+)"/)?.1)
        return (html, String(ticket))
    }

    private func decide(
        _ app: Application, _ browser: Browser, ticket: String, approve: Bool = true, passkey: Passkey? = nil,
        challengeFrom signed: String? = nil
    ) async throws -> TestingHTTPResponse {
        var credential: String?
        if approve {
            let challenge = try await keys(app, browser)
                .verify(signed ?? ticket, as: AuthorisationTicket.self).passkeyChallenge
            credential = try (passkey ?? browser.passkey).assertion(over: challenge)
        }
        return try await send(
            app, .POST, "t/authorize", browser: browser,
            form: AuthorisationDecision(ticket: ticket, approve: approve, credential: credential, scopes: nil))
    }

    private func approve(
        _ app: Application, _ browser: Browser, scope: String = "plan:link", passkey: Passkey? = nil
    ) async throws -> (code: String, verifier: String) {
        let pkce = PKCE()
        let (_, ticket) = try await consent(app, browser, scope: scope, pkce: pkce)
        let answer = try query(of: try await decide(app, browser, ticket: ticket, passkey: passkey))
        #expect(answer["state"] == "xyz")
        return (try #require(answer["code"]), pkce.verifier)
    }

    private func exchange(_ app: Application, code: String, verifier: String, browser: Browser) async throws
        -> TestingHTTPResponse
    {
        try await send(
            app, .POST, "t/oauth/token", browser: browser,
            form: TokenRequest(
                grantType: "authorization_code", clientID: Self.service, code: code,
                redirectURI: Self.redirectURI, codeVerifier: verifier, refreshToken: nil))
    }

    private func refresh(_ app: Application, _ token: String, browser: Browser) async throws -> TestingHTTPResponse {
        try await send(
            app, .POST, "t/oauth/token", browser: browser,
            form: TokenRequest(
                grantType: "refresh_token", clientID: Self.service, code: nil, redirectURI: nil,
                codeVerifier: nil, refreshToken: token))
    }

    private func linkDevice(_ app: Application, _ browser: Browser, scope: String = "plan:link") async throws
        -> TokenResponse
    {
        let (code, verifier) = try await approve(app, browser, scope: scope)
        return try await exchange(app, code: code, verifier: verifier, browser: browser).content.decode(TokenResponse.self)
    }

    private func confirmation(
        _ app: Application, _ browser: Browser, action: String, passkey: Passkey? = nil
    ) async throws -> String {
        struct Options: Decodable { let challenge: URLEncodedBase64 }
        let options = try await send(app, .POST, "confirm", browser: browser, form: ConfirmationRequest(action: action))
        return try (passkey ?? browser.passkey).assertion(over: try options.content.decode(Options.self).challenge)
    }

    private func keys(_ app: Application, _ browser: Browser) async throws -> JWTKeyCollection {
        let jwks = try await send(app, .GET, "t/.well-known/jwks.json", browser: browser).content.decode(JWKS.self)
        return try await JWTKeyCollection().add(jwks: jwks)
    }

    private func grants(_ app: Application, _ browser: Browser) async throws -> [ThirdPartyGrantSummary] {
        try await send(app, .GET, "t/api/access/grants", browser: browser).content.decode([ThirdPartyGrantSummary].self)
    }

    // MARK: - Authorise page

    @Test("the consent page shows the service and what it asks for")
    func consentPage() async throws {
        try await withAccess { app, browser, delivered in
            let (page, _) = try await consent(app, browser)
            #expect(page.contains("KeepTalking Plan"))
            #expect(page.contains("gateway.test"))
            #expect(page.contains("Link your subscription"))
            #expect(page.contains("Allow with passkey"))
            #expect(browser.cookie == nil)
        }
    }

    @Test("Allow with a passkey gives a code that trades for verifiable tokens")
    func codeFlow() async throws {
        try await withAccess { app, browser, delivered in
            let (code, verifier) = try await approve(app, browser)
            let tokens = try await exchange(app, code: code, verifier: verifier, browser: browser)
                .content.decode(TokenResponse.self)
            #expect(tokens.scope == "plan:link")
            #expect(tokens.expiresIn == 300)

            let access = try await keys(app, browser).verify(tokens.accessToken, as: ThirdPartyAccessToken.self)
            #expect(access.subject.value == browser.user?.id?.uuidString)
            try access.audience.verifyIntendedAudience(includes: Self.service)
            #expect(access.scopes == ["plan:link"])
            #expect(try await grants(app, browser).map(\.id) == [access.grant])

            #expect(try await exchange(app, code: code, verifier: verifier, browser: browser).status == .badRequest)
        }
    }

    @Test("approving signs in as the approving account, replacing whoever was signed in")
    func approvalSignsIn() async throws {
        try await withAccess { app, browser, delivered in
            _ = try await approve(app, browser)
            let bobsPasskey = Passkey()
            let bob = try await account("bob", passkey: bobsPasskey, on: app.db)
            let (code, verifier) = try await approve(app, browser, passkey: bobsPasskey)
            let tokens = try await exchange(app, code: code, verifier: verifier, browser: browser)
                .content.decode(TokenResponse.self)
            let access = try await keys(app, browser).verify(tokens.accessToken, as: ThirdPartyAccessToken.self)
            #expect(access.subject.value == bob.id?.uuidString)
            #expect(try await grants(app, browser).map(\.id) == [access.grant])
        }
    }

    @Test("a tampered or expired ticket approves nothing")
    func badTickets() async throws {
        try await withAccess { app, browser, delivered in
            let (_, ticket) = try await consent(app, browser)
            var parts = ticket.split(separator: ".").map(String.init)
            parts[2] = (parts[2].hasPrefix("A") ? "B" : "A") + parts[2].dropFirst()
            let tampered = parts.joined(separator: ".")
            #expect(try await decide(app, browser, ticket: tampered, challengeFrom: ticket).status == .badRequest)

            let request = AuthorisationRequest(
                responseType: "code", clientID: Self.service, redirectURI: Self.redirectURI, scope: "plan:link",
                state: "xyz", codeChallenge: PKCE().challenge, codeChallengeMethod: "S256")
            let expired = try await app.jwt.keys.sign(
                AuthorisationTicket(
                    request: request,
                    client: try JSONDecoder().decode(ThirdPartyClient.self, from: Data(try Self.document().utf8)),
                    scopes: ["plan:link"], allowlisted: false, native: false, passkeyChallenge: [1, 2, 3],
                    now: .now.addingTimeInterval(-AuthorisationTicket.lifetime - 1)),
                kid: ThirdPartyAccessController.kid)
            let answer = try await send(
                app, .POST, "t/authorize", browser: browser,
                form: AuthorisationDecision(ticket: expired, approve: false, credential: nil, scopes: nil))
            #expect(answer.status == .badRequest)
            #expect(try await AuthorisationCode.query(on: app.db).count() == 0)
        }
    }

    @Test("a passkey answer only approves the request it was made for")
    func answerBoundToTicket() async throws {
        try await withAccess { app, browser, delivered in
            let (_, first) = try await consent(app, browser)
            let (_, second) = try await consent(app, browser)
            #expect(try await decide(app, browser, ticket: second, challengeFrom: first).status == .unauthorized)
            #expect(try await decide(app, browser, ticket: second, passkey: Passkey()).status == .unauthorized)
            #expect(try await decide(app, browser, ticket: second, approve: true, passkey: nil).status == .seeOther)
            #expect(try await AuthorisationCode.query(on: app.db).count() == 1)
        }
    }

    @Test("Don't Allow sends access_denied back")
    func deny() async throws {
        try await withAccess { app, browser, delivered in
            let (_, ticket) = try await consent(app, browser)
            let decided = try await decide(app, browser, ticket: ticket, approve: false)
            #expect(try query(of: decided) == ["error": "access_denied", "state": "xyz"])
            #expect(try await AuthorisationCode.query(on: app.db).count() == 0)
            #expect(browser.cookie == nil)
        }
    }

    @Test("bad requests stay on PassKeyValue until the redirect URI is the service's own")
    func badRequests() async throws {
        try await withAccess { app, browser, delivered in
            let challenge = PKCE().challenge
            #expect(try await send(app, .GET, authorizePath(service: "someone", challenge: challenge), browser: browser).status == .badRequest)
            #expect(try await send(app, .GET, authorizePath(redirectURI: "evil://cb", challenge: challenge), browser: browser).status == .badRequest)
            let plain = try await send(app, .GET, authorizePath(challenge: challenge, method: "plain"), browser: browser)
            #expect(try query(of: plain)["error"] == "invalid_request")
            let scope = try await send(app, .GET, authorizePath(scope: "profile:read", challenge: challenge), browser: browser)
            #expect(try query(of: scope)["error"] == "invalid_scope")
        }
    }

    @Test("a service is only believed when its own document vouches for it")
    func clientDocuments() async throws {
        try await withAccess { app, browser, delivered in
            let elsewhere = "https://elsewhere.test/client.json"
            let farNotices = "https://gateway.test/notices.json"
            let broken = "https://gateway.test/broken.json"
            delivered.documents[elsewhere] = try Self.document()
            delivered.documents[farNotices] = try Self.document(
                clientID: farNotices, revocation: "https://elsewhere.test/revocations")
            delivered.documents[broken] = "{"
            let challenge = PKCE().challenge
            for service in [
                elsewhere, farNotices, broken, "https://gateway.test/missing.json",
                "http://gateway.test/passkv/client.json", "keeptalking-gateway",
            ] {
                let answer = try await send(app, .GET, authorizePath(service: service, challenge: challenge), browser: browser)
                #expect(answer.status == .badRequest, "\(service)")
            }
        }
    }

    @Test("a code needs its own verifier, and is spent by the first try")
    func codeNeedsVerifier() async throws {
        try await withAccess { app, browser, delivered in
            let (code, verifier) = try await approve(app, browser)
            #expect(try await exchange(app, code: code, verifier: PKCE().verifier, browser: browser).status == .badRequest)
            #expect(try await exchange(app, code: code, verifier: verifier, browser: browser).status == .badRequest)
        }
    }

    // MARK: - Refresh and revocation

    @Test("refresh tokens rotate, and a spent one coming back revokes the grant")
    func refreshRotation() async throws {
        try await withAccess { app, browser, delivered in
            let first = try await linkDevice(app, browser)
            let second = try await refresh(app, first.refreshToken, browser: browser).content.decode(TokenResponse.self)
            #expect(second.refreshToken != first.refreshToken)

            #expect(try await refresh(app, first.refreshToken, browser: browser).status == .badRequest)
            #expect(try await refresh(app, second.refreshToken, browser: browser).status == .badRequest)
            #expect(try await grants(app, browser).isEmpty)
            #expect(try await delivered.requests(1).map(\.url.string) == [Self.revocationURL])
        }
    }

    @Test("each approval is its own device grant, revoked on its own")
    func perDeviceGrants() async throws {
        try await withAccess { app, browser, delivered in
            let phone = try await linkDevice(app, browser)
            let mac = try await linkDevice(app, browser, scope: "plan:access")
            let listed = try await grants(app, browser)
            #expect(listed.count == 2)

            let phoneGrant = try await keys(app, browser).verify(phone.accessToken, as: ThirdPartyAccessToken.self).grant
            #expect(try await send(app, .DELETE, "t/api/access/grants/\(phoneGrant)", browser: browser).status == .forbidden)
            let confirmed = Confirmation(confirmation: try await confirmation(app, browser, action: "revoke:\(phoneGrant)"))
            #expect(
                try await send(app, .DELETE, "t/api/access/grants/\(phoneGrant)", browser: browser, form: confirmed).status
                    == .noContent)
            #expect(try await refresh(app, phone.refreshToken, browser: browser).status == .badRequest)
            #expect(try await refresh(app, mac.refreshToken, browser: browser).status == .ok)

            let requests = try await delivered.requests(1)
            #expect(requests.count == 1)
            let notice = try await keys(app, browser).verify(
                try #require(requests.first?.body.map { String(buffer: $0) }), as: ThirdPartyRevocation.self)
            #expect(notice.grant == phoneGrant)
            #expect(notice.scope == "plan:link")
        }
    }

    @Test("a device can give its grant back")
    func deviceRevokes() async throws {
        try await withAccess { app, browser, delivered in
            let tokens = try await linkDevice(app, browser)
            let revoke = RevocationRequest(token: tokens.refreshToken, clientID: Self.service)
            #expect(try await send(app, .POST, "t/oauth/revoke", browser: browser, form: revoke).status == .ok)
            #expect(try await refresh(app, tokens.refreshToken, browser: browser).status == .badRequest)
            #expect(try await grants(app, browser).isEmpty)
            #expect(try await send(app, .POST, "t/oauth/revoke", browser: browser, form: revoke).status == .ok)
        }
    }

    @Test("the revocation notice is a signed JWT posted to the service, retried until it lands")
    func revocationNotice() async throws {
        try await withAccess { app, browser, delivered in
            delivered.statuses = [.serviceUnavailable]
            let tokens = try await linkDevice(app, browser)
            let grant = try await keys(app, browser).verify(tokens.accessToken, as: ThirdPartyAccessToken.self).grant
            _ = try await send(
                app, .POST, "t/oauth/revoke", browser: browser,
                form: RevocationRequest(token: tokens.refreshToken, clientID: Self.service))

            let requests = try await delivered.requests(2)
            #expect(requests.count == 2)
            let request = try #require(requests.last)
            #expect(request.url.string == Self.revocationURL)
            #expect(request.headers.contentType == .jwt)
            let notice = try await keys(app, browser).verify(
                try #require(request.body.map { String(buffer: $0) }), as: ThirdPartyRevocation.self)
            #expect(notice.grant == grant)
            #expect(notice.subject.value == browser.user?.id?.uuidString)
            try notice.audience.verifyIntendedAudience(includes: Self.service)
        }
    }

    @Test("revoking needs a fresh passkey answer from this account, for this grant")
    func revokingNeedsPasskey() async throws {
        try await withAccess { app, browser, delivered in
            let tokens = try await linkDevice(app, browser)
            let grant = try await keys(app, browser).verify(tokens.accessToken, as: ThirdPartyAccessToken.self).grant
            let path = "t/api/access/grants/\(grant)"

            let otherAction = Confirmation(confirmation: try await confirmation(app, browser, action: "revoke:\(UUID())"))
            #expect(try await send(app, .DELETE, path, browser: browser, form: otherAction).status == .forbidden)

            let bob = Passkey()
            _ = try await account("bob", passkey: bob, on: app.db)
            let someoneElse = Confirmation(
                confirmation: try await confirmation(app, browser, action: "revoke:\(grant)", passkey: bob))
            #expect(try await send(app, .DELETE, path, browser: browser, form: someoneElse).status == .forbidden)

            let reused = try await confirmation(app, browser, action: "revoke:\(grant)")
            #expect(try await send(app, .DELETE, path, browser: browser, form: Confirmation(confirmation: reused)).status == .noContent)
            #expect(try await grants(app, browser).isEmpty)
        }
    }

    @Test("adding a passkey to a signed-in account needs a fresh passkey answer")
    func addingPasskeyNeedsPasskey() async throws {
        try await withAccess { app, browser, delivered in
            _ = try await approve(app, browser)
            let begin = BeginPasskeyRequest(stage: .registration, isMerging: true, passkeyName: "Second")
            #expect(try await send(app, .POST, "begin", browser: browser, form: begin).status == .forbidden)
            let confirmed = BeginPasskeyRequest(
                stage: .registration, isMerging: true, passkeyName: "Second",
                confirmation: try await confirmation(app, browser, action: "add-passkey"))
            #expect(try await send(app, .POST, "begin", browser: browser, form: confirmed).status == .ok)
        }
    }

    @Test("a website session lasts twelve hours, in a strict same-site cookie")
    func sessionLifetime() async throws {
        try await withAccess { app, browser, delivered in
            _ = try await approve(app, browser)
            #expect(try await send(app, .GET, "t/access", browser: browser).status == .ok)
            #expect(browser.cookie?.sameSite == .strict)
            #expect(browser.cookie?.maxAge == Int(SessionLifetime.duration))

            let records = try await SessionRecord.query(on: app.db).all()
            #expect(records.contains { $0.data[PasskeySessionKey.signedInAt] != nil })
            for record in records where record.data[PasskeySessionKey.signedInAt] != nil {
                record.data[PasskeySessionKey.signedInAt] = String(Date.now.timeIntervalSince1970 - SessionLifetime.duration - 1)
                try await record.save(on: app.db)
            }
            #expect(try await send(app, .GET, "t/access", browser: browser).status == .seeOther)
        }
    }

    @Test("the access page lists grants and revokes them")
    func accessPage() async throws {
        try await withAccess { app, browser, delivered in
            let tokens = try await linkDevice(app, browser)
            let grant = try await keys(app, browser).verify(tokens.accessToken, as: ThirdPartyAccessToken.self).grant
            let page = try await send(app, .GET, "t/access", browser: browser)
            #expect(page.body.string.contains("KeepTalking Plan"))
            #expect(page.body.string.contains("Link your subscription"))
            let confirmed = Confirmation(confirmation: try await confirmation(app, browser, action: "revoke:\(grant)"))
            #expect(try await send(app, .POST, "t/access/\(grant)/revoke", browser: browser, form: confirmed).status == .seeOther)
            #expect(try await grants(app, browser).isEmpty)
        }
    }

    @Test("managing grants needs a signed-in account")
    func requiresSession() async throws {
        try await withAccess { app, browser, delivered in
            let api = try await send(app, .GET, "t/api/access/grants", browser: browser)
            let page = try await send(app, .GET, "t/access", browser: browser)
            #expect(api.status == .unauthorized)
            #expect(page.status == .seeOther)
        }
    }

    @Test("without a signing key there's no key set and no authorise page")
    func withoutSigningKey() async throws {
        try await withApp(configure: configure) { app in
            try await app.testing().test(.GET, ".well-known/jwks.json", afterResponse: { res in
                #expect(res.status == .notFound)
            })
            try await app.testing().test(.GET, "authorize", afterResponse: { res in
                #expect(res.status == .notFound)
            })
        }
    }
}

struct Passkey {
    let key = P256.Signing.PrivateKey()
    let id = OpaqueToken.generate()

    var cose: [UInt8] {
        let raw = [UInt8](key.publicKey.rawRepresentation)
        return [0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20] + raw.prefix(32) + [0x22, 0x58, 0x20]
            + raw.suffix(32)
    }

    func register(for user: User, on db: any Database) async throws {
        try await WebAuthnCredential(
            id: URLEncodedBase64(id).urlDecoded.asString(), publicKey: cose.base64URLEncodedString().asString(),
            currentSignCount: 0, name: "Test", userID: user.requireID()
        ).save(on: db)
    }

    func assertion(over challenge: URLEncodedBase64) throws -> String {
        let clientData = Data(
            #"{"type":"webauthn.get","challenge":"\#(challenge.asString())","origin":"http://localhost:8080"}"#.utf8)
        let authenticatorData = Data(SHA256.hash(data: Data("localhost".utf8))) + Data([0x05, 0, 0, 0, 0])
        let signature = try key.signature(for: authenticatorData + Data(SHA256.hash(data: clientData)))
        let credential: [String: Any] = [
            "id": id, "rawId": id, "type": "public-key",
            "response": [
                "authenticatorData": authenticatorData.base64URLEncodedString().asString(),
                "clientDataJSON": clientData.base64URLEncodedString().asString(),
                "signature": signature.derRepresentation.base64URLEncodedString().asString(),
            ],
        ]
        return String(decoding: try JSONSerialization.data(withJSONObject: credential), as: UTF8.self)
    }

    func registration(over challenge: URLEncodedBase64) throws -> [String: Any] {
        func bytes(_ value: [UInt8]) -> [UInt8] {
            value.count < 24 ? [0x40 + UInt8(value.count)] + value
                : value.count < 256 ? [0x58, UInt8(value.count)] + value
                : [0x59, UInt8(value.count >> 8), UInt8(value.count & 0xFF)] + value
        }
        func text(_ value: String) -> [UInt8] { [0x60 + UInt8(value.utf8.count)] + Array(value.utf8) }
        let credentialID = URLEncodedBase64(id).decodedBytes ?? []
        let authenticatorData: [UInt8] =
            Array(SHA256.hash(data: Data("localhost".utf8))) + [0x45, 0, 0, 0, 0] + [UInt8](repeating: 0, count: 16)
            + [UInt8(credentialID.count >> 8), UInt8(credentialID.count & 0xFF)] + credentialID + cose
        let attestation: [UInt8] =
            [0xA3] + text("fmt") + text("none") + text("attStmt") + [0xA0] + text("authData") + bytes(authenticatorData)
        let clientData = Data(
            #"{"type":"webauthn.create","challenge":"\#(challenge.asString())","origin":"http://localhost:8080"}"#.utf8)
        return [
            "id": id, "rawId": id, "type": "public-key",
            "response": [
                "attestationObject": attestation.base64URLEncodedString().asString(),
                "clientDataJSON": clientData.base64URLEncodedString().asString(),
            ],
        ]
    }
}

final class Delivered: Sendable {
    private struct State {
        var documents: [String: String] = [:]
        var statuses: [HTTPStatus] = []
        var requests: [ClientRequest] = []
    }

    private let state = NIOLockedValueBox(State())

    var documents: [String: String] {
        get { state.withLockedValue(\.documents) }
        set { state.withLockedValue { $0.documents = newValue } }
    }

    var statuses: [HTTPStatus] {
        get { state.withLockedValue(\.statuses) }
        set { state.withLockedValue { $0.statuses = newValue } }
    }

    func respond(to request: ClientRequest) -> ClientResponse {
        state.withLockedValue { state in
            if request.method == .GET {
                guard let document = state.documents[request.url.string] else { return ClientResponse(status: .notFound) }
                return ClientResponse(status: .ok, body: ByteBuffer(string: document))
            }
            state.requests.append(request)
            return ClientResponse(status: state.statuses.isEmpty ? .noContent : state.statuses.removeFirst())
        }
    }

    func requests(_ count: Int) async throws -> [ClientRequest] {
        for _ in 0..<200 {
            let requests = state.withLockedValue(\.requests)
            if requests.count >= count { return requests }
            try await Task.sleep(for: .milliseconds(10))
        }
        return state.withLockedValue(\.requests)
    }
}

struct RecordingClient: Client {
    let eventLoop: any EventLoop
    let delivered: Delivered

    func delegating(to eventLoop: any EventLoop) -> any Client {
        RecordingClient(eventLoop: eventLoop, delivered: delivered)
    }

    func send(_ request: ClientRequest) -> EventLoopFuture<ClientResponse> {
        eventLoop.makeSucceededFuture(delivered.respond(to: request))
    }
}
