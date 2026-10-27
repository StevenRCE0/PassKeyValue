import Crypto
import Fluent
import JWT
import SQLKit
import Testing
import VaporTesting
import WebAuthn

@testable import App

@Suite("First-party apps and app data", .serialized)
struct FirstPartyKVTests {
    static let first = "https://kt.first.test/passkv/client.json"
    static let other = "https://other.test/passkv/client.json"
    static let redirectURI = "ktpasskv://authorized"

    static func document(_ clientID: String, name: String) throws -> String {
        let client = ThirdPartyClient(
            clientID: clientID, clientName: name, redirectURIs: [redirectURI],
            scopeDescriptions: ["plan": "Use your plan"], revocationNoticeURI: nil)
        return String(decoding: try JSONEncoder().encode(client), as: UTF8.self)
    }

    final class Instance: @unchecked Sendable {
        let app: Application
        let delivered: Delivered
        let user: User
        let passkey: Passkey
        var cookie: HTTPCookies.Value?

        init(app: Application, delivered: Delivered, user: User, passkey: Passkey) {
            self.app = app
            self.delivered = delivered
            self.user = user
            self.passkey = passkey
        }
    }

    private struct Challenge: Decodable {
        struct Options: Decodable { let challenge: URLEncodedBase64 }
        let authorization_code: String?
        let error: String?
        let auth_session: String?
        let passkey: Options?
        let signup_session: String?
        let passkey_registration: Options?
    }

    private func withInstance(_ body: (Instance) async throws -> Void) async throws {
        try await withApp(configure: configure) { app in
            let delivered = Delivered()
            delivered.documents[Self.first] = try Self.document(Self.first, name: "KeepTalking")
            delivered.documents[Self.other] = try Self.document(Self.other, name: "Other")
            app.clients.use { app in RecordingClient(eventLoop: app.eventLoopGroup.next(), delivered: delivered) }
            app.thirdParty = ThirdPartySettings(issuer: "http://localhost:8080", firstPartyDomains: ["first.test"])
            await app.jwt.keys.add(ecdsa: ES256PrivateKey(), kid: ThirdPartyAccessController.kid)
            let routes = app.grouped("t")
            try routes.register(collection: ThirdPartyAccessController(publicKey: nil))
            try routes.register(collection: AuthorisationController())
            let passkey = Passkey()
            let user = User(username: "ada")
            try await user.save(on: app.db)
            try await passkey.register(for: user, on: app.db)
            try await body(Instance(app: app, delivered: delivered, user: user, passkey: passkey))
        }
    }

    // MARK: - Helpers

    @discardableResult
    private func send(
        _ instance: Instance, _ method: HTTPMethod, _ path: String, json: [String: Any]? = nil,
        form: (any Content)? = nil, bearer: String? = nil
    ) async throws -> TestingHTTPResponse {
        var result: TestingHTTPResponse?
        try await instance.app.testing().test(
            method, path,
            beforeRequest: { req in
                if let bearer {
                    req.headers.bearerAuthorization = .init(token: bearer)
                } else if let cookie = instance.cookie {
                    req.headers.cookie = ["passkv_session": cookie]
                }
                if let json {
                    req.headers.contentType = .json
                    req.body = ByteBuffer(data: try JSONSerialization.data(withJSONObject: json))
                }
                if let form { try req.content.encode(form, as: .urlEncodedForm) }
            },
            afterResponse: { res in
                if let cookie = res.headers.setCookie?["passkv_session"] { instance.cookie = cookie }
                result = res
            }
        )
        return try #require(result)
    }

    private func request(_ client: String, scope: String, pkce: ThirdPartyAccessTests.PKCE) -> [String: String] {
        [
            "response_type": "code", "client_id": client, "redirect_uri": Self.redirectURI, "scope": scope,
            "state": "s", "code_challenge": pkce.challenge, "code_challenge_method": "S256",
        ]
    }

    private func authorizePath(_ client: String, scope: String, pkce: ThirdPartyAccessTests.PKCE) -> String {
        var components = URLComponents(string: "t/authorize")!
        components.queryItems = request(client, scope: scope, pkce: pkce).sorted { $0.key < $1.key }
            .map { URLQueryItem(name: $0.key, value: $0.value) }
        return components.string!
    }

    private func challenge(of ticket: String, _ instance: Instance) async throws -> URLEncodedBase64 {
        try await instance.app.jwt.keys.verify(ticket, as: AuthorisationTicket.self).passkeyChallenge
    }

    private func challengeEndpoint(_ instance: Instance, _ form: [String: String]) async throws
        -> (status: HTTPStatus, body: Challenge)
    {
        let response = try await send(instance, .POST, "t/oauth/authorize-challenge", form: form)
        return (response.status, try response.content.decode(Challenge.self))
    }

    private func nativeTicket(_ instance: Instance, client: String = first, scope: String) async throws
        -> (ticket: String, pkce: ThirdPartyAccessTests.PKCE)
    {
        let pkce = ThirdPartyAccessTests.PKCE()
        let (status, body) = try await challengeEndpoint(
            instance,
            ["client_id": client, "scope": scope, "code_challenge": pkce.challenge, "code_challenge_method": "S256"])
        #expect(status == .badRequest)
        #expect(body.error == "insufficient_authorization")
        return (try #require(body.auth_session), pkce)
    }

    private func exchange(
        _ instance: Instance, client: String = first, code: String, pkce: ThirdPartyAccessTests.PKCE,
        redirectURI: String? = nil
    ) async throws -> TokenResponse {
        try await send(
            instance, .POST, "t/oauth/token",
            form: TokenRequest(
                grantType: "authorization_code", clientID: client, code: code, redirectURI: redirectURI,
                codeVerifier: pkce.verifier, refreshToken: nil)
        ).content.decode(TokenResponse.self)
    }

    private func nativeSignIn(_ instance: Instance, scope: String, passkey: Passkey? = nil) async throws -> TokenResponse {
        let (ticket, pkce) = try await nativeTicket(instance, scope: scope)
        let assertion = try (passkey ?? instance.passkey).assertion(over: try await challenge(of: ticket, instance))
        let (status, body) = try await challengeEndpoint(instance, ["auth_session": ticket, "passkey": assertion])
        #expect(status == .ok)
        return try await exchange(instance, code: try #require(body.authorization_code), pkce: pkce)
    }

    private func signInOnTheWeb(_ instance: Instance) async throws {
        _ = try await consentTokens(instance, scope: "kv", choosing: [])
    }

    private func consentTokens(_ instance: Instance, scope: String, choosing chosen: [String]) async throws
        -> TokenResponse
    {
        let pkce = ThirdPartyAccessTests.PKCE()
        let page = try await send(instance, .GET, authorizePath(Self.other, scope: scope, pkce: pkce)).body.string
        let ticket = String(try #require(page.firstMatch(of: /name="ticket" value="([^"]+)"/)?.1))
        let assertion = try instance.passkey.assertion(over: try await challenge(of: ticket, instance))
        let decided = try await send(
            instance, .POST, "t/authorize",
            form: AuthorisationDecision(ticket: ticket, approve: true, credential: assertion, scopes: chosen))
        let location = try #require(decided.headers.first(name: .location))
        let code = try #require(URLComponents(string: location)?.queryItems?.first { $0.name == "code" }?.value)
        return try await exchange(instance, client: Self.other, code: code, pkce: pkce, redirectURI: Self.redirectURI)
    }

    private func value(_ response: TestingHTTPResponse) throws -> String? {
        response.status == .ok ? try response.content.decode(KVGetResponse.self).item.value : nil
    }

    private func namespace(_ name: String) -> String {
        name.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? name
    }

    // MARK: - Signing in

    @Test("this instance's own app signs in natively and gets what it asks for, with no consent page")
    func firstPartyNative() async throws {
        try await withInstance { instance in
            let tokens = try await nativeSignIn(instance, scope: "kv kv:shared:read kv:shared:write plan")
            #expect(Set(tokens.scope.split(separator: " ")) == ["kv", "kv:shared:read", "kv:shared:write", "plan"])
            #expect(instance.cookie == nil)

            let (ticket, _) = try await nativeTicket(instance, scope: "kv")
            let wrong = try Passkey().assertion(over: try await challenge(of: ticket, instance))
            #expect(try await challengeEndpoint(instance, ["auth_session": ticket, "passkey": wrong]).body.error == "access_denied")
            #expect(try await challengeEndpoint(instance, ["auth_session": "nonsense"]).body.error == "invalid_session")
            #expect(try await challengeEndpoint(instance, ["scope": "kv"]).body.error == "invalid_request")
        }
    }

    @Test("on the web page an allowlisted app still asks, with every scope required")
    func allowlistedOnTheWeb() async throws {
        try await withInstance { instance in
            let pkce = ThirdPartyAccessTests.PKCE()
            let page = try await send(
                instance, .GET, authorizePath(Self.first, scope: "kv kv:shared:read", pkce: pkce)
            ).body.string
            #expect(page.contains("would like to"))
            #expect(!page.contains("computer"))
            #expect(page.contains("Read your shared data"))
            #expect(page.contains("Allow with passkey"))
            #expect(!page.contains("scope-choice"))

            let ticket = String(try #require(page.firstMatch(of: /name="ticket" value="([^"]+)"/)?.1))
            let assertion = try instance.passkey.assertion(over: try await challenge(of: ticket, instance))
            let viaApp = try await challengeEndpoint(instance, ["auth_session": ticket, "passkey": assertion])
            #expect(viaApp.body.error == "invalid_session")

            let decided = try await send(
                instance, .POST, "t/authorize",
                form: AuthorisationDecision(ticket: ticket, approve: true, credential: assertion, scopes: []))
            let location = try #require(decided.headers.first(name: .location))
            let code = try #require(URLComponents(string: location)?.queryItems?.first { $0.name == "code" }?.value)
            #expect(try await exchange(instance, code: code, pkce: pkce, redirectURI: Self.redirectURI).scope == "kv kv:shared:read")

            let (native, _) = try await nativeTicket(instance, scope: "kv")
            let nativeAssertion = try instance.passkey.assertion(over: try await challenge(of: native, instance))
            let onThePage = try await send(
                instance, .POST, "t/authorize",
                form: AuthorisationDecision(ticket: native, approve: true, credential: nativeAssertion, scopes: nil))
            #expect(onThePage.status == .forbidden)
        }
    }

    @Test("a loopback redirect matches on any port, and only on loopback")
    func loopbackRedirects() async throws {
        try await withInstance { instance in
            let desktop = "https://desk.other.test/passkv/client.json"
            instance.delivered.documents[desktop] = String(
                decoding: try JSONEncoder().encode(
                    ThirdPartyClient(
                        clientID: desktop, clientName: "Desktop", redirectURIs: ["http://127.0.0.1/callback"],
                        scopeDescriptions: ["notes": "Read your notes"], revocationNoticeURI: nil)),
                as: UTF8.self)
            func page(_ redirect: String) async throws -> HTTPStatus {
                var components = URLComponents(string: "t/authorize")!
                components.queryItems = [
                    "response_type": "code", "client_id": desktop, "redirect_uri": redirect, "scope": "notes",
                    "state": "s", "code_challenge": ThirdPartyAccessTests.PKCE().challenge,
                    "code_challenge_method": "S256",
                ].map { URLQueryItem(name: $0.key, value: $0.value) }
                return try await send(instance, .GET, components.string!).status
            }
            #expect(try await page("http://127.0.0.1:53124/callback") == .ok)
            #expect(try await page("http://127.0.0.1/callback") == .ok)
            #expect(try await page("http://127.0.0.1:53124/elsewhere") == .badRequest)
            #expect(try await page("http://localhost:53124/callback") == .badRequest)
            #expect(try await page("https://127.0.0.1:53124/callback") == .badRequest)
        }
    }

    @Test("other apps can't sign in natively, and get shared data only when the box stays ticked")
    func thirdPartyConsent() async throws {
        try await withInstance { instance in
            let native = try await challengeEndpoint(
                instance,
                ["client_id": Self.other, "scope": "kv", "code_challenge": ThirdPartyAccessTests.PKCE().challenge,
                 "code_challenge_method": "S256"])
            #expect(native.body.error == "redirect_to_web")
            #expect(native.body.auth_session == nil)

            let page = try await send(
                instance, .GET, authorizePath(Self.other, scope: "kv kv:shared:read", pkce: .init())
            ).body.string
            #expect(page.contains("would like to"))
            #expect(page.contains("Read your shared data"))
            #expect(page.contains("scope-choice"))

            #expect(try await consentTokens(instance, scope: "kv kv:shared:read", choosing: []).scope == "kv")
            #expect(
                try await consentTokens(instance, scope: "kv kv:shared:read", choosing: [KVScope.sharedRead]).scope
                    == "kv kv:shared:read")
        }
    }

    @Test("a new person creates a passkey, and their account, on the way in")
    func signUp() async throws {
        try await withInstance { instance in
            let (ticket, pkce) = try await nativeTicket(instance, scope: "kv")
            let started = try await challengeEndpoint(instance, ["auth_session": ticket, "name": "grace"]).body
            #expect(started.error == "insufficient_authorization")
            let signup = try #require(started.signup_session)
            let creation = try #require(started.passkey_registration)
            let grace = Passkey()
            let registration = String(
                decoding: try JSONSerialization.data(withJSONObject: try grace.registration(over: creation.challenge)),
                as: UTF8.self)
            let finished = try await challengeEndpoint(
                instance, ["auth_session": ticket, "signup_session": signup, "passkey_registration": registration])
            let tokens = try await exchange(instance, code: try #require(finished.body.authorization_code), pkce: pkce)
            let user = try #require(try await User.query(on: instance.app.db).filter(\.$username == "grace").first())
            let access = try await instance.app.jwt.keys.verify(tokens.accessToken, as: ThirdPartyAccessToken.self)
            #expect(access.subject.value == user.id?.uuidString)
            #expect(access.issuer.value == "http://localhost:8080")
            #expect(instance.cookie == nil)

            _ = try await nativeSignIn(instance, scope: "kv", passkey: grace)

            let (another, _) = try await nativeTicket(instance, scope: "kv")
            let other = String(
                decoding: try JSONSerialization.data(withJSONObject: try Passkey().registration(over: creation.challenge)),
                as: UTF8.self)
            let mismatched = try await challengeEndpoint(
                instance, ["auth_session": another, "signup_session": signup, "passkey_registration": other])
            #expect(mismatched.body.error == "access_denied")

            let onThePage = try await send(
                instance, .POST, "t/authorize/signup", json: ["ticket": another, "name": "eve"])
            #expect(onThePage.status == .forbidden)
        }
    }

    @Test("on the web page, a new person signs up and approves in one go")
    func signUpOnTheWeb() async throws {
        try await withInstance { instance in
            let pkce = ThirdPartyAccessTests.PKCE()
            let page = try await send(instance, .GET, authorizePath(Self.other, scope: "kv", pkce: pkce)).body.string
            let ticket = String(try #require(page.firstMatch(of: /name="ticket" value="([^"]+)"/)?.1))
            struct Started: Decodable {
                struct Options: Decodable { let challenge: URLEncodedBase64 }
                let ticket: String
                let options: Options
            }
            let started = try await send(
                instance, .POST, "t/authorize/signup", json: ["ticket": ticket, "name": "lin"]
            ).content.decode(Started.self)
            let finished = try await send(
                instance, .POST, "t/authorize/signup/finish",
                json: [
                    "ticket": ticket, "signup": started.ticket,
                    "credential": try Passkey().registration(over: started.options.challenge), "scopes": [String](),
                ]
            ).content.decode(AuthorisationAnswer.self)
            #expect(finished.redirect.hasPrefix("ktpasskv://authorized?code="))
            #expect(instance.cookie != nil)
            let tokens = try await exchange(
                instance, client: Self.other, code: finished.code, pkce: pkce, redirectURI: Self.redirectURI)
            #expect(tokens.scope == "kv")
        }
    }

    // MARK: - Data

    @Test("apps keep their own data, and shared data needs its scope")
    func namespaces() async throws {
        try await withInstance { instance in
            try await signInOnTheWeb(instance)
            let own = try await nativeSignIn(instance, scope: "kv")
            #expect(try await send(instance, .POST, "api/kv/theme", json: ["value": "dark"], bearer: own.accessToken).status == .ok)
            #expect(try await send(instance, .POST, "api/kv/theme", json: ["value": "light"]).status == .ok)

            #expect(try value(try await send(instance, .GET, "api/kv/theme", bearer: own.accessToken)) == "dark")
            #expect(try await send(instance, .GET, "api/kv/theme?namespace=shared", bearer: own.accessToken).status == .forbidden)

            let reader = try await consentTokens(instance, scope: "kv kv:shared:read", choosing: [KVScope.sharedRead])
            #expect(try await send(instance, .GET, "api/kv/theme", bearer: reader.accessToken).status == .notFound)
            #expect(try value(try await send(instance, .GET, "api/kv/theme?namespace=shared", bearer: reader.accessToken)) == "light")
            #expect(
                try await send(instance, .POST, "api/kv/theme?namespace=shared", json: ["value": "x"], bearer: reader.accessToken)
                    .status == .forbidden)
            #expect(
                try await send(instance, .GET, "api/kv/theme?namespace=\(namespace(Self.first))", bearer: reader.accessToken)
                    .status == .forbidden)

            #expect(try value(try await send(instance, .GET, "api/kv/theme")) == "light")
            #expect(try value(try await send(instance, .GET, "api/kv/theme?namespace=\(namespace(Self.first))")) == "dark")
        }
    }

    @Test("tokens without data scopes, from revoked grants or from another issuer are refused")
    func refusedTokens() async throws {
        try await withInstance { instance in
            let plan = try await nativeSignIn(instance, scope: "plan")
            #expect(try await send(instance, .GET, "api/kv", bearer: plan.accessToken).status == .forbidden)

            let kv = try await nativeSignIn(instance, scope: "kv")
            let grantID = try await instance.app.jwt.keys.verify(kv.accessToken, as: ThirdPartyAccessToken.self).grant
            let grant = try #require(try await ThirdPartyGrant.find(grantID, on: instance.app.db))
            let forged = try await instance.app.jwt.keys.sign(
                try ThirdPartyAccessToken(grant: grant, issuer: "https://elsewhere.test"), kid: ThirdPartyAccessController.kid)
            #expect(try await send(instance, .GET, "api/kv", bearer: forged).status == .unauthorized)

            try await send(
                instance, .POST, "t/oauth/revoke", form: RevocationRequest(token: kv.refreshToken, clientID: Self.first))
            #expect(try await send(instance, .GET, "api/kv", bearer: kv.accessToken).status == .unauthorized)

            instance.cookie = nil
            #expect(try await send(instance, .GET, "api/kv").status == .unauthorized)
        }
    }

    @Test("an app's data can be deleted once its access is gone")
    func appData() async throws {
        try await withInstance { instance in
            try await signInOnTheWeb(instance)
            let tokens = try await nativeSignIn(instance, scope: "kv")
            try await send(instance, .POST, "api/kv/nodes", json: ["value": "[]"], bearer: tokens.accessToken)

            let page = try await send(instance, .GET, "t/access").body.string
            #expect(page.contains("Data kept by apps"))
            #expect(page.contains("KeepTalking"))
            #expect(page.contains("Revoke access to delete"))

            func deletion() async throws -> ThirdPartyAccessController.AppDataDeletion {
                struct Options: Decodable { let challenge: URLEncodedBase64 }
                let options = try await send(
                    instance, .POST, "confirm", json: ["action": "delete-data:\(Self.first)"]
                ).content.decode(Options.self)
                return .init(namespace: Self.first, confirmation: try instance.passkey.assertion(over: options.challenge))
            }
            #expect(
                try await send(instance, .POST, "t/access/data/delete", form: ThirdPartyAccessController.AppDataDeletion(namespace: Self.first))
                    .status == .forbidden)
            #expect(try await send(instance, .POST, "t/access/data/delete", form: try await deletion()).status == .conflict)
            try await send(
                instance, .POST, "t/oauth/revoke", form: RevocationRequest(token: tokens.refreshToken, clientID: Self.first))
            #expect(try await send(instance, .POST, "t/access/data/delete", form: try await deletion()).status == .seeOther)
            #expect(try await KVRecord.query(on: instance.app.db).filter(\.$namespace == Self.first).count() == 0)
        }
    }

    @Test("data kept on the account before namespaces moves into the shared space")
    func storageMoves() async throws {
        try await withApp(configure: configure) { app in
            try await MoveUserStorageToKV().revert(on: app.db)
            let user = User(username: "old")
            try await user.save(on: app.db)
            try await (app.db as! any SQLDatabase)
                .raw("UPDATE users SET storage = \(bind: #"{"ktOwnedNodes":"[]"}"#) WHERE id = \(bind: try user.requireID())")
                .run()
            try await MoveUserStorageToKV().prepare(on: app.db)

            let records = try await KVRecord.query(on: app.db).all()
            #expect(records.map { "\($0.namespace) \($0.key) \($0.value)" } == ["shared ktOwnedNodes []"])
            #expect(records.first?.$user.id == user.id)
        }
    }
}
