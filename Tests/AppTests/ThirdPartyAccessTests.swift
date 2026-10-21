import JWT
import Testing
import VaporTesting

@testable import App

@Suite("Third-party access", .serialized)
struct ThirdPartyAccessTests {
    private static let services: [String: ThirdPartyService] = [
        "keeptalking-gateway": .init(
            name: "KeepTalking Plan",
            scopes: ["plan:link": "Link your subscription", "plan:access": "Use your plan on other devices"]),
        "other-service": .init(name: "Other", scopes: ["profile:read": "Read your profile"]),
    ]

    /// Who the next request is from; set by each test.
    private final class Session: @unchecked Sendable {
        var user: User?
    }

    private func withAccess(
        signingKey: ES256PrivateKey? = ES256PrivateKey(),
        _ body: (Application, Session) async throws -> Void
    ) async throws {
        try await withApp(configure: configure) { app in
            if let signingKey {
                await app.jwt.keys.add(ecdsa: signingKey, kid: ThirdPartyAccessController.kid)
            }
            let session = Session()
            let controller = ThirdPartyAccessController(publicKey: signingKey?.publicKey, services: Self.services)
            // A fresh router under /t, so configure's own registration (no
            // key, no services) stays out of the way.
            try app.grouped("t").grouped(SessionUser(session: session)).register(collection: controller)
            try await body(app, session)
        }
    }

    /// Logs the session's user in, standing in for a passkey session.
    private struct SessionUser: AsyncMiddleware {
        let session: Session

        func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
            if let user = session.user { request.auth.login(user) }
            return try await next.respond(to: request)
        }
    }

    private func signUp(_ name: String, on app: Application) async throws -> User {
        let user = User(username: name)
        try await user.save(on: app.db)
        return user
    }

    private func post(
        _ app: Application, _ path: String, service: String, scopes: [String]
    ) async throws -> TestingHTTPResponse {
        var result: TestingHTTPResponse?
        try await app.testing().test(
            .POST, "t/api/access/\(path)",
            beforeRequest: { try $0.content.encode(ThirdPartyAccessRequest(service: service, scopes: scopes)) },
            afterResponse: { result = $0 }
        )
        return try #require(result)
    }

    private func grants(_ app: Application) async throws -> [ThirdPartyGrantSummary] {
        var grants: [ThirdPartyGrantSummary] = []
        try await app.testing().test(.GET, "t/api/access/grants") {
            grants = try $0.content.decode([ThirdPartyGrantSummary].self)
        }
        return grants
    }

    @Test("an assertion under a grant verifies against the published key set")
    func assertionVerifies() async throws {
        try await withAccess { app, session in
            let user = try await signUp("ada", on: app)
            session.user = user
            #expect(try await post(app, "grants", service: "keeptalking-gateway", scopes: ["plan:link"]).status == .ok)

            let minted = try await post(app, "assertions", service: "keeptalking-gateway", scopes: ["plan:link"])
                .content.decode(ThirdPartyAssertionResponse.self)
            var jwks: JWKS?
            try await app.testing().test(.GET, "t/.well-known/jwks.json") { jwks = try $0.content.decode(JWKS.self) }

            // Coordinates are base64url, as RFC 7518 requires.
            let key = try #require(jwks?.keys.first)
            for coordinate in [key.x, key.y] {
                #expect(coordinate?.contains(where: { "+/=".contains($0) }) == false)
            }
            // What a relying service does: the public key set only, no secret.
            let keys = try await JWTKeyCollection().add(jwks: #require(jwks))
            let payload = try await keys.verify(minted.assertion, as: ThirdPartyAssertion.self)
            #expect(payload.subject.value == user.id?.uuidString)
            try payload.audience.verifyIntendedAudience(includes: "keeptalking-gateway")
            #expect(payload.scopes == ["plan:link"])

            let listed = try await grants(app)
            #expect(listed.map(\.id) == [payload.grant])
            #expect(listed.first?.serviceName == "KeepTalking Plan")
            #expect(listed.first?.lastUsedAt != nil)
        }
    }

    @Test("assertions stay within what was granted")
    func assertionsNeedAGrant() async throws {
        try await withAccess { app, session in
            session.user = try await signUp("ada", on: app)
            // Nothing granted yet.
            #expect(try await post(app, "assertions", service: "keeptalking-gateway", scopes: ["plan:link"]).status == .forbidden)

            _ = try await post(app, "grants", service: "keeptalking-gateway", scopes: ["plan:link"])
            #expect(try await post(app, "assertions", service: "keeptalking-gateway", scopes: ["plan:access"]).status == .forbidden)
            #expect(try await post(app, "assertions", service: "other-service", scopes: ["profile:read"]).status == .forbidden)

            // Granting more widens the same grant.
            _ = try await post(app, "grants", service: "keeptalking-gateway", scopes: ["plan:access"])
            #expect(try await post(app, "assertions", service: "keeptalking-gateway", scopes: ["plan:link", "plan:access"]).status == .ok)
            #expect(try await grants(app).count == 1)
        }
    }

    @Test("only configured services and scopes can be granted")
    func grantsAreBounded() async throws {
        try await withAccess { app, session in
            session.user = try await signUp("ada", on: app)
            for (service, scopes) in [
                ("someone-else", ["plan:link"]),
                ("keeptalking-gateway", ["profile:read"]),
                ("keeptalking-gateway", ["plan:link", "admin"]),
                ("keeptalking-gateway", []),
            ] {
                let status = try await post(app, "grants", service: service, scopes: scopes).status
                #expect(status == .badRequest, "\(service) \(scopes)")
            }
            #expect(try await grants(app).isEmpty)
        }
    }

    @Test("revoking stops assertions, and only the owner can revoke")
    func revocation() async throws {
        try await withAccess { app, session in
            let ada = try await signUp("ada", on: app)
            session.user = ada
            let grant = try await post(app, "grants", service: "keeptalking-gateway", scopes: ["plan:link"])
                .content.decode(ThirdPartyGrantSummary.self)

            session.user = try await signUp("bob", on: app)
            try await app.testing().test(.DELETE, "t/api/access/grants/\(grant.id)") { #expect($0.status == .notFound) }

            session.user = ada
            try await app.testing().test(.DELETE, "t/api/access/grants/\(grant.id)") { #expect($0.status == .noContent) }
            #expect(try await grants(app).isEmpty)
            #expect(try await post(app, "assertions", service: "keeptalking-gateway", scopes: ["plan:link"]).status == .forbidden)
            try await app.testing().test(.DELETE, "t/api/access/grants/\(grant.id)") { #expect($0.status == .notFound) }
        }
    }

    @Test("the access page lists grants and revokes them")
    func accessPage() async throws {
        try await withAccess { app, session in
            session.user = try await signUp("ada", on: app)
            let grant = try await post(app, "grants", service: "keeptalking-gateway", scopes: ["plan:link"])
                .content.decode(ThirdPartyGrantSummary.self)

            try await app.testing().test(.GET, "t/access") { res in
                #expect(res.status == .ok)
                #expect(res.body.string.contains("KeepTalking Plan"))
                #expect(res.body.string.contains("Link your subscription"))
            }
            try await app.testing().test(.POST, "t/access/\(grant.id)/revoke") { #expect($0.status == .seeOther) }
            #expect(try await grants(app).isEmpty)
        }
    }

    @Test("everything needs a signed-in account")
    func requiresSession() async throws {
        try await withAccess { app, _ in
            #expect(try await post(app, "grants", service: "keeptalking-gateway", scopes: ["plan:link"]).status == .unauthorized)
            #expect(try await post(app, "assertions", service: "keeptalking-gateway", scopes: ["plan:link"]).status == .unauthorized)
            try await app.testing().test(.GET, "t/access") { #expect($0.status == .seeOther) }
        }
    }

    @Test("without a signing key, grants still work but nothing is asserted")
    func withoutSigningKey() async throws {
        try await withAccess(signingKey: nil) { app, session in
            session.user = try await signUp("ada", on: app)
            #expect(try await post(app, "grants", service: "keeptalking-gateway", scopes: ["plan:link"]).status == .ok)
            #expect(try await post(app, "assertions", service: "keeptalking-gateway", scopes: ["plan:link"]).status == .serviceUnavailable)
            try await app.testing().test(.GET, "t/.well-known/jwks.json") { #expect($0.status == .notFound) }
        }
    }
}
