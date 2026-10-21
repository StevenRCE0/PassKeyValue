import Fluent
import JWT
import Vapor

/// Third-party access: a signed-in user grants a configured service some
/// scopes, and the user's clients can then get short-lived assertions that
/// tell the service which account it is acting for. The service verifies them
/// against `/.well-known/jwks.json`, with no cookie or shared secret.
///
/// Grants are listed and revoked by the user, through the API and on the
/// `/access` page. Revoking stops new assertions at once; one already issued
/// lapses within five minutes.
struct ThirdPartyAccessController: RouteCollection {
    static let kid: JWKIdentifier = "third-party"

    let services: [String: ThirdPartyService]
    /// The signing key's public half; `nil` when no key is configured, which
    /// leaves grants manageable but issues no assertions.
    let jwks: JWKS?

    init(publicKey: ES256PublicKey?, services: [String: ThirdPartyService]) {
        jwks = publicKey?.parameters.map { x, y in
            JWKS(keys: [.ecdsa(.es256, identifier: Self.kid, x: x.base64URL, y: y.base64URL, curve: .p256)])
        }
        self.services = services
    }

    func boot(routes: any RoutesBuilder) throws {
        let signedIn = routes.grouped(User.sessionAuthenticator())
        let api = signedIn.grouped(User.guardMiddleware()).grouped("api", "access")
        api.get("services", use: listServices)
        api.get("grants", use: listGrants)
        api.post("grants", use: grant)
        api.delete("grants", ":grantID", use: revoke)
        api.post("assertions", use: assertion)

        let page = signedIn.grouped(User.redirectMiddleware(path: "/"))
        page.get("access", use: accessPage)
        page.post("access", ":grantID", "revoke", use: revokeFromPage)

        routes.get(".well-known", "jwks.json") { _ in
            guard let jwks else { throw Abort(.notFound) }
            return jwks
        }
    }

    // MARK: - Website

    struct AccessPage: Encodable {
        let title = "Third-Party Access"
        let username: String
        let grants: [ThirdPartyGrantSummary]
    }

    func accessPage(req: Request) async throws -> View {
        let user = try req.auth.require(User.self)
        return try await req.view.render(
            "access", AccessPage(username: user.username, grants: try await listGrants(req: req)))
    }

    func revokeFromPage(req: Request) async throws -> Response {
        _ = try await revoke(req: req)
        return req.redirect(to: "/access")
    }

    // MARK: - API

    func listServices(req: Request) async throws -> [ThirdPartyServiceSummary] {
        services.keys.sorted().map { summary(of: $0) }
    }

    func listGrants(req: Request) async throws -> [ThirdPartyGrantSummary] {
        let userID = try req.auth.require(User.self).requireID()
        return try await ThirdPartyGrant.query(on: req.db)
            .filter(\.$user.$id == userID)
            .filter(\.$revokedAt == nil)
            .sort(\.$createdAt)
            .all()
            .map(summary(of:))
    }

    /// Grants `scopes` to a service, adding to an active grant if there is one.
    func grant(req: Request) async throws -> ThirdPartyGrantSummary {
        let userID = try req.auth.require(User.self).requireID()
        let request = try req.content.decode(ThirdPartyAccessRequest.self)
        let scopes = try validScopes(request)
        let grant = try await ThirdPartyGrant.active(userID: userID, service: request.service, on: req.db)
            ?? ThirdPartyGrant(userID: userID, service: request.service, scopes: [])
        grant.scopes = Set(grant.scopes).union(scopes).sorted()
        try await grant.save(on: req.db)
        return try summary(of: grant)
    }

    func revoke(req: Request) async throws -> HTTPStatus {
        let userID = try req.auth.require(User.self).requireID()
        guard let grant = try await ThirdPartyGrant.find(req.parameters.get("grantID"), on: req.db),
            grant.$user.id == userID, grant.revokedAt == nil
        else { throw Abort(.notFound, reason: "No such grant.") }
        grant.revokedAt = .now
        try await grant.save(on: req.db)
        return .noContent
    }

    /// An assertion for a service, within what the user granted it.
    func assertion(req: Request) async throws -> ThirdPartyAssertionResponse {
        guard jwks != nil else { throw Abort(.serviceUnavailable, reason: "Third-party assertions aren't configured.") }
        let userID = try req.auth.require(User.self).requireID()
        let request = try req.content.decode(ThirdPartyAccessRequest.self)
        let scopes = try validScopes(request)
        guard let grant = try await ThirdPartyGrant.active(userID: userID, service: request.service, on: req.db),
            scopes.isSubset(of: grant.scopes)
        else { throw Abort(.forbidden, reason: "This account hasn't granted that access.") }
        grant.lastUsedAt = .now
        try await grant.save(on: req.db)
        let payload = try ThirdPartyAssertion(userID: userID, grant: grant, scopes: scopes)
        return ThirdPartyAssertionResponse(
            assertion: try await req.jwt.sign(payload, kid: Self.kid),
            expiresAt: payload.expiration.value
        )
    }

    /// The requested scopes, if the service exists and offers all of them.
    private func validScopes(_ request: ThirdPartyAccessRequest) throws -> Set<String> {
        let scopes = Set(request.scopes)
        guard let service = services[request.service], !scopes.isEmpty,
            scopes.isSubset(of: service.scopes.keys)
        else { throw Abort(.badRequest, reason: "Unknown service or scope.") }
        return scopes
    }

    private func summary(of id: String) -> ThirdPartyServiceSummary {
        let service = services[id]
        return ThirdPartyServiceSummary(
            id: id,
            name: service?.name ?? id,
            scopes: (service?.scopes ?? [:]).sorted { $0.key < $1.key }
                .map { ThirdPartyScope(id: $0.key, description: $0.value) }
        )
    }

    private func summary(of grant: ThirdPartyGrant) throws -> ThirdPartyGrantSummary {
        let service = services[grant.service]
        return ThirdPartyGrantSummary(
            id: try grant.requireID(),
            service: grant.service,
            serviceName: service?.name ?? grant.service,
            scopes: grant.scopes.map { ThirdPartyScope(id: $0, description: service?.scopes[$0] ?? $0) },
            createdAt: grant.createdAt,
            lastUsedAt: grant.lastUsedAt
        )
    }
}

private extension String {
    /// JWK coordinates are base64url without padding (RFC 7518 §6.2.1);
    /// JWTKit hands them over in standard base64.
    var base64URL: String {
        replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
