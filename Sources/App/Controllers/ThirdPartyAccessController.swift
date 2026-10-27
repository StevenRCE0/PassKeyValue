import Fluent
import JWT
import Vapor

struct ThirdPartyAccessController: RouteCollection {
    static let kid: JWKIdentifier = "third-party"

    let services: [String: ThirdPartyService]
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
        api.delete("grants", ":grantID", use: revoke)

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
        services.keys.sorted().map { id in
            let service = services[id]
            return ThirdPartyServiceSummary(id: id, name: service?.name ?? id, scopes: scopes(service?.scopes.keys.sorted() ?? [], of: id))
        }
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

    func revoke(req: Request) async throws -> HTTPStatus {
        let userID = try req.auth.require(User.self).requireID()
        guard let grant = try await ThirdPartyGrant.find(req.parameters.get("grantID"), on: req.db),
            grant.$user.id == userID, grant.revokedAt == nil
        else { throw Abort(.notFound, reason: "No such grant.") }
        try await grant.revoke(
            announcingTo: services[grant.service]?.revocationURL, on: req.db, app: req.application)
        return .noContent
    }

    private func scopes(_ ids: [String], of service: String) -> [ThirdPartyScope] {
        ids.map { ThirdPartyScope(id: $0, description: services[service]?.scopes[$0] ?? $0) }
    }

    private func summary(of grant: ThirdPartyGrant) throws -> ThirdPartyGrantSummary {
        ThirdPartyGrantSummary(
            id: try grant.requireID(),
            service: grant.service,
            serviceName: services[grant.service]?.name ?? grant.service,
            scopes: scopes(grant.scopes, of: grant.service),
            createdAt: grant.createdAt,
            lastUsedAt: grant.lastUsedAt
        )
    }
}

extension String {
    // JWTKit hands JWK coordinates over in standard base64; JWKS needs base64url.
    var base64URL: String {
        replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
