import Fluent
import JWT
import Vapor

struct ThirdPartyAccessController: RouteCollection {
    static let kid: JWKIdentifier = "third-party"

    let jwks: JWKS?

    init(publicKey: ES256PublicKey?) {
        jwks = publicKey?.parameters.map { x, y in
            JWKS(keys: [.ecdsa(.es256, identifier: Self.kid, x: x.base64URL, y: y.base64URL, curve: .p256)])
        }
    }

    func boot(routes: any RoutesBuilder) throws {
        let signedIn = routes.grouped(User.sessionAuthenticator())
        let api = signedIn.grouped(User.guardMiddleware()).grouped("api", "access")
        api.get("grants", use: listGrants)
        api.delete("grants", ":grantID", use: revoke)

        let page = signedIn.grouped(User.redirectMiddleware(path: "/"))
        page.get("access", use: accessPage)
        page.post("access", ":grantID", "revoke", use: revokeFromPage)
        page.post("access", "data", "delete", use: deleteAppData)

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
        let appData: [AppData]
    }

    struct AppData: Encodable {
        let namespace: String
        let name: String
        let domain: String?
        let count: Int
        let hasAccess: Bool
    }

    struct AppDataDeletion: Content {
        let namespace: String
        var confirmation: String?
    }

    func accessPage(req: Request) async throws -> View {
        let user = try req.auth.require(User.self)
        let grants = try await listGrants(req: req)
        return try await req.view.render(
            "access",
            AccessPage(username: user.username, grants: grants, appData: try await appData(of: user, grants: grants, on: req)))
    }

    func deleteAppData(req: Request) async throws -> Response {
        let userID = try req.auth.require(User.self).requireID()
        let deletion = try req.content.decode(AppDataDeletion.self)
        guard deletion.namespace != KVRecord.shared else { throw Abort(.badRequest, reason: "That's your shared data.") }
        try await req.confirmPasskey(for: "delete-data:\(deletion.namespace)", answer: deletion.confirmation)
        let active = try await ThirdPartyGrant.query(on: req.db)
            .filter(\.$user.$id == userID)
            .filter(\.$service == deletion.namespace)
            .filter(\.$revokedAt == nil)
            .count()
        guard active == 0 else { throw Abort(.conflict, reason: "Revoke the app's access first.") }
        try await KVRecord.query(on: req.db)
            .filter(\.$user.$id == userID)
            .filter(\.$namespace == deletion.namespace)
            .delete()
        return req.redirect(to: "/access")
    }

    private func appData(of user: User, grants: [ThirdPartyGrantSummary], on req: Request) async throws -> [AppData] {
        let userID = try user.requireID()
        let records = try await KVRecord.query(on: req.db)
            .filter(\.$user.$id == userID)
            .filter(\.$namespace != KVRecord.shared)
            .all()
        let counts = Dictionary(grouping: records, by: \.namespace).mapValues(\.count)
        let names = try await ThirdPartyGrant.query(on: req.db)
            .filter(\.$user.$id == userID)
            .filter(\.$service ~~ Array(counts.keys))
            .all()
            .reduce(into: [String: String]()) { names, grant in names[grant.service] = grant.serviceName ?? names[grant.service] }
        return counts.keys.sorted().map { namespace in
            AppData(
                namespace: namespace, name: names[namespace] ?? namespace, domain: URL(string: namespace)?.host,
                count: counts[namespace] ?? 0, hasAccess: grants.contains { $0.service == namespace })
        }
    }

    func revokeFromPage(req: Request) async throws -> Response {
        _ = try await revoke(req: req)
        return req.redirect(to: "/access")
    }

    // MARK: - API

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
        try await req.confirmPasskey(
            for: "revoke:\(try grant.requireID())", answer: (try? req.content.decode(Confirmation.self))?.confirmation)
        try await grant.revoke(on: req.db, app: req.application)
        return .noContent
    }

    private func summary(of grant: ThirdPartyGrant) throws -> ThirdPartyGrantSummary {
        ThirdPartyGrantSummary(
            id: try grant.requireID(),
            service: grant.service,
            serviceName: grant.serviceName ?? grant.service,
            serviceDomain: URL(string: grant.service)?.host,
            scopes: grant.scopes.map { ThirdPartyScope(id: $0, description: grant.scopeDescriptions?[$0] ?? $0) },
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
