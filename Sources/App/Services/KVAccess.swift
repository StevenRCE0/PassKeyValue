import Vapor

struct KVAccess: Authenticatable {
    let userID: UUID
    let own: String
    let scopes: Set<String>
    let isOwner: Bool

    init(owner: UUID) {
        userID = owner
        own = KVRecord.shared
        scopes = []
        isOwner = true
    }

    init(bearer token: String, on req: Request) async throws {
        guard let access = try? await req.jwt.verify(token, as: ThirdPartyAccessToken.self),
            access.issuer.value == req.application.thirdParty.issuer,
            let grant = try await ThirdPartyGrant.find(access.grant, on: req.db),
            grant.revokedAt == nil,
            grant.$user.id.uuidString == access.subject.value,
            access.audience.value.contains(grant.service)
        else {
            throw Abort(.unauthorized, reason: "That access token isn't valid.")
        }
        let scopes = access.scopes.intersection(grant.scopes)
        guard !scopes.isDisjoint(with: KVScope.descriptions.keys) else {
            throw Abort(.forbidden, reason: "That access doesn't cover your data.")
        }
        userID = grant.$user.id
        own = grant.service
        self.scopes = scopes
        isOwner = false
    }

    func namespace(_ requested: String?, writing: Bool) throws -> String {
        let namespace = requested ?? (isOwner || scopes.contains(KVScope.own) ? own : KVRecord.shared)
        let allowed =
            if isOwner {
                true
            } else if namespace == own {
                scopes.contains(KVScope.own)
            } else if namespace == KVRecord.shared {
                scopes.contains(writing ? KVScope.sharedWrite : KVScope.sharedRead)
            } else {
                false
            }
        guard allowed else { throw Abort(.forbidden, reason: "That data isn't covered by this app's access.") }
        return namespace
    }
}

struct KVAccessAuthenticator: AsyncMiddleware {
    func respond(to req: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        if let bearer = req.headers.bearerAuthorization {
            req.auth.login(try await KVAccess(bearer: bearer.token, on: req))
        } else if let user = req.auth.get(User.self) {
            req.auth.login(KVAccess(owner: try user.requireID()))
        } else {
            throw Abort(.unauthorized)
        }
        return try await next.respond(to: req)
    }
}
