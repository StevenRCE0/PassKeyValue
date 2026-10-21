import JWT
import Vapor

/// A service users can grant access to. Configured in `THIRD_PARTY_SERVICES`,
/// keyed by the service's identifier:
///
///     {"keeptalking-gateway": {"name": "KeepTalking Plan",
///       "scopes": {"plan:link": "Link your subscription to this account"}}}
struct ThirdPartyService: Codable, Sendable {
    var name: String
    /// Each scope the service may be granted, with what it lets the service
    /// do, as shown to the user.
    var scopes: [String: String]
}

struct ThirdPartyScope: Content {
    let id: String
    let description: String
}

struct ThirdPartyServiceSummary: Content {
    let id: String
    let name: String
    let scopes: [ThirdPartyScope]
}

/// Grant a service scopes, or request an assertion under a grant.
struct ThirdPartyAccessRequest: Content {
    let service: String
    let scopes: [String]
}

struct ThirdPartyGrantSummary: Content {
    let id: UUID
    let service: String
    let serviceName: String
    let scopes: [ThirdPartyScope]
    let createdAt: Date?
    let lastUsedAt: Date?
}

struct ThirdPartyAssertionResponse: Content {
    let assertion: String
    let expiresAt: Date
}

/// "The bearer is signed in as `subject`, and `audience` may act on that
/// account for `scope`", for five minutes, under the grant `grant`.
struct ThirdPartyAssertion: JWTPayload {
    static let lifetime: TimeInterval = 5 * 60

    enum CodingKeys: String, CodingKey {
        case subject = "sub"
        case audience = "aud"
        case scope
        case grant
        case issuedAt = "iat"
        case expiration = "exp"
        case id = "jti"
    }

    var subject: SubjectClaim
    var audience: AudienceClaim
    /// Space-separated, as in OAuth.
    var scope: String
    var grant: UUID
    var issuedAt: IssuedAtClaim
    var expiration: ExpirationClaim
    var id: IDClaim

    init(userID: UUID, grant: ThirdPartyGrant, scopes: Set<String>, now: Date = .now) throws {
        subject = .init(value: userID.uuidString)
        audience = .init(value: grant.service)
        scope = scopes.sorted().joined(separator: " ")
        self.grant = try grant.requireID()
        issuedAt = .init(value: now)
        expiration = .init(value: now.addingTimeInterval(Self.lifetime))
        id = .init(value: UUID().uuidString)
    }

    var scopes: Set<String> { Set(scope.split(separator: " ").map(String.init)) }

    func verify(using _: some JWTAlgorithm) async throws {
        try expiration.verifyNotExpired()
    }
}

extension JWKS: @retroactive Content {}
