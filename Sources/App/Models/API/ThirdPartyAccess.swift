import JWT
import Vapor
import WebAuthn

struct ThirdPartyService: Codable, Sendable {
    var name: String
    var scopes: [String: String]
    var redirectURIs: [String]
    var revocationURL: String?
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

struct ThirdPartyGrantSummary: Content {
    let id: UUID
    let service: String
    let serviceName: String
    let scopes: [ThirdPartyScope]
    let createdAt: Date?
    let lastUsedAt: Date?
}

// MARK: - Authorisation code flow

struct AuthorisationRequest: Content {
    let responseType: String
    let clientID: String
    let redirectURI: String
    let scope: String
    let state: String
    let codeChallenge: String
    let codeChallengeMethod: String

    enum CodingKeys: String, CodingKey {
        case responseType = "response_type"
        case clientID = "client_id"
        case redirectURI = "redirect_uri"
        case scope, state
        case codeChallenge = "code_challenge"
        case codeChallengeMethod = "code_challenge_method"
    }
}

struct AuthorisationTicket: JWTPayload {
    static let audience = "passkv-consent"
    static let lifetime: TimeInterval = 5 * 60

    enum CodingKeys: String, CodingKey {
        case audience = "aud"
        case expiration = "exp"
        case service, scopes, state
        case redirectURI = "redirect_uri"
        case codeChallenge = "code_challenge"
        case passkeyChallenge = "passkey_challenge"
    }

    var audience: AudienceClaim
    var expiration: ExpirationClaim
    var service: String
    var scopes: [String]
    var redirectURI: String
    var state: String
    var codeChallenge: String
    var passkeyChallenge: URLEncodedBase64

    init(request: AuthorisationRequest, scopes: [String], passkeyChallenge: [UInt8], now: Date = .now) {
        audience = .init(value: Self.audience)
        expiration = .init(value: now.addingTimeInterval(Self.lifetime))
        service = request.clientID
        self.scopes = scopes
        redirectURI = request.redirectURI
        state = request.state
        codeChallenge = request.codeChallenge
        self.passkeyChallenge = passkeyChallenge.base64URLEncodedString()
    }

    func verify(using _: some JWTAlgorithm) async throws {
        try expiration.verifyNotExpired()
        try audience.verifyIntendedAudience(includes: Self.audience)
    }
}

struct AuthorisationDecision: Content {
    let ticket: String
    let approve: Bool
    let credential: String?
}

struct TokenRequest: Content {
    let grantType: String
    let clientID: String
    let code: String?
    let redirectURI: String?
    let codeVerifier: String?
    let refreshToken: String?

    enum CodingKeys: String, CodingKey {
        case grantType = "grant_type"
        case clientID = "client_id"
        case code
        case redirectURI = "redirect_uri"
        case codeVerifier = "code_verifier"
        case refreshToken = "refresh_token"
    }
}

struct TokenResponse: Content {
    let accessToken: String
    let tokenType = "Bearer"
    let expiresIn: Int
    let refreshToken: String
    let scope: String

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case refreshToken = "refresh_token"
        case scope
    }
}

struct RevocationRequest: Content {
    let token: String
    let clientID: String

    enum CodingKeys: String, CodingKey {
        case token
        case clientID = "client_id"
    }
}

// MARK: - Tokens

struct ThirdPartyAccessToken: JWTPayload {
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
    var scope: String
    var grant: UUID
    var issuedAt: IssuedAtClaim
    var expiration: ExpirationClaim
    var id: IDClaim

    init(grant: ThirdPartyGrant, now: Date = .now) throws {
        subject = .init(value: grant.$user.id.uuidString)
        audience = .init(value: grant.service)
        scope = grant.scopes.joined(separator: " ")
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

struct ThirdPartyRevocation: JWTPayload {
    static let lifetime: TimeInterval = 5 * 60

    enum CodingKeys: String, CodingKey {
        case subject = "sub"
        case audience = "aud"
        case scope
        case grant
        case revokedAt = "revoked_at"
        case issuedAt = "iat"
        case expiration = "exp"
        case id = "jti"
    }

    var subject: SubjectClaim
    var audience: AudienceClaim
    var scope: String
    var grant: UUID
    var revokedAt: Date
    var issuedAt: IssuedAtClaim
    var expiration: ExpirationClaim
    var id: IDClaim

    init(grant: ThirdPartyGrant, now: Date = .now) throws {
        subject = .init(value: grant.$user.id.uuidString)
        audience = .init(value: grant.service)
        scope = grant.scopes.joined(separator: " ")
        self.grant = try grant.requireID()
        revokedAt = grant.revokedAt ?? now
        issuedAt = .init(value: now)
        expiration = .init(value: now.addingTimeInterval(Self.lifetime))
        id = .init(value: UUID().uuidString)
    }

    func verify(using _: some JWTAlgorithm) async throws {
        try expiration.verifyNotExpired()
    }
}

extension JWKS: @retroactive Content {}
