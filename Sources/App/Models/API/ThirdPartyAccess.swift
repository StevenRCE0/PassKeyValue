import JWT
import Vapor
import WebAuthn

struct ThirdPartyClient: Content {
    static let loopbackHosts: Set<String> = ["127.0.0.1", "::1", "[::1]"]

    let clientID: String
    let clientName: String
    let redirectURIs: [String]
    let scopeDescriptions: [String: String]
    let revocationNoticeURI: String?

    enum CodingKeys: String, CodingKey {
        case clientID = "client_id"
        case clientName = "client_name"
        case redirectURIs = "redirect_uris"
        case scopeDescriptions = "scope_descriptions"
        case revocationNoticeURI = "revocation_notice_uri"
    }

    func allows(redirectURI: String) -> Bool {
        redirectURIs.contains(redirectURI) || redirectURIs.contains { Self.sameLoopback($0, redirectURI) }
    }

    // RFC 8252 §7.3: a loopback redirect matches on any port.
    private static func sameLoopback(_ registered: String, _ requested: String) -> Bool {
        guard var registered = URLComponents(string: registered), var requested = URLComponents(string: requested),
            registered.scheme == "http", requested.scheme == "http",
            let host = registered.host, loopbackHosts.contains(host), requested.host == host
        else { return false }
        registered.port = nil
        requested.port = nil
        return registered == requested
    }
}

struct ThirdPartyScope: Content {
    let id: String
    let description: String
    var isOptional = false
}

enum KVScope {
    static let own = "kv"
    static let sharedRead = "kv:shared:read"
    static let sharedWrite = "kv:shared:write"

    static let descriptions = [
        own: "Keep its own data in your account",
        sharedRead: "Read your shared data",
        sharedWrite: "Change your shared data",
    ]

    static func isOptional(_ scope: String) -> Bool {
        scope == sharedRead || scope == sharedWrite
    }
}

struct ThirdPartyGrantSummary: Content {
    let id: UUID
    let service: String
    let serviceName: String
    let serviceDomain: String?
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
        case service, scopes, state, allowlisted, native
        case serviceName = "service_name"
        case scopeDescriptions = "scope_descriptions"
        case revocationURL = "revocation_url"
        case redirectURI = "redirect_uri"
        case codeChallenge = "code_challenge"
        case passkeyChallenge = "passkey_challenge"
    }

    var audience: AudienceClaim
    var expiration: ExpirationClaim
    var service: String
    var scopes: [String]
    var allowlisted: Bool
    var native: Bool
    var serviceName: String
    var scopeDescriptions: [String: String]
    var revocationURL: String?
    var redirectURI: String
    var state: String
    var codeChallenge: String
    var passkeyChallenge: URLEncodedBase64

    init(
        request: AuthorisationRequest, client: ThirdPartyClient, scopes: [String], allowlisted: Bool, native: Bool,
        passkeyChallenge: [UInt8], now: Date = .now
    ) {
        audience = .init(value: Self.audience)
        expiration = .init(value: now.addingTimeInterval(Self.lifetime))
        service = request.clientID
        self.scopes = scopes
        self.allowlisted = allowlisted
        self.native = native
        serviceName = client.clientName
        scopeDescriptions = client.scopeDescriptions.merging(KVScope.descriptions) { _, ours in ours }
            .filter { scopes.contains($0.key) }
        revocationURL = client.revocationNoticeURI
        redirectURI = request.redirectURI
        state = request.state
        codeChallenge = request.codeChallenge
        self.passkeyChallenge = passkeyChallenge.base64URLEncodedString()
    }

    func verify(using _: some JWTAlgorithm) async throws {
        try expiration.verifyNotExpired()
        try audience.verifyIntendedAudience(includes: Self.audience)
    }

    var firstParty: Bool { allowlisted && native }

    func granted(choosing chosen: [String]?) -> [String] {
        guard !allowlisted else { return scopes }
        return scopes.filter { !KVScope.isOptional($0) || chosen?.contains($0) == true }
    }
}

struct AuthorisationDecision: Content {
    let ticket: String
    let approve: Bool
    let credential: String?
    let scopes: [String]?
}

struct AuthorisationChallengeRequest: Content {
    let clientID: String?
    let scope: String?
    let codeChallenge: String?
    let codeChallengeMethod: String?
    let authSession: String?
    let passkey: String?
    let name: String?
    let signupSession: String?
    let passkeyRegistration: String?

    enum CodingKeys: String, CodingKey {
        case clientID = "client_id"
        case scope
        case codeChallenge = "code_challenge"
        case codeChallengeMethod = "code_challenge_method"
        case authSession = "auth_session"
        case passkey, name
        case signupSession = "signup_session"
        case passkeyRegistration = "passkey_registration"
    }
}

struct AuthorisationChallengeResponse: Encodable, AsyncResponseEncodable {
    var status: HTTPResponseStatus = .badRequest
    var authorizationCode: String?
    var error: String?
    var errorDescription: String?
    var authSession: String?
    var passkey: PublicKeyCredentialRequestOptions?
    var signupSession: String?
    var passkeyRegistration: PublicKeyCredentialCreationOptions?

    enum CodingKeys: String, CodingKey {
        case authorizationCode = "authorization_code"
        case error
        case errorDescription = "error_description"
        case authSession = "auth_session"
        case passkey
        case signupSession = "signup_session"
        case passkeyRegistration = "passkey_registration"
    }

    static func code(_ value: String) -> Self {
        Self(status: .ok, authorizationCode: value)
    }

    static func failure(_ error: String, _ description: String?) -> Self {
        Self(error: error, errorDescription: description)
    }

    func encodeResponse(for request: Request) async throws -> Response {
        var headers = HTTPHeaders()
        headers.contentType = .json
        headers.cacheControl = .init(noStore: true)
        return Response(status: status, headers: headers, body: .init(data: try JSONEncoder().encode(self)))
    }
}

struct SignupRequest: Content {
    let ticket: String
    let name: String
}

struct SignupAnswer: Decodable {
    let ticket: String
    let signup: String
    let credential: RegistrationCredential
    let scopes: [String]?
}

struct SignupTicket: JWTPayload {
    static let audience = "passkv-signup"

    enum CodingKeys: String, CodingKey {
        case audience = "aud"
        case expiration = "exp"
        case user, username, ticket
        case passkeyChallenge = "passkey_challenge"
    }

    var audience: AudienceClaim
    var expiration: ExpirationClaim
    var user: UUID
    var username: String
    var ticket: String
    var passkeyChallenge: URLEncodedBase64

    init(user: UUID, username: String, ticket: String, passkeyChallenge: [UInt8], now: Date = .now) {
        audience = .init(value: Self.audience)
        expiration = .init(value: now.addingTimeInterval(AuthorisationTicket.lifetime))
        self.user = user
        self.username = username
        self.ticket = OpaqueToken.hash(ticket)
        self.passkeyChallenge = passkeyChallenge.base64URLEncodedString()
    }

    func verify(using _: some JWTAlgorithm) async throws {
        try expiration.verifyNotExpired()
        try audience.verifyIntendedAudience(includes: Self.audience)
    }
}

struct AuthorisationAnswer: Content {
    let code: String
    let state: String
    let redirect: String
}

struct PasskeyChallenge<Options: Encodable>: AsyncResponseEncodable, Encodable {
    let ticket: String
    let options: Options

    func encodeResponse(for request: Request) async throws -> Response {
        var headers = HTTPHeaders()
        headers.contentType = .json
        return Response(status: .ok, headers: headers, body: .init(data: try JSONEncoder().encode(self)))
    }
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
        case issuer = "iss"
        case subject = "sub"
        case audience = "aud"
        case scope
        case grant
        case issuedAt = "iat"
        case expiration = "exp"
        case id = "jti"
    }

    var issuer: IssuerClaim
    var subject: SubjectClaim
    var audience: AudienceClaim
    var scope: String
    var grant: UUID
    var issuedAt: IssuedAtClaim
    var expiration: ExpirationClaim
    var id: IDClaim

    init(grant: ThirdPartyGrant, issuer: String, now: Date = .now) throws {
        self.issuer = .init(value: issuer)
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
        case issuer = "iss"
        case subject = "sub"
        case audience = "aud"
        case scope
        case grant
        case revokedAt = "revoked_at"
        case issuedAt = "iat"
        case expiration = "exp"
        case id = "jti"
    }

    var issuer: IssuerClaim
    var subject: SubjectClaim
    var audience: AudienceClaim
    var scope: String
    var grant: UUID
    var revokedAt: Date
    var issuedAt: IssuedAtClaim
    var expiration: ExpirationClaim
    var id: IDClaim

    init(grant: ThirdPartyGrant, issuer: String, now: Date = .now) throws {
        self.issuer = .init(value: issuer)
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
