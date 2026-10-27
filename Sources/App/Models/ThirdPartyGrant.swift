import Fluent
import Vapor

final class ThirdPartyGrant: Model, @unchecked Sendable {
    static let schema = "third_party_grants"

    @ID
    var id: UUID?

    @Parent(key: "user_id")
    var user: User

    @Field(key: "service")
    var service: String

    @Field(key: "scopes")
    var scopes: [String]

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @OptionalField(key: "last_used_at")
    var lastUsedAt: Date?

    @OptionalField(key: "revoked_at")
    var revokedAt: Date?

    @Children(for: \.$grant)
    var refreshTokens: [RefreshToken]

    init() {}

    init(userID: UUID, service: String, scopes: [String]) {
        self.$user.id = userID
        self.service = service
        self.scopes = scopes.sorted()
    }

    func revoke(announcingTo revocationURL: String?, on db: any Database, app: Application) async throws {
        guard revokedAt == nil else { return }
        revokedAt = .now
        try await save(on: db)
        try await RefreshToken.query(on: db).filter(\.$grant.$id == requireID()).delete()
        if let revocationURL {
            try await app.announceRevocation(of: self, to: revocationURL)
        }
    }
}

struct CreateThirdPartyGrant: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema(ThirdPartyGrant.schema)
            .id()
            .field("user_id", .uuid, .required, .references("users", "id", onDelete: .cascade))
            .field("service", .string, .required)
            .field("scopes", .array(of: .string), .required)
            .field("created_at", .datetime)
            .field("last_used_at", .datetime)
            .field("revoked_at", .datetime)
            .create()
    }

    func revert(on database: any Database) async throws {
        try await database.schema(ThirdPartyGrant.schema).delete()
    }
}

// MARK: - Authorisation codes

final class AuthorisationCode: Model, @unchecked Sendable {
    static let schema = "authorisation_codes"
    static let lifetime: TimeInterval = 60

    @ID
    var id: UUID?

    @Field(key: "code_hash")
    var codeHash: String

    @Parent(key: "user_id")
    var user: User

    @Field(key: "service")
    var service: String

    @Field(key: "scopes")
    var scopes: [String]

    @Field(key: "redirect_uri")
    var redirectURI: String

    @Field(key: "code_challenge")
    var codeChallenge: String

    @Field(key: "expires_at")
    var expiresAt: Date

    init() {}

    static func issue(for ticket: AuthorisationTicket, userID: UUID) -> (AuthorisationCode, String) {
        let value = OpaqueToken.generate()
        let code = AuthorisationCode()
        code.codeHash = OpaqueToken.hash(value)
        code.$user.id = userID
        code.service = ticket.service
        code.scopes = ticket.scopes
        code.redirectURI = ticket.redirectURI
        code.codeChallenge = ticket.codeChallenge
        code.expiresAt = .now.addingTimeInterval(lifetime)
        return (code, value)
    }

    func isAnswered(by verifier: String) -> Bool {
        Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncodedString() == codeChallenge
    }
}

struct CreateAuthorisationCode: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema(AuthorisationCode.schema)
            .id()
            .field("code_hash", .string, .required)
            .field("user_id", .uuid, .required, .references("users", "id", onDelete: .cascade))
            .field("service", .string, .required)
            .field("scopes", .array(of: .string), .required)
            .field("redirect_uri", .string, .required)
            .field("code_challenge", .string, .required)
            .field("expires_at", .datetime, .required)
            .unique(on: "code_hash")
            .create()
    }

    func revert(on database: any Database) async throws {
        try await database.schema(AuthorisationCode.schema).delete()
    }
}

// MARK: - Refresh tokens

final class RefreshToken: Model, @unchecked Sendable {
    static let schema = "refresh_tokens"

    @ID
    var id: UUID?

    @Field(key: "token_hash")
    var tokenHash: String

    @Parent(key: "grant_id")
    var grant: ThirdPartyGrant

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @OptionalField(key: "spent_at")
    var spentAt: Date?

    init() {}

    static func issue(for grant: ThirdPartyGrant) throws -> (RefreshToken, String) {
        let value = OpaqueToken.generate()
        let token = RefreshToken()
        token.tokenHash = OpaqueToken.hash(value)
        token.$grant.id = try grant.requireID()
        return (token, value)
    }
}

struct CreateRefreshToken: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema(RefreshToken.schema)
            .id()
            .field("token_hash", .string, .required)
            .field(
                "grant_id", .uuid, .required,
                .references(ThirdPartyGrant.schema, "id", onDelete: .cascade))
            .field("created_at", .datetime)
            .field("spent_at", .datetime)
            .unique(on: "token_hash")
            .create()
    }

    func revert(on database: any Database) async throws {
        try await database.schema(RefreshToken.schema).delete()
    }
}

enum OpaqueToken {
    static func generate() -> String {
        Data([UInt8].random(count: 32)).base64URLEncodedString()
    }

    static func hash(_ value: String) -> String {
        Data(SHA256.hash(data: Data(value.utf8))).base64URLEncodedString()
    }
}
