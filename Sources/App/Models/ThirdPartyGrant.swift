import Fluent
import Vapor

/// A user's consent for a third-party service to act on their account with
/// some scopes. Assertions for the service are only issued under an active
/// grant, and the user can revoke it from the website or the API at any time.
final class ThirdPartyGrant: Model, @unchecked Sendable {
    static let schema = "third_party_grants"

    @ID
    var id: UUID?

    @Parent(key: "user_id")
    var user: User

    /// The service's identifier: the assertions' audience.
    @Field(key: "service")
    var service: String

    @Field(key: "scopes")
    var scopes: [String]

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    /// When an assertion was last issued under this grant.
    @OptionalField(key: "last_used_at")
    var lastUsedAt: Date?

    /// Set on revocation; a revoked grant is kept for the record but never used.
    @OptionalField(key: "revoked_at")
    var revokedAt: Date?

    init() {}

    init(userID: UUID, service: String, scopes: Set<String>) {
        self.$user.id = userID
        self.service = service
        self.scopes = scopes.sorted()
    }

    /// The user's active grant for `service`, if any.
    static func active(userID: UUID, service: String, on db: any Database) async throws -> ThirdPartyGrant? {
        try await query(on: db)
            .filter(\.$user.$id == userID)
            .filter(\.$service == service)
            .filter(\.$revokedAt == nil)
            .first()
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
