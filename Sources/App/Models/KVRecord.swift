import Fluent
import Vapor

final class KVRecord: Model, @unchecked Sendable {
    static let schema = "kv_entries"
    static let shared = "shared"

    @ID
    var id: UUID?

    @Parent(key: "user_id")
    var user: User

    @Field(key: "namespace")
    var namespace: String

    @Field(key: "key")
    var key: String

    @Field(key: "value")
    var value: String

    @Timestamp(key: "updated_at", on: .update)
    var updatedAt: Date?

    init() {}

    init(userID: UUID, namespace: String, key: String, value: String) {
        self.$user.id = userID
        self.namespace = namespace
        self.key = key
        self.value = value
    }
}

struct CreateKVRecord: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema(KVRecord.schema)
            .id()
            .field("user_id", .uuid, .required, .references("users", "id", onDelete: .cascade))
            .field("namespace", .string, .required)
            .field("key", .string, .required)
            .field("value", .string, .required)
            .field("updated_at", .datetime)
            .unique(on: "user_id", "namespace", "key")
            .create()
    }

    func revert(on database: any Database) async throws {
        try await database.schema(KVRecord.schema).delete()
    }
}

struct MoveUserStorageToKV: AsyncMigration {
    private final class StoredUser: Model, @unchecked Sendable {
        static let schema = "users"

        @ID
        var id: UUID?

        @OptionalField(key: "storage")
        var storage: [String: String]?
    }

    func prepare(on database: any Database) async throws {
        try await database.transaction { db in
            for user in try await StoredUser.query(on: db).all() {
                for (key, value) in user.storage ?? [:] {
                    try await KVRecord(userID: try user.requireID(), namespace: KVRecord.shared, key: key, value: value)
                        .create(on: db)
                }
            }
        }
        try await database.schema("users").deleteField("storage").update()
    }

    func revert(on database: any Database) async throws {
        try await database.schema("users").field("storage", .dictionary(of: .string)).update()
    }
}
