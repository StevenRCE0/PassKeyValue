import Fluent
import Vapor
import WebAuthn

final class User: Model, Content, @unchecked Sendable {
    static let schema: String = "users"

    // cascading is not supported since serialisation seemed more flexible
    typealias KVKeyType = String
    typealias KVValueType = String
    //    enum KVValueType: Codable {
    //        case string (String)
    //        case int (Int)
    //        case float (Float)
    //        case boolean (Bool)
    //    }

    typealias KVType = [KVKeyType: KVValueType]

    @ID
    var id: UUID?

    @Field(key: "username")
    var username: String

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @Children(for: \.$user)
    var credentials: [WebAuthnCredential]

    @Field(key: "storage")
    var storage: KVType

    init() {}

    init(id: UUID? = nil, username: String) {
        self.id = id
        self.username = username
        self.storage = [:]
    }
}

extension User {
    var webAuthnUser: PublicKeyCredentialUserEntity {
        PublicKeyCredentialUserEntity(
            id: [UInt8](id!.uuidString.utf8), name: username, displayName: username)
    }
}

extension User: ModelSessionAuthenticatable {}
