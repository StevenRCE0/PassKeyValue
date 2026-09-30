import Vapor

enum APNWakePurpose: String, Content {
    case contextMessage = "context_message"
    case actionAuthorisation = "action_authorisation"
}

struct APNWakeHandle: Content {
    let id: UUID
    let purpose: APNWakePurpose
    let contextID: UUID?
    let relationID: UUID?
    let actionID: UUID?
    let opaqueValue: String
    let topic: String
    let environment: String
}

struct APNWakeMintScope: Content {
    let purpose: APNWakePurpose
    let contextID: UUID?
    let relationID: UUID?
    let actionID: UUID?
}

struct APNWakeMintRequest: Content {
    let token: String
    let topic: String
    let environment: String
    let scopes: [APNWakeMintScope]
}

struct APNWakeMintResponse: Content {
    let handles: [APNWakeHandle]
}

struct APNWakeSendRequest: Content {
    /// What the push carries. `.context` and `.revocation` ride a context
    /// handle, `.action` an action one.
    enum Wake: Codable {
        case context(envelope: APNContextWakeEnvelope)
        case action(envelope: APNAsymmetricCipherEnvelope)
        /// Takes back notifications for deleted messages, as a silent push.
        case revocation(envelope: APNContextWakeEnvelope)
    }

    let handle: APNWakeHandle
    let wake: Wake
}

struct APNWakeSendResponse: Content {
    let accepted: Bool
    let messageID: String?
}

struct APNContextWakeEnvelope: Content {
    let contextID: UUID
    let ciphertext: String
}

struct APNAsymmetricCipherEnvelope: Content {
    let senderNodeID: UUID
    let recipientNodeID: UUID
    let ciphertext: Data
}
