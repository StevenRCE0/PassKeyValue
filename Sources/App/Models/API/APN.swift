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
    let handle: APNWakeHandle
    let contextEnvelope: APNContextWakeEnvelope?
    let actionEnvelope: APNAsymmetricCipherEnvelope?
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
