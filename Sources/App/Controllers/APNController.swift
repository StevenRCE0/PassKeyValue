#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation
import Vapor

struct APNController: RouteCollection {
    func boot(routes: any RoutesBuilder) throws {
        let apnRoutes = routes.grouped("api", "apn")

        apnRoutes.post("mint", use: mintHandler)
        apnRoutes.post("send", use: sendHandler)
    }

    private func mintHandler(req: Request) async throws -> APNWakeMintResponse {
        let payload = try req.content.decode(APNWakeMintRequest.self)

        let normalizedToken = payload.token.trimmingCharacters(
            in: .whitespacesAndNewlines
        )
        let normalizedTopic = payload.topic.trimmingCharacters(
            in: .whitespacesAndNewlines
        )
        let normalizedEnvironment = payload.environment.trimmingCharacters(
            in: .whitespacesAndNewlines
        )

        guard !normalizedToken.isEmpty else {
            throw Abort(.badRequest, reason: "APNs token is required.")
        }
        guard !normalizedTopic.isEmpty else {
            throw Abort(.badRequest, reason: "APNs topic is required.")
        }
        guard normalizedEnvironment == "development"
            || normalizedEnvironment == "production"
        else {
            throw Abort(
                .badRequest,
                reason: "APNs environment must be development or production."
            )
        }

        let sealer = try req.apnHandleSealer()
        let handles = try payload.scopes.map { scope in
            let handleID = UUID()
            let sealed = try sealer.seal(
                payload: APNSealedWakeHandle(
                    id: handleID,
                    purpose: scope.purpose,
                    contextID: scope.contextID,
                    relationID: scope.relationID,
                    actionID: scope.actionID,
                    token: normalizedToken,
                    topic: normalizedTopic,
                    environment: normalizedEnvironment
                )
            )
            return APNWakeHandle(
                id: handleID,
                purpose: scope.purpose,
                contextID: scope.contextID,
                relationID: scope.relationID,
                actionID: scope.actionID,
                opaqueValue: sealed,
                topic: normalizedTopic,
                environment: normalizedEnvironment
            )
        }

        return APNWakeMintResponse(handles: handles)
    }

    private func sendHandler(req: Request) async throws -> APNWakeSendResponse {
        let payload = try req.content.decode(APNWakeSendRequest.self)
        let sealer = try req.apnHandleSealer()
        let handlePayload = try sealer.open(payload.handle.opaqueValue)

        guard handlePayload.matches(payload.handle) else {
            throw Abort(.badRequest, reason: "Push wake handle mismatch.")
        }
        switch payload.handle.purpose {
            case .contextMessage:
                guard
                    let contextEnvelope = payload.contextEnvelope,
                    payload.actionEnvelope == nil,
                    contextEnvelope.contextID == payload.handle.contextID
                else {
                    throw Abort(
                        .badRequest,
                        reason: "Context wake payload mismatch."
                    )
                }
            case .actionAuthorisation:
                guard
                    let actionEnvelope = payload.actionEnvelope,
                    payload.contextEnvelope == nil
                else {
                    throw Abort(
                        .badRequest,
                        reason: "Action wake payload mismatch."
                    )
                }
                guard actionEnvelope.recipientNodeID != actionEnvelope.senderNodeID
                else {
                    throw Abort(
                        .badRequest,
                        reason: "Action wake sender and recipient must differ."
                    )
                }
        }

        let requestPayload = APNPushRequestPayload(
            handle: payload.handle,
            contextEnvelope: payload.contextEnvelope,
            actionEnvelope: payload.actionEnvelope
        )
        let encodedPayload = try JSONEncoder().encode(requestPayload)
        guard encodedPayload.count <= 4096 else {
            throw Abort(.payloadTooLarge, reason: "APNs payload exceeds 4 KB.")
        }

        let provider = try req.apnProvider()
        let response = try await provider.send(
            payload: encodedPayload,
            topic: handlePayload.topic,
            token: handlePayload.token,
            environment: handlePayload.environment,
            collapseID: collapseID(for: payload.handle)
        )

        guard (200 ... 299).contains(response.status.code) else {
            let body = response.body.flatMap {
                String(buffer: $0)
            } ?? "APNs delivery failed."
            throw Abort(response.status, reason: body)
        }

        return APNWakeSendResponse(
            accepted: true,
            messageID: response.headers.first(name: "apns-id")
        )
    }

    private func collapseID(for handle: APNWakeHandle) -> String {
        if let actionID = handle.actionID {
            return "action-\(actionID.uuidString.lowercased())"
        }
        if let contextID = handle.contextID {
            return "context-\(contextID.uuidString.lowercased())"
        }
        return "wake-\(handle.id.uuidString.lowercased())"
    }

}

private struct APNSealedWakeHandle: Codable {
    let id: UUID
    let purpose: APNWakePurpose
    let contextID: UUID?
    let relationID: UUID?
    let actionID: UUID?
    let token: String
    let topic: String
    let environment: String

    func matches(_ handle: APNWakeHandle) -> Bool {
        id == handle.id
            && purpose == handle.purpose
            && contextID == handle.contextID
            && relationID == handle.relationID
            && actionID == handle.actionID
            && topic == handle.topic
            && environment == handle.environment
    }
}

private struct APNPushRequestPayload: Codable {
    struct APS: Codable {
        struct Alert: Codable {
            let title: String
            let body: String
        }

        let alert: Alert
        let sound: String

        enum CodingKeys: String, CodingKey {
            case alert
            case sound
            case contentAvailable = "content-available"
            case mutableContent = "mutable-content"
        }

        let contentAvailable: Int
        let mutableContent: Int
    }

    let aps: APS
    let ktContextWake: APNContextWakeEnvelope?
    let ktActionWake: APNAsymmetricCipherEnvelope?

    enum CodingKeys: String, CodingKey {
        case aps
        case ktContextWake = "kt_context_wake"
        case ktActionWake = "kt_action_wake"
    }

    init(
        handle: APNWakeHandle,
        contextEnvelope: APNContextWakeEnvelope?,
        actionEnvelope: APNAsymmetricCipherEnvelope?
    ) {
        let fallbackTitle =
            switch handle.purpose {
                case .contextMessage:
                    "New KeepTalking activity"
                case .actionAuthorisation:
                    "Action approval requested"
            }
        let fallbackBody =
            switch handle.purpose {
                case .contextMessage:
                    "Open KeepTalking to sync the latest context activity."
                case .actionAuthorisation:
                    "Open KeepTalking to review and approve the remote action."
            }

        self.aps = APS(
            alert: .init(
                title: fallbackTitle,
                body: fallbackBody
            ),
            sound: "default",
            contentAvailable: 1,
            mutableContent: 1
        )
        self.ktContextWake = contextEnvelope
        self.ktActionWake = actionEnvelope
    }
}

private struct APNHandleSealer {
    private let key: SymmetricKey

    init(secret: String) throws {
        let material = Data(secret.utf8)
        guard material.count >= 32 else {
            throw Abort(
                .internalServerError,
                reason: "APN_HANDLE_SECRET must be at least 32 bytes."
            )
        }
        key = SymmetricKey(data: material)
    }

    func seal(payload: APNSealedWakeHandle) throws -> String {
        let encoded = try JSONEncoder().encode(payload)
        let sealed = try AES.GCM.seal(encoded, using: key)
        guard let combined = sealed.combined else {
            throw Abort(.internalServerError, reason: "Failed sealing APN handle.")
        }
        return combined.base64EncodedString()
    }

    func open(_ value: String) throws -> APNSealedWakeHandle {
        guard let combined = Data(base64Encoded: value),
            let sealedBox = try? AES.GCM.SealedBox(combined: combined)
        else {
            throw Abort(.badRequest, reason: "Invalid APN wake handle.")
        }
        let data = try AES.GCM.open(sealedBox, using: key)
        return try JSONDecoder().decode(APNSealedWakeHandle.self, from: data)
    }
}

private struct APNProvider {
    private static let tokenCache = APNProviderTokenCache()
    private let client: any Client
    private let keyID: String
    private let teamID: String
    private let privateKey: P256.Signing.PrivateKey

    init(req: Request) throws {
        client = req.client
        keyID = try Self.requiredEnv("APN_KEY_ID")
        teamID = try Self.requiredEnv("APN_TEAM_ID")
        let pem = try Self.privateKeyPEM(logger: req.logger)
        do {
            privateKey = try P256.Signing.PrivateKey(pemRepresentation: pem)
        } catch {
            req.logger.error(
                "APNs private key parse failed. key_id=\(self.keyID) team_id=\(self.teamID) error=\(String(describing: error))"
            )
            throw Abort(
                .serviceUnavailable,
                reason:
                    "Failed to parse APNs private key. Expected the contents of AuthKey_<KEYID>.p8 as a P-256 PEM. Underlying error: \(error.localizedDescription)"
            )
        }
    }

    func send(
        payload: Data,
        topic: String,
        token: String,
        environment: String,
        collapseID: String
    ) async throws -> ClientResponse {
        let host =
            switch environment {
                case "development":
                    "https://api.sandbox.push.apple.com"
                default:
                    "https://api.push.apple.com"
            }
        let jwt = try await Self.tokenCache.token(
            keyID: keyID,
            teamID: teamID,
            privateKey: privateKey
        )
        let uri = URI(string: "\(host)/3/device/\(token)")

        return try await client.post(uri) { request in
            request.headers.bearerAuthorization = .init(token: jwt)
            request.headers.add(name: "apns-topic", value: topic)
            request.headers.add(name: "apns-push-type", value: "alert")
            request.headers.add(name: "apns-priority", value: "10")
            request.headers.add(name: "apns-collapse-id", value: collapseID)
            request.headers.contentType = .json
            request.body = .init(data: payload)
        }
    }

    private static func requiredEnv(_ key: String) throws -> String {
        guard let value = Environment.get(key)?.trimmingCharacters(
            in: .whitespacesAndNewlines
        ), !value.isEmpty
        else {
            throw Abort(
                .serviceUnavailable,
                reason: "\(key) is not configured."
            )
        }
        return value
    }

    private static func privateKeyPEM(logger: Logger) throws -> String {
        if let path = Environment.get("APN_PRIVATE_KEY_PATH")?
            .trimmingCharacters(in: .whitespacesAndNewlines),
            !path.isEmpty
        {
            do {
                let pem = try String(contentsOfFile: path, encoding: .utf8)
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                let fileManager = FileManager.default
                let attributes = try? fileManager.attributesOfItem(atPath: path)
                let size =
                    (attributes?[.size] as? NSNumber)?.intValue ?? pem.utf8.count
                let firstLine = pem.split(separator: "\n", maxSplits: 1).first
                    .map(String.init) ?? "<empty>"
                let hasBeginPrivateKey = pem.contains("-----BEGIN PRIVATE KEY-----")
                let hasEndPrivateKey = pem.contains("-----END PRIVATE KEY-----")
                logger.info(
                    "Loading APNs private key from path=\(path) bytes=\(size) first_line=\(firstLine) has_begin_private_key=\(hasBeginPrivateKey) has_end_private_key=\(hasEndPrivateKey)"
                )
                guard hasBeginPrivateKey, hasEndPrivateKey
                else {
                    throw Abort(
                        .serviceUnavailable,
                        reason:
                            "APN_PRIVATE_KEY_PATH does not point to a PEM private key. Expected a .p8 file containing BEGIN/END PRIVATE KEY markers."
                    )
                }
                return pem
            } catch {
                if let abort = error as? Abort {
                    throw abort
                }
                logger.error(
                    "Failed reading APNs private key from path=\(path) error=\(String(describing: error))"
                )
                throw Abort(
                    .serviceUnavailable,
                    reason:
                        "Unable to read APN private key at APN_PRIVATE_KEY_PATH. Underlying error: \(error.localizedDescription)"
                )
            }
        }

        let pem = try requiredEnv("APN_PRIVATE_KEY_PEM")
            .replacingOccurrences(of: "\\n", with: "\n")
        let firstLine = pem.split(separator: "\n", maxSplits: 1).first
            .map(String.init) ?? "<empty>"
        let hasBeginPrivateKey = pem.contains("-----BEGIN PRIVATE KEY-----")
        let hasEndPrivateKey = pem.contains("-----END PRIVATE KEY-----")
        logger.info(
            "Loading APNs private key from APN_PRIVATE_KEY_PEM bytes=\(pem.utf8.count) first_line=\(firstLine) has_begin_private_key=\(hasBeginPrivateKey) has_end_private_key=\(hasEndPrivateKey)"
        )
        guard hasBeginPrivateKey, hasEndPrivateKey
        else {
            throw Abort(
                .serviceUnavailable,
                reason:
                    "APN_PRIVATE_KEY_PEM is not a PEM private key. Expected the contents of AuthKey_<KEYID>.p8."
            )
        }
        return pem
    }
}

private actor APNProviderTokenCache {
    private struct Entry {
        let token: String
        let issuedAt: Date
    }

    private let reuseWindow: TimeInterval = 50 * 60
    private var entries: [String: Entry] = [:]

    func token(
        keyID: String,
        teamID: String,
        privateKey: P256.Signing.PrivateKey
    ) throws -> String {
        let cacheKey = "\(teamID):\(keyID)"
        let now = Date()

        if let entry = entries[cacheKey],
            now.timeIntervalSince(entry.issuedAt) < reuseWindow
        {
            return entry.token
        }

        let token = try makeJWT(
            keyID: keyID,
            teamID: teamID,
            issuedAt: now,
            privateKey: privateKey
        )
        entries[cacheKey] = Entry(token: token, issuedAt: now)
        return token
    }

    private func makeJWT(
        keyID: String,
        teamID: String,
        issuedAt: Date,
        privateKey: P256.Signing.PrivateKey
    ) throws -> String {
        let header = try base64URLJSON([
            "alg": "ES256",
            "kid": keyID,
        ])
        let claims = try base64URLJSON([
            "iss": teamID,
            "iat": Int(issuedAt.timeIntervalSince1970),
        ])
        let signingInput = "\(header).\(claims)"
        let signature = try privateKey.signature(
            for: Data(signingInput.utf8)
        )
        return "\(signingInput).\(signature.rawRepresentation.base64URLEncodedString())"
    }

    private func base64URLJSON(_ object: [String: Any]) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: object)
        return data.base64URLEncodedString()
    }
}

private extension Request {
    func apnHandleSealer() throws -> APNHandleSealer {
        guard let secret = Environment.get("APN_HANDLE_SECRET") else {
            throw Abort(
                .serviceUnavailable,
                reason: "APN_HANDLE_SECRET is not configured."
            )
        }
        return try APNHandleSealer(secret: secret)
    }

    func apnProvider() throws -> APNProvider {
        try APNProvider(req: self)
    }
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
