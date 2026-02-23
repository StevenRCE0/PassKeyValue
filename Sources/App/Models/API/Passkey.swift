import Vapor
import WebAuthn

enum PasskeyFlow: String, Codable {
    case registration
    case authentication
}

enum MergeMode: String, Decodable {
    case keepCurrentUser
    case keepProvidedUser
}

struct BeginPasskeyRequest: Content {
    let stage: PasskeyFlow
    let isMerging: Bool
    let passkeyName: String?

    init(stage: PasskeyFlow, isMerging: Bool = false, passkeyName: String? = nil) {
        self.stage = stage
        self.isMerging = isMerging
        self.passkeyName = passkeyName
    }
}

struct BeginPasskeyResponse: Encodable {
    let mode: PasskeyFlow
    let creationOptions: PublicKeyCredentialCreationOptions?
    let requestOptions: PublicKeyCredentialRequestOptions?
}

struct ContinuePasskeyResponse: Encodable {
    let status: String
    let userID: UUID
    let passkeys: [PasskeySummary]
}

struct PasskeyListResponse: Content {
    let userID: UUID
    let passkeys: [PasskeySummary]
}

struct DeletePasskeyResponse: Content {
    let status: String
    let userID: UUID
    let passkeys: [PasskeySummary]
}

struct PasskeySummary: Content {
    let id: String
    let name: String
}

struct ContinueRegistrationRequest: Decodable {
    let credential: RegistrationCredential
    let passkeyName: String
}

struct ContinueAuthenticationRequest: Decodable {
    let credential: AuthenticationCredential
    let mergeMode: MergeMode?
}

extension PublicKeyCredentialCreationOptions {
    public func encodeResponse(for request: Request) async throws -> Response {
        var headers = HTTPHeaders()
        headers.contentType = .json
        return try Response(
            status: .ok, headers: headers, body: .init(data: JSONEncoder().encode(self)))
    }
}

extension PublicKeyCredentialRequestOptions {
    public func encodeResponse(for request: Request) async throws -> Response {
        var headers = HTTPHeaders()
        headers.contentType = .json
        return try Response(
            status: .ok, headers: headers, body: .init(data: JSONEncoder().encode(self)))
    }
}

extension BeginPasskeyResponse: AsyncResponseEncodable {
    func encodeResponse(for request: Request) async throws -> Response {
        var headers = HTTPHeaders()
        headers.contentType = .json
        return try Response(
            status: .ok, headers: headers, body: .init(data: JSONEncoder().encode(self)))
    }
}

extension ContinuePasskeyResponse: AsyncResponseEncodable {
    func encodeResponse(for request: Request) async throws -> Response {
        var headers = HTTPHeaders()
        headers.contentType = .json
        return try Response(
            status: .ok, headers: headers, body: .init(data: JSONEncoder().encode(self)))
    }
}
