import Fluent
import Vapor
import WebAuthn

extension PasskeyController {
    func beginHandler(req: Request) async throws -> BeginPasskeyResponse {
        let beginRequest = try req.content.decode(BeginPasskeyRequest.self)
        let stage = beginRequest.stage
        let isMerging = beginRequest.isMerging
        req.session.data[PasskeySessionKey.userID] = nil
        req.session.data[PasskeySessionKey.isMerging] = isMerging ? "1" : "0"

        switch stage {
        case .registration:
            let user: User
            if isMerging, let sessionUser = req.auth.get(User.self) {
                user = sessionUser
            } else {
                let username = beginRequest.passkeyName?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                guard !username.isEmpty else {
                    throw Abort(.badRequest, reason: "Passkey name is required.")
                }

                let newUser = User(username: username)
                try await newUser.create(on: req.db)
                user = newUser
            }

            let userID = try user.requireID()
            req.session.data[PasskeySessionKey.userID] = userID.uuidString

            let options = req.webAuthn.beginRegistration(user: user.webAuthnUser)
            req.session.data[PasskeySessionKey.flow] = PasskeyFlow.registration.rawValue
            req.session.data[PasskeySessionKey.challenge] = Data(options.challenge).base64EncodedString()
            return BeginPasskeyResponse(
                mode: stage, creationOptions: options, requestOptions: nil)

        case .authentication:
            let options = try req.webAuthn.beginAuthentication()
            req.session.data[PasskeySessionKey.flow] = PasskeyFlow.authentication.rawValue
            req.session.data[PasskeySessionKey.challenge] = Data(options.challenge).base64EncodedString()
            return BeginPasskeyResponse(
                mode: stage, creationOptions: nil, requestOptions: options)
        }
    }
}
