import Vapor
import WebAuthn

enum PasskeySessionKey {
    static let flow = "passkeyFlow"
    static let challenge = "passkeyChallenge"
    static let userID = "passkeyUserID"
    static let activeCredentialID = "activeCredentialID"
    static let isMerging = "passkeyIsMerging"
    static let confirmChallenge = "confirmChallenge"
    static let confirmAction = "confirmAction"
}

struct PasskeyController: RouteCollection {
    func boot(routes: any RoutesBuilder) throws {
        let authSessionRoutes = routes.grouped(User.sessionAuthenticator())
        authSessionRoutes.post("begin", use: beginHandler)
        authSessionRoutes.post("continue", use: continueHandler)
        authSessionRoutes.get("verify", use: verifyHandler)
        authSessionRoutes.get("passkeys", use: listPasskeysHandler)
        authSessionRoutes.delete("passkeys", ":credentialID", use: deletePasskeyHandler)
        let account = authSessionRoutes.grouped(User.guardMiddleware())
        account.post("confirm", use: confirmHandler)
        account.delete("account", use: deleteAccountHandler)
        account.post("account", "delete", use: deleteAccountFromPage)
    }

    func confirmHandler(req: Request) async throws -> Response {
        try await req.confirmationChallenge(for: try req.content.decode(ConfirmationRequest.self).action)
            .encodeResponse(for: req)
    }
}
