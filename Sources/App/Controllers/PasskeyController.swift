import Vapor

enum PasskeySessionKey {
    static let flow = "passkeyFlow"
    static let challenge = "passkeyChallenge"
    static let userID = "passkeyUserID"
    static let activeCredentialID = "activeCredentialID"
    static let isMerging = "passkeyIsMerging"
}

struct PasskeyController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let authSessionRoutes = routes.grouped(User.sessionAuthenticator())
        authSessionRoutes.post("begin", use: beginHandler)
        authSessionRoutes.post("continue", use: continueHandler)
        authSessionRoutes.get("passkeys", use: listPasskeysHandler)
        authSessionRoutes.delete("passkeys", ":credentialID", use: deletePasskeyHandler)
    }
}
