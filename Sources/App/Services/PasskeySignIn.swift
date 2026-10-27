import Fluent
import Vapor
import WebAuthn

extension Request {
    func verifiedPasskey(_ assertion: AuthenticationCredential, challenge: [UInt8]) async throws -> WebAuthnCredential {
        guard
            let credential = try await WebAuthnCredential.query(on: db)
                .filter(\.$id == assertion.id.urlDecoded.asString())
                .with(\.$user)
                .first()
        else {
            throw Abort(.unauthorized, reason: "Credential not found.")
        }
        guard let publicKey = URLEncodedBase64(credential.publicKey).urlDecoded.decoded else {
            throw Abort(.internalServerError, reason: "Stored credential public key is invalid.")
        }
        let verified: VerifiedAuthentication
        do {
            verified = try webAuthn.finishAuthentication(
                credential: assertion,
                expectedChallenge: challenge,
                credentialPublicKey: [UInt8](publicKey),
                credentialCurrentSignCount: credential.currentSignCount
            )
        } catch {
            throw Abort(.unauthorized, reason: "That passkey couldn’t be verified.")
        }
        credential.currentSignCount = verified.newSignCount
        try await credential.save(on: db)
        return credential
    }

    func signIn(with credential: WebAuthnCredential) throws {
        session.data[PasskeySessionKey.activeCredentialID] = try credential.requireID()
        startSession(for: credential.user)
    }

    func confirmationChallenge(for action: String) -> PublicKeyCredentialRequestOptions {
        let options = webAuthn.beginAuthentication()
        session.data[PasskeySessionKey.confirmChallenge] = Data(options.challenge).base64EncodedString()
        session.data[PasskeySessionKey.confirmAction] = action
        return options
    }

    func confirmPasskey(for action: String, answer: String?) async throws {
        let challenge = session.data[PasskeySessionKey.confirmChallenge].flatMap { Data(base64Encoded: $0) }
        let confirming = session.data[PasskeySessionKey.confirmAction]
        session.data[PasskeySessionKey.confirmChallenge] = nil
        session.data[PasskeySessionKey.confirmAction] = nil
        guard let challenge, confirming == action, let answer,
            let assertion = try? JSONDecoder().decode(AuthenticationCredential.self, from: Data(answer.utf8)),
            let userID = auth.get(User.self)?.id
        else {
            throw Abort(.forbidden, reason: "Confirm this with your passkey.")
        }
        let credential = try await verifiedPasskey(assertion, challenge: [UInt8](challenge))
        guard credential.$user.id == userID else {
            throw Abort(.forbidden, reason: "Confirm with one of this account’s passkeys.")
        }
    }

    func startSession(for user: User) {
        session.data[PasskeySessionKey.signedInAt] = String(Date.now.timeIntervalSince1970)
        auth.login(user)
    }
}

struct SessionLifetime: AsyncMiddleware {
    static let duration: TimeInterval = 12 * 60 * 60

    func respond(to req: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        if req.hasSession, req.session.authenticated(User.self) != nil {
            let signedInAt = req.session.data[PasskeySessionKey.signedInAt].flatMap(TimeInterval.init)
            if signedInAt.map({ Date.now.timeIntervalSince1970 - $0 > Self.duration }) ?? true {
                req.session.unauthenticate(User.self)
                req.session.destroy()
            }
        }
        return try await next.respond(to: req)
    }
}
