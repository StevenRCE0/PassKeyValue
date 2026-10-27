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
        auth.login(credential.user)
    }
}
