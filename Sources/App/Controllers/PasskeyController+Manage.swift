import Fluent
import Vapor

extension PasskeyController {
    func listPasskeysHandler(req: Request) async throws -> PasskeyListResponse {
        guard let user = req.auth.get(User.self), let userID = user.id else {
            throw Abort(.unauthorized)
        }

        let passkeys = try await passkeySummaries(for: userID, on: req.db)
        return PasskeyListResponse(userID: userID, passkeys: passkeys)
    }

    func deletePasskeyHandler(req: Request) async throws -> DeletePasskeyResponse {
        guard let user = req.auth.get(User.self), let userID = user.id else {
            throw Abort(.unauthorized)
        }

        guard let credentialID = req.parameters.get("credentialID"), !credentialID.isEmpty else {
            throw Abort(.badRequest, reason: "Credential ID is required.")
        }

        let credentials = try await WebAuthnCredential.query(on: req.db)
            .filter(\.$user.$id == userID)
            .all()

        guard credentials.count > 1 else {
            throw Abort(.badRequest, reason: "Cannot delete the last passkey.")
        }

        guard let credential = credentials.first(where: { $0.id == credentialID }) else {
            throw Abort(.notFound, reason: "Passkey not found for current user.")
        }

        try await credential.delete(on: req.db)

        if req.session.data[PasskeySessionKey.activeCredentialID] == credentialID {
            let remaining = try await WebAuthnCredential.query(on: req.db)
                .filter(\.$user.$id == userID)
                .first()
            req.session.data[PasskeySessionKey.activeCredentialID] = remaining?.id
        }

        let passkeys = try await passkeySummaries(for: userID, on: req.db)
        return DeletePasskeyResponse(status: "deleted", userID: userID, passkeys: passkeys)
    }
}
