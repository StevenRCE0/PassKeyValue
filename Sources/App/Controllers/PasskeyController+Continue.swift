import Fluent
import Vapor
import WebAuthn

extension PasskeyController {
    func continueHandler(req: Request) async throws -> ContinuePasskeyResponse {
        guard let flowRaw = req.session.data[PasskeySessionKey.flow],
            let flow = PasskeyFlow(rawValue: flowRaw),
            let challengeEncoded = req.session.data[PasskeySessionKey.challenge],
            let challenge = Data(base64Encoded: challengeEncoded)
        else {
            throw Abort(.badRequest, reason: "Missing or invalid passkey session state.")
        }

        req.session.data[PasskeySessionKey.flow] = nil
        req.session.data[PasskeySessionKey.challenge] = nil
        req.session.data[PasskeySessionKey.isMerging] = nil

        switch flow {
        case .registration:
            guard let userIDRaw = req.session.data[PasskeySessionKey.userID],
                let userID = UUID(uuidString: userIDRaw)
            else {
                throw Abort(.badRequest, reason: "Missing registration user session state.")
            }
            req.session.data[PasskeySessionKey.userID] = nil

            guard let user = try await User.find(userID, on: req.db) else {
                throw Abort(.notFound, reason: "User not found.")
            }

            let registrationRequest = try req.content.decode(ContinueRegistrationRequest.self)
            let passkeyName = registrationRequest.passkeyName.trimmingCharacters(
                in: .whitespacesAndNewlines)
            guard !passkeyName.isEmpty else {
                throw Abort(.badRequest, reason: "Passkey name is required.")
            }

            let verifiedCredential = try await req.webAuthn.finishRegistration(
                challenge: [UInt8](challenge),
                credentialCreationData: registrationRequest.credential,
                confirmCredentialIDNotRegisteredYet: { credentialID in
                    let existingCredential = try await WebAuthnCredential.query(on: req.db)
                        .filter(\.$id == credentialID)
                        .first()
                    return existingCredential == nil
                }
            )

            try await WebAuthnCredential(
                from: verifiedCredential, name: passkeyName, userID: userID
            )
            .save(on: req.db)
            req.session.data[PasskeySessionKey.activeCredentialID] = verifiedCredential.id
            req.auth.login(user)

            let passkeys = try await passkeySummaries(for: userID, on: req.db)
            return ContinuePasskeyResponse(status: "registered", userID: userID, passkeys: passkeys)

        case .authentication:
            req.session.data[PasskeySessionKey.userID] = nil

            let authenticationRequest = try req.content.decode(ContinueAuthenticationRequest.self)
            let authenticationCredential = authenticationRequest.credential

            guard
                let providedCredential = try await WebAuthnCredential.query(on: req.db)
                    .filter(\.$id == authenticationCredential.id.urlDecoded.asString())
                    .with(\.$user)
                    .first()
            else {
                throw Abort(.unauthorized, reason: "Credential not found.")
            }

            guard
                let publicKeyData = URLEncodedBase64(providedCredential.publicKey).urlDecoded
                    .decoded
            else {
                throw Abort(
                    .internalServerError, reason: "Stored credential public key is invalid.")
            }

            let verifiedAuthentication = try req.webAuthn.finishAuthentication(
                credential: authenticationCredential,
                expectedChallenge: [UInt8](challenge),
                credentialPublicKey: [UInt8](publicKeyData),
                credentialCurrentSignCount: providedCredential.currentSignCount
            )

            providedCredential.currentSignCount = verifiedAuthentication.newSignCount
            try await providedCredential.save(on: req.db)

            let providedUserID = try providedCredential.user.requireID()

            if let mergeMode = authenticationRequest.mergeMode {
                guard let currentSessionUser = req.auth.get(User.self),
                    let currentSessionUserID = currentSessionUser.id
                else {
                    throw Abort(
                        .unauthorized,
                        reason: "Active session with passkey A is required for merge.")
                }

                guard
                    let mergeOriginCredentialID = req.session.data[
                        PasskeySessionKey.activeCredentialID]
                else {
                    throw Abort(
                        .badRequest,
                        reason: "Missing active passkey A in session. Sign in first before merge.")
                }

                guard
                    let mergeOriginCredential = try await WebAuthnCredential.query(on: req.db)
                        .filter(\.$id == mergeOriginCredentialID)
                        .with(\.$user)
                        .first()
                else {
                    throw Abort(.badRequest, reason: "Session passkey A not found.")
                }

                let mergeOriginUserID = try mergeOriginCredential.user.requireID()
                guard mergeOriginUserID == currentSessionUserID else {
                    throw Abort(.unauthorized, reason: "Session user does not match passkey A.")
                }

                guard mergeOriginUserID != providedUserID else {
                    throw Abort(.badRequest, reason: "Passkey A and B belong to the same user.")
                }

                let mergedUserID = try await mergeUsers(
                    keepMode: mergeMode,
                    currentUserID: mergeOriginUserID,
                    providedUserID: providedUserID,
                    on: req.db
                )

                guard let mergedUser = try await User.find(mergedUserID, on: req.db) else {
                    throw Abort(.internalServerError, reason: "Merged user not found.")
                }

                switch mergeMode {
                case .keepCurrentUser:
                    req.session.data[PasskeySessionKey.activeCredentialID] = mergeOriginCredentialID
                case .keepProvidedUser:
                    req.session.data[PasskeySessionKey.activeCredentialID] =
                        try providedCredential.requireID()
                }

                req.auth.login(mergedUser)
                let passkeys = try await passkeySummaries(for: mergedUserID, on: req.db)
                return ContinuePasskeyResponse(
                    status: "merged", userID: mergedUserID, passkeys: passkeys)
            }

            req.session.data[PasskeySessionKey.activeCredentialID] =
                try providedCredential.requireID()
            req.auth.login(providedCredential.user)
            let passkeys = try await passkeySummaries(for: providedUserID, on: req.db)
            return ContinuePasskeyResponse(
                status: "authenticated", userID: providedUserID, passkeys: passkeys)
        }
    }

    func passkeySummaries(for userID: UUID, on db: any Database) async throws -> [PasskeySummary] {
        let credentials = try await WebAuthnCredential.query(on: db)
            .filter(\.$user.$id == userID)
            .all()

        var summaries: [PasskeySummary] = []
        summaries.reserveCapacity(credentials.count)

        for credential in credentials {
            summaries.append(PasskeySummary(id: try credential.requireID(), name: credential.name))
        }

        return summaries
    }

    private func mergeUsers(
        keepMode: MergeMode,
        currentUserID: UUID,
        providedUserID: UUID,
        on db: any Database
    ) async throws -> UUID {
        let winnerUserID: UUID
        let loserUserID: UUID
        switch keepMode {
        case .keepCurrentUser:
            winnerUserID = currentUserID
            loserUserID = providedUserID
        case .keepProvidedUser:
            winnerUserID = providedUserID
            loserUserID = currentUserID
        }

        let loserCredentials = try await WebAuthnCredential.query(on: db)
            .filter(\.$user.$id == loserUserID)
            .all()

        for credential in loserCredentials {
            credential.$user.id = winnerUserID
            try await credential.save(on: db)
        }

        if let loserUser = try await User.find(loserUserID, on: db) {
            try await loserUser.delete(on: db)
        }

        return winnerUserID
    }
}
