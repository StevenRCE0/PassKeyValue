import Fluent
import Vapor

extension PasskeyController {
    func verifyHandler(req: Request) async throws -> VerifyPasskeyResponse {
        guard let user = req.auth.get(User.self), let userID = user.id else {
            throw Abort(.unauthorized, reason: "No active session.")
        }

        let passkeys = try await passkeySummaries(for: userID, on: req.db)
        return VerifyPasskeyResponse(
            status: "verified",
            userID: userID,
            passkeys: passkeys
        )
    }
}
