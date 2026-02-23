import Fluent
import Vapor

struct KVController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let protectedRoutes = routes.grouped(User.sessionAuthenticator())
        let kvRoutes = protectedRoutes.grouped("api", "kv")

        kvRoutes.get(use: listHandler)
        kvRoutes.get(":key", use: getHandler)
        kvRoutes.post(":key", use: upsertHandler)
        kvRoutes.delete(":key", use: deleteHandler)
    }

    private func listHandler(req: Request) async throws -> KVListResponse {
        let user = try authenticatedUser(from: req)
        let entries = user.storage.map { KVEntry(key: $0.key, value: $0.value) }
            .sorted { $0.key < $1.key }
        return KVListResponse(items: entries)
    }

    private func getHandler(req: Request) async throws -> KVGetResponse {
        let user = try authenticatedUser(from: req)
        let key = try validatedKey(from: req)

        guard let value = user.storage[key] else {
            throw Abort(.notFound, reason: "Key not found.")
        }

        return KVGetResponse(item: KVEntry(key: key, value: value))
    }

    private func upsertHandler(req: Request) async throws -> KVUpsertResponse {
        let user = try authenticatedUser(from: req)
        let key = try validatedKey(from: req)
        let payload = try req.content.decode(KVUpsertRequest.self)

        guard !key.isEmpty else {
            throw Abort(.badRequest, reason: "Key is required.")
        }

        if user.storage[key] != nil {
            user.storage[key] = payload.value
        }

        user.storage[key] = payload.value
        try await user.save(on: req.db)
        return KVUpsertResponse(item: KVEntry(key: key, value: payload.value))
    }

    private func deleteHandler(req: Request) async throws -> KVDeleteResponse {
        let user = try authenticatedUser(from: req)
        let key = try validatedKey(from: req)

        guard user.storage.removeValue(forKey: key) != nil else {
            throw Abort(.notFound, reason: "Key not found.")
        }

        try await user.save(on: req.db)
        return KVDeleteResponse(deletedKey: key, present: user.storage)
    }

    private func authenticatedUser(from req: Request) throws -> User {
        guard let user = req.auth.get(User.self) else {
            throw Abort(.unauthorized)
        }
        return user
    }

    private func validatedKey(from req: Request) throws -> String {
        guard let key = req.parameters.get("key")?.trimmingCharacters(in: .whitespacesAndNewlines),
            !key.isEmpty
        else {
            throw Abort(.badRequest, reason: "Key is required.")
        }
        return key
    }
}
