import Fluent
import Vapor

struct KVController: RouteCollection {
    func boot(routes: any RoutesBuilder) throws {
        let kvRoutes = routes.grouped(User.sessionAuthenticator(), KVAccessAuthenticator()).grouped("api", "kv")

        kvRoutes.get(use: listHandler)
        kvRoutes.get(":key", use: getHandler)
        kvRoutes.post(":key", use: upsertHandler)
        kvRoutes.delete(":key", use: deleteHandler)
    }

    private func listHandler(req: Request) async throws -> KVListResponse {
        let records = try await query(req, writing: false).sort(\.$key).all()
        return KVListResponse(items: records.map { KVEntry(key: $0.key, value: $0.value) })
    }

    private func getHandler(req: Request) async throws -> KVGetResponse {
        let key = try validatedKey(from: req)
        guard let record = try await query(req, writing: false).filter(\.$key == key).first() else {
            throw Abort(.notFound, reason: "Key not found.")
        }
        return KVGetResponse(item: KVEntry(key: key, value: record.value))
    }

    private func upsertHandler(req: Request) async throws -> KVUpsertResponse {
        let access = try req.auth.require(KVAccess.self)
        let namespace = try access.namespace(req.query[String.self, at: "namespace"], writing: true)
        let key = try validatedKey(from: req)
        let payload = try req.content.decode(KVUpsertRequest.self)

        let record =
            try await KVRecord.query(on: req.db)
            .filter(\.$user.$id == access.userID)
            .filter(\.$namespace == namespace)
            .filter(\.$key == key)
            .first() ?? KVRecord(userID: access.userID, namespace: namespace, key: key, value: payload.value)
        record.value = payload.value
        try await record.save(on: req.db)
        return KVUpsertResponse(item: KVEntry(key: key, value: payload.value))
    }

    private func deleteHandler(req: Request) async throws -> KVDeleteResponse {
        let key = try validatedKey(from: req)
        guard let record = try await query(req, writing: true).filter(\.$key == key).first() else {
            throw Abort(.notFound, reason: "Key not found.")
        }
        try await record.delete(on: req.db)
        let remaining = try await query(req, writing: false).all()
        return KVDeleteResponse(
            deletedKey: key, present: Dictionary(uniqueKeysWithValues: remaining.map { ($0.key, $0.value) }))
    }

    private func query(_ req: Request, writing: Bool) throws -> QueryBuilder<KVRecord> {
        let access = try req.auth.require(KVAccess.self)
        let namespace = try access.namespace(req.query[String.self, at: "namespace"], writing: writing)
        return KVRecord.query(on: req.db)
            .filter(\.$user.$id == access.userID)
            .filter(\.$namespace == namespace)
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
