import Fluent
import Vapor

struct TestViewController: RouteCollection {
    func boot(routes: any RoutesBuilder) throws {
        let sessionRoutes = routes.grouped(User.sessionAuthenticator())
        sessionRoutes.get(use: index)

        let privateRoutes = sessionRoutes.grouped(User.redirectMiddleware(path: "/"))
        privateRoutes.get("private", use: privateArea)
        privateRoutes.get("kv", use: kvArea)
        privateRoutes.post("logout", use: logout)
    }

    private func index(req: Request) async throws -> Response {
        if req.auth.get(User.self) != nil {
            return req.redirect(to: "/private")
        }

        return try await req.view.render("index", ["title": "Sign In"])
            .encodeResponse(for: req)
    }

    private func privateArea(req: Request) async throws -> View {
        guard let user = req.auth.get(User.self) else {
            throw Abort(.unauthorized)
        }

        let grants = try await ThirdPartyGrant.query(on: req.db)
            .filter(\.$user.$id == user.requireID())
            .filter(\.$revokedAt == nil)
            .all()
        let erasures = Dictionary(grants.map { ($0.serviceName ?? $0.service, $0.erasedOnRevocation) }) { $1 ?? $0 }
            .compactMap { name, erased in erased.map { Erasure(serviceName: name, erased: $0) } }
            .sorted { $0.serviceName < $1.serviceName }
        return try await req.view.render(
            "private", AccountPage(title: "Account", username: user.username, erasures: erasures))
    }

    private struct AccountPage: Encodable {
        let title: String
        let username: String
        let erasures: [Erasure]
    }

    private struct Erasure: Encodable {
        let serviceName: String
        let erased: String
    }

    private func kvArea(req: Request) async throws -> View {
        guard let user = req.auth.get(User.self) else {
            throw Abort(.unauthorized)
        }

        return try await req.view.render(
            "kv",
            [
                "title": "Key-Value Storage",
                "username": user.username,
            ])
    }

    private func logout(req: Request) async throws -> Response {
        req.auth.logout(User.self)
        req.session.destroy()
        return req.redirect(to: "/")
    }
}
