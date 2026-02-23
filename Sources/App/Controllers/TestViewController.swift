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

        return try await req.view.render("index", ["title": "Passkey Tester"])
            .encodeResponse(for: req)
    }

    private func privateArea(req: Request) async throws -> View {
        guard let user = req.auth.get(User.self) else {
            throw Abort(.unauthorized)
        }

        return try await req.view.render(
            "private",
            [
                "title": "Private Area",
                "username": user.username,
            ])
    }

    private func kvArea(req: Request) async throws -> View {
        guard let user = req.auth.get(User.self) else {
            throw Abort(.unauthorized)
        }

        return try await req.view.render(
            "kv",
            [
                "title": "KV Manager",
                "username": user.username,
            ])
    }

    private func logout(req: Request) async throws -> Response {
        req.auth.logout(User.self)
        req.session.destroy()
        return req.redirect(to: "/")
    }
}
