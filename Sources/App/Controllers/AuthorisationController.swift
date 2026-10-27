import Fluent
import JWT
import Vapor
import WebAuthn

struct AuthorisationController: RouteCollection {
    let services: [String: ThirdPartyService]

    func boot(routes: any RoutesBuilder) throws {
        let page = routes.grouped(User.sessionAuthenticator()).grouped("authorize")
        page.get(use: authorise)
        page.post(use: decide)

        let oauth = routes.grouped("oauth")
        oauth.post("token", use: token)
        oauth.post("revoke", use: revoke)
    }

    // MARK: - Authorise page

    struct ConsentPage: Encodable {
        let title = "Authorise"
        let serviceName: String
        let scopes: [ThirdPartyScope]
        let ticket: String
        let requestOptions: String
    }

    func authorise(req: Request) async throws -> Response {
        let request = try req.query.decode(AuthorisationRequest.self)
        // Never redirect anywhere until the URI is known to be the service's own.
        guard let service = services[request.clientID] else {
            throw Abort(.badRequest, reason: "Unknown service.")
        }
        guard service.redirectURIs.contains(request.redirectURI) else {
            throw Abort(.badRequest, reason: "That redirect URI isn't registered for \(service.name).")
        }
        let scopes = Set(request.scope.split(separator: " ").map(String.init))
        guard request.responseType == "code" else {
            return redirect(req, to: request.redirectURI, ["error": "unsupported_response_type", "state": request.state])
        }
        guard request.codeChallengeMethod == "S256", !request.codeChallenge.isEmpty else {
            return redirect(req, to: request.redirectURI, ["error": "invalid_request", "state": request.state])
        }
        guard !scopes.isEmpty, scopes.isSubset(of: service.scopes.keys) else {
            return redirect(req, to: request.redirectURI, ["error": "invalid_scope", "state": request.state])
        }

        let options = req.webAuthn.beginAuthentication()
        let ticket = AuthorisationTicket(request: request, scopes: scopes.sorted(), passkeyChallenge: options.challenge)
        return try await req.view.render(
            "authorize",
            ConsentPage(
                serviceName: service.name,
                scopes: ticket.scopes.map { ThirdPartyScope(id: $0, description: service.scopes[$0] ?? $0) },
                ticket: try await req.jwt.sign(ticket, kid: ThirdPartyAccessController.kid),
                requestOptions: String(decoding: try JSONEncoder().encode(options), as: UTF8.self)
            )
        ).encodeResponse(for: req)
    }

    func decide(req: Request) async throws -> Response {
        let decision = try req.content.decode(AuthorisationDecision.self)
        guard let ticket = try? await req.jwt.verify(decision.ticket, as: AuthorisationTicket.self) else {
            throw Abort(.badRequest, reason: "This request has expired. Start again from the app.")
        }
        guard decision.approve else {
            return redirect(req, to: ticket.redirectURI, ["error": "access_denied", "state": ticket.state])
        }
        guard let assertion = try? decision.credential.map({
            try JSONDecoder().decode(AuthenticationCredential.self, from: Data($0.utf8))
        }), let challenge = ticket.passkeyChallenge.decodedBytes else {
            throw Abort(.badRequest, reason: "Approve with your passkey.")
        }
        let credential = try await req.verifiedPasskey(assertion, challenge: challenge)
        try req.signIn(with: credential)
        let (code, value) = AuthorisationCode.issue(for: ticket, userID: try credential.user.requireID())
        try await code.save(on: req.db)
        return redirect(req, to: ticket.redirectURI, ["code": value, "state": ticket.state])
    }

    private func redirect(_ req: Request, to uri: String, _ parameters: [String: String]) -> Response {
        guard var components = URLComponents(string: uri) else { return req.redirect(to: uri) }
        components.queryItems = (components.queryItems ?? [])
            + parameters.sorted { $0.key < $1.key }.map { URLQueryItem(name: $0.key, value: $0.value) }
        return req.redirect(to: components.string ?? uri)
    }

    // MARK: - Token endpoint

    func token(req: Request) async throws -> TokenResponse {
        let request = try req.content.decode(TokenRequest.self)
        guard services[request.clientID] != nil else { throw OAuthError.invalidClient }
        switch request.grantType {
            case "authorization_code":
                return try await exchangeCode(request, on: req)
            case "refresh_token":
                return try await refresh(request, on: req)
            default:
                throw OAuthError.unsupportedGrantType
        }
    }

    private func exchangeCode(_ request: TokenRequest, on req: Request) async throws -> TokenResponse {
        guard let value = request.code, let redirectURI = request.redirectURI, let verifier = request.codeVerifier
        else { throw OAuthError.invalidRequest }
        guard
            let code = try await AuthorisationCode.query(on: req.db)
                .filter(\.$codeHash == OpaqueToken.hash(value))
                .first()
        else { throw OAuthError.invalidGrant }
        try await code.delete(on: req.db)
        guard code.service == request.clientID, code.redirectURI == redirectURI,
            code.expiresAt > .now, code.isAnswered(by: verifier)
        else { throw OAuthError.invalidGrant }

        let grant = ThirdPartyGrant(userID: code.$user.id, service: code.service, scopes: code.scopes)
        try await grant.save(on: req.db)
        return try await issueTokens(for: grant, on: req)
    }

    private func refresh(_ request: TokenRequest, on req: Request) async throws -> TokenResponse {
        guard let value = request.refreshToken else { throw OAuthError.invalidRequest }
        guard
            let token = try await RefreshToken.query(on: req.db)
                .filter(\.$tokenHash == OpaqueToken.hash(value))
                .with(\.$grant)
                .first(),
            token.grant.service == request.clientID, token.grant.revokedAt == nil
        else { throw OAuthError.invalidGrant }
        guard token.spentAt == nil else {
            // A spent token came back, so someone else holds a copy.
            try await token.grant.revoke(
                announcingTo: services[token.grant.service]?.revocationURL, on: req.db, app: req.application)
            throw OAuthError.invalidGrant
        }
        token.spentAt = .now
        try await token.save(on: req.db)
        return try await issueTokens(for: token.grant, on: req)
    }

    private func issueTokens(for grant: ThirdPartyGrant, on req: Request) async throws -> TokenResponse {
        let access = try ThirdPartyAccessToken(grant: grant)
        let signed = try await req.jwt.sign(access, kid: ThirdPartyAccessController.kid)
        let (refresh, value) = try RefreshToken.issue(for: grant)
        try await refresh.save(on: req.db)
        grant.lastUsedAt = .now
        try await grant.save(on: req.db)
        return TokenResponse(
            accessToken: signed,
            expiresIn: Int(ThirdPartyAccessToken.lifetime),
            refreshToken: value,
            scope: access.scope
        )
    }

    // MARK: - Revocation endpoint

    func revoke(req: Request) async throws -> HTTPStatus {
        let request = try req.content.decode(RevocationRequest.self)
        if let token = try await RefreshToken.query(on: req.db)
            .filter(\.$tokenHash == OpaqueToken.hash(request.token))
            .with(\.$grant)
            .first(),
            token.grant.service == request.clientID
        {
            try await token.grant.revoke(
                announcingTo: services[token.grant.service]?.revocationURL, on: req.db, app: req.application)
        }
        return .ok
    }
}

enum OAuthError: String, AbortError {
    case invalidRequest = "invalid_request"
    case invalidClient = "invalid_client"
    case invalidGrant = "invalid_grant"
    case unsupportedGrantType = "unsupported_grant_type"

    var status: HTTPResponseStatus {
        self == .invalidClient ? .unauthorized : .badRequest
    }

    var reason: String { rawValue }
}
