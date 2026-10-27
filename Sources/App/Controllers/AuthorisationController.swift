import Fluent
import JWT
import Vapor
import WebAuthn

struct AuthorisationController: RouteCollection {
    func boot(routes: any RoutesBuilder) throws {
        let page = routes.grouped(User.sessionAuthenticator()).grouped("authorize")
        page.get(use: authorise)
        page.post(use: decide)
        page.post("signup", use: signUp)
        page.post("signup", "finish", use: finishSignUp)

        let oauth = routes.grouped("oauth")
        oauth.post("authorize-challenge", use: authorisationChallenge)
        oauth.post("token", use: token)
        oauth.post("revoke", use: revoke)
    }

    // MARK: - Authorise page

    struct ConsentPage: Encodable {
        let title = "Authorise"
        let serviceName: String
        let serviceDomain: String
        let scopes: [ThirdPartyScope]
        let ticket: String
        let requestOptions: String
    }

    func authorise(req: Request) async throws -> Response {
        let request = try req.query.decode(AuthorisationRequest.self)
        let (ticket, options): (AuthorisationTicket, PublicKeyCredentialRequestOptions)
        do {
            (ticket, options) = try await self.ticket(for: request, native: false, on: req)
        } catch let error as OAuthError {
            return redirect(req, to: request.redirectURI, ["error": error.rawValue, "state": request.state])
        }
        return try await req.view.render(
            "authorize",
            ConsentPage(
                serviceName: ticket.serviceName,
                serviceDomain: URL(string: ticket.service)?.host ?? ticket.service,
                scopes: ticket.scopes.map {
                    ThirdPartyScope(
                        id: $0, description: ticket.scopeDescriptions[$0] ?? $0,
                        isOptional: !ticket.allowlisted && KVScope.isOptional($0))
                },
                ticket: try await req.jwt.sign(ticket, kid: ThirdPartyAccessController.kid),
                requestOptions: String(decoding: try JSONEncoder().encode(options), as: UTF8.self)
            )
        ).encodeResponse(for: req)
    }

    func decide(req: Request) async throws -> Response {
        let decision = try req.content.decode(AuthorisationDecision.self)
        let ticket = try await verified(decision.ticket, on: req)
        guard !ticket.native else { throw Abort(.forbidden, reason: "Answer this request in the app.") }
        guard decision.approve else {
            return redirect(req, to: ticket.redirectURI, ["error": "access_denied", "state": ticket.state])
        }
        guard let assertion = try? decision.credential.map({
            try JSONDecoder().decode(AuthenticationCredential.self, from: Data($0.utf8))
        }) else {
            throw Abort(.badRequest, reason: "Approve with your passkey.")
        }
        let code = try await approve(ticket, answering: assertion, choosing: decision.scopes, on: req)
        return redirect(req, to: ticket.redirectURI, ["code": code, "state": ticket.state])
    }

    // MARK: - First-party apps

    // The Authorization Challenge Endpoint of OAuth 2.0 for First-Party Applications.
    func authorisationChallenge(req: Request) async throws -> AuthorisationChallengeResponse {
        let request = try req.content.decode(AuthorisationChallengeRequest.self)
        guard let session = request.authSession else { return try await openChallenge(request, on: req) }
        guard let ticket = try? await req.jwt.verify(session, as: AuthorisationTicket.self), ticket.native,
            request.clientID.map({ $0 == ticket.service }) ?? true
        else {
            return .failure("invalid_session", "This sign-in has expired. Start again.")
        }
        do {
            if let registration = request.passkeyRegistration, let signup = request.signupSession {
                let credential = try JSONDecoder().decode(RegistrationCredential.self, from: Data(registration.utf8))
                let created = try await createAccount(for: session, signup: signup, credential: credential, on: req)
                return .code(try await issue(ticket, to: created, choosing: nil, on: req))
            }
            if let name = request.name {
                let (signup, options) = try await startSignUp(for: session, name: name, on: req)
                var response = AuthorisationChallengeResponse.failure(
                    "insufficient_authorization", "Create a passkey to continue.")
                response.authSession = session
                response.signupSession = signup
                response.passkeyRegistration = options
                return response
            }
            guard let answer = request.passkey,
                let assertion = try? JSONDecoder().decode(AuthenticationCredential.self, from: Data(answer.utf8))
            else {
                return .failure("invalid_request", "Answer the passkey challenge.")
            }
            return .code(try await approve(ticket, answering: assertion, choosing: nil, on: req))
        } catch let error as Abort {
            return .failure("access_denied", error.reason)
        }
    }

    private func openChallenge(_ request: AuthorisationChallengeRequest, on req: Request) async throws
        -> AuthorisationChallengeResponse
    {
        guard let clientID = request.clientID, let scope = request.scope, let codeChallenge = request.codeChallenge
        else {
            return .failure("invalid_request", "client_id, scope and code_challenge are required.")
        }
        let authorisation = AuthorisationRequest(
            responseType: "code", clientID: clientID, redirectURI: "", scope: scope, state: "",
            codeChallenge: codeChallenge, codeChallengeMethod: request.codeChallengeMethod ?? "")
        let (ticket, options): (AuthorisationTicket, PublicKeyCredentialRequestOptions)
        do {
            (ticket, options) = try await self.ticket(for: authorisation, native: true, on: req)
        } catch let error as OAuthError {
            return .failure(error.rawValue, nil)
        } catch let error as Abort {
            return .failure("invalid_client", error.reason)
        }
        guard ticket.firstParty else {
            return .failure("redirect_to_web", "Sign in through the authorise page.")
        }
        var response = AuthorisationChallengeResponse.failure("insufficient_authorization", "Answer with a passkey.")
        response.authSession = try await req.jwt.sign(ticket, kid: ThirdPartyAccessController.kid)
        response.passkey = options
        return response
    }

    // MARK: - Sign-up on the authorise page

    func signUp(req: Request) async throws -> PasskeyChallenge<PublicKeyCredentialCreationOptions> {
        let request = try req.content.decode(SignupRequest.self)
        guard try await !verified(request.ticket, on: req).native else {
            throw Abort(.forbidden, reason: "Sign up in the app.")
        }
        let (signup, options) = try await startSignUp(for: request.ticket, name: request.name, on: req)
        return PasskeyChallenge(ticket: signup, options: options)
    }

    func finishSignUp(req: Request) async throws -> AuthorisationAnswer {
        let answer = try req.content.decode(SignupAnswer.self)
        let ticket = try await verified(answer.ticket, on: req)
        guard !ticket.native else { throw Abort(.forbidden, reason: "Sign up in the app.") }
        let credential = try await createAccount(
            for: answer.ticket, signup: answer.signup, credential: answer.credential, on: req)
        let code = try await issue(ticket, to: credential, choosing: answer.scopes, on: req)
        return AuthorisationAnswer(
            code: code, state: ticket.state,
            redirect: location(ticket.redirectURI, ["code": code, "state": ticket.state]))
    }

    private func startSignUp(for ticket: String, name: String, on req: Request) async throws
        -> (String, PublicKeyCredentialCreationOptions)
    {
        let username = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !username.isEmpty else { throw Abort(.badRequest, reason: "Choose a name for your account.") }
        let user = User(id: UUID(), username: username)
        let options = req.webAuthn.beginRegistration(user: user.webAuthnUser)
        let signup = SignupTicket(
            user: try user.requireID(), username: username, ticket: ticket, passkeyChallenge: options.challenge)
        return (try await req.jwt.sign(signup, kid: ThirdPartyAccessController.kid), options)
    }

    private func createAccount(
        for ticket: String, signup: String, credential: RegistrationCredential, on req: Request
    ) async throws -> WebAuthnCredential {
        guard let signup = try? await req.jwt.verify(signup, as: SignupTicket.self),
            signup.ticket == OpaqueToken.hash(ticket),
            let challenge = signup.passkeyChallenge.decodedBytes
        else {
            throw Abort(.badRequest, reason: "This sign-up has expired. Start again from the app.")
        }
        let registered: Credential
        do {
            registered = try await req.webAuthn.finishRegistration(
                challenge: challenge,
                credentialCreationData: credential,
                confirmCredentialIDNotRegisteredYet: { id in
                    try await WebAuthnCredential.find(id, on: req.db) == nil
                }
            )
        } catch {
            throw Abort(.unauthorized, reason: "That passkey couldn’t be created.")
        }
        let user = User(id: signup.user, username: signup.username)
        let created = WebAuthnCredential(from: registered, name: signup.username, userID: signup.user)
        try await req.db.transaction { db in
            try await user.create(on: db)
            try await created.create(on: db)
        }
        created.$user.value = user
        return created
    }

    // MARK: - Tickets and approval

    private func ticket(for request: AuthorisationRequest, native: Bool, on req: Request) async throws
        -> (AuthorisationTicket, PublicKeyCredentialRequestOptions)
    {
        // Never redirect anywhere until the URI is known to be the service's own.
        let client = try await req.thirdPartyClient(at: request.clientID)
        guard native || client.allows(redirectURI: request.redirectURI) else {
            throw Abort(.badRequest, reason: "That redirect URI isn't one of \(client.clientName)’s.")
        }
        guard request.responseType == "code" else { throw OAuthError.unsupportedResponseType }
        guard request.codeChallengeMethod == "S256", !request.codeChallenge.isEmpty else {
            throw OAuthError.invalidRequest
        }
        let scopes = Set(request.scope.split(separator: " ").map(String.init))
        let known = Set(client.scopeDescriptions.keys).union(KVScope.descriptions.keys)
        guard !scopes.isEmpty, scopes.isSubset(of: known) else { throw OAuthError.invalidScope }

        let options = req.webAuthn.beginAuthentication()
        let ticket = AuthorisationTicket(
            request: request, client: client, scopes: scopes.sorted(),
            allowlisted: req.application.thirdParty.isFirstParty(request.clientID), native: native,
            passkeyChallenge: options.challenge)
        return (ticket, options)
    }

    private func verified(_ ticket: String, on req: Request) async throws -> AuthorisationTicket {
        guard let ticket = try? await req.jwt.verify(ticket, as: AuthorisationTicket.self) else {
            throw Abort(.badRequest, reason: "This request has expired. Start again from the app.")
        }
        return ticket
    }

    private func approve(
        _ ticket: AuthorisationTicket, answering assertion: AuthenticationCredential, choosing scopes: [String]?,
        on req: Request
    ) async throws -> String {
        guard let challenge = ticket.passkeyChallenge.decodedBytes else {
            throw Abort(.badRequest, reason: "Approve with your passkey.")
        }
        let credential = try await req.verifiedPasskey(assertion, challenge: challenge)
        return try await issue(ticket, to: credential, choosing: scopes, on: req)
    }

    private func issue(
        _ ticket: AuthorisationTicket, to credential: WebAuthnCredential, choosing scopes: [String]?, on req: Request
    ) async throws -> String {
        if !ticket.native { try req.signIn(with: credential) }
        let (code, value) = AuthorisationCode.issue(
            for: ticket, scopes: ticket.granted(choosing: scopes), userID: try credential.user.requireID())
        try await code.save(on: req.db)
        return value
    }

    private func redirect(_ req: Request, to uri: String, _ parameters: [String: String]) -> Response {
        req.redirect(to: location(uri, parameters))
    }

    private func location(_ uri: String, _ parameters: [String: String]) -> String {
        guard var components = URLComponents(string: uri) else { return uri }
        components.queryItems = (components.queryItems ?? [])
            + parameters.sorted { $0.key < $1.key }.map { URLQueryItem(name: $0.key, value: $0.value) }
        return components.string ?? uri
    }

    // MARK: - Token endpoint

    func token(req: Request) async throws -> TokenResponse {
        let request = try req.content.decode(TokenRequest.self)
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
        guard let value = request.code, let verifier = request.codeVerifier else { throw OAuthError.invalidRequest }
        guard
            let code = try await AuthorisationCode.query(on: req.db)
                .filter(\.$codeHash == OpaqueToken.hash(value))
                .first()
        else { throw OAuthError.invalidGrant }
        try await code.delete(on: req.db)
        guard code.service == request.clientID, code.redirectURI == request.redirectURI ?? "",
            code.expiresAt > .now, code.isAnswered(by: verifier)
        else { throw OAuthError.invalidGrant }

        let grant = ThirdPartyGrant(approvedBy: code)
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
            try await token.grant.revoke(on: req.db, app: req.application)
            throw OAuthError.invalidGrant
        }
        token.spentAt = .now
        try await token.save(on: req.db)
        return try await issueTokens(for: token.grant, on: req)
    }

    private func issueTokens(for grant: ThirdPartyGrant, on req: Request) async throws -> TokenResponse {
        let access = try ThirdPartyAccessToken(grant: grant, issuer: req.application.thirdParty.issuer)
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
            try await token.grant.revoke(on: req.db, app: req.application)
        }
        return .ok
    }
}

enum OAuthError: String, AbortError {
    case invalidRequest = "invalid_request"
    case invalidScope = "invalid_scope"
    case invalidGrant = "invalid_grant"
    case unsupportedGrantType = "unsupported_grant_type"
    case unsupportedResponseType = "unsupported_response_type"

    var status: HTTPResponseStatus { .badRequest }

    var reason: String { rawValue }
}
