import Fluent
import FluentSQLiteDriver
import JWT
import Leaf
import QueuesFluentDriver
import Vapor
import WebAuthn

// configures your application
public func configure(_ app: Application) async throws {
    // mandatory CORS settings
    let corsConfiguration = CORSMiddleware.Configuration(
        allowedOrigin: .all,
        allowedMethods: [.GET, .POST, .PUT, .OPTIONS, .DELETE, .PATCH],
        allowedHeaders: [
            .accept, .authorization, .contentType, .origin, .xRequestedWith,
            .userAgent,
            .accessControlAllowOrigin, .accessControlAllowCredentials,
        ],
        allowCredentials: false
    )
    let cors = CORSMiddleware(configuration: corsConfiguration)

    app.middleware.use(cors, at: .beginning)
    app.middleware.use(
        FileMiddleware(publicDirectory: app.directory.publicDirectory)
    )

    // Configure the session driver before adding session middleware.
    app.sessions.configuration.cookieName = "passkv_session"
    app.sessions.configuration.cookieFactory = { sessionID in
        .init(
            string: sessionID.string,
            maxAge: Int(SessionLifetime.duration),
            isSecure: app.environment == .production,
            isHTTPOnly: true,
            sameSite: .strict
        )
    }

    if app.environment == .testing {
        // One in-memory database per test app, so suites running in
        // parallel never race over the same tables.
        app.databases.use(.sqlite(.memory), as: .sqlite)
    } else {
        // app.databases.use(.sqlite(.memory), as: .sqlite)
        app.databases.use(
            .sqlite(
                .file(Environment.get("SQLITE_DATABASE_PATH") ?? "db.sqlite")
            ),
            as: .sqlite
        )
    }

    app.sessions.use(.fluent)
    app.middleware.use(app.sessions.middleware)
    app.middleware.use(SessionLifetime())

    app.migrations.add(JobMetadataMigrate())
    app.migrations.add(SessionRecord.migration)
    app.migrations.add(CreateUser())
    app.migrations.add(CreateWebAuthnCredential())
    app.migrations.add(CreateThirdPartyGrant())
    app.migrations.add(CreateAuthorisationCode())
    app.migrations.add(CreateRefreshToken())
    app.migrations.add(AddThirdPartyClientDetails())
    app.migrations.add(CreateKVRecord())
    app.migrations.add(MoveUserStorageToKV())

    app.queues.use(.fluent())
    try app.queues.startInProcessJobs(on: .default)

    app.views.use(.leaf)
    app.leaf.tags["instanceDomain"] = InstanceDomainTag(domain: Environment.get("RP_ID") ?? "localhost")
    app.webAuthn = WebAuthnManager(
        configuration: WebAuthnManager.Configuration(
            relyingPartyID: Environment.get("RP_ID") ?? "localhost",
            relyingPartyName: Environment.get("RP_DISPLAY_NAME")
                ?? "PassKeyValue",
            relyingPartyOrigin: Environment.get("RP_ORIGIN")
                ?? "http://localhost:8080"
        )
    )

    // register routes
    try routes(app)

    let signingKey = try Environment.get("THIRD_PARTY_SIGNING_KEY")
        .flatMap { $0.isEmpty ? nil : $0 }
        .map { try ES256PrivateKey(pem: $0) }
    if let signingKey {
        await app.jwt.keys.add(ecdsa: signingKey, kid: ThirdPartyAccessController.kid)
    }
    try app.register(collection: ThirdPartyAccessController(publicKey: signingKey?.publicKey))
    if signingKey != nil {
        try app.register(collection: AuthorisationController())
    }

    try await app.autoMigrate()
}
