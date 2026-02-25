import Fluent
import FluentSQLiteDriver
import Leaf
import QueuesFluentDriver
import Vapor
import WebAuthn

// configures your application
public func configure(_ app: Application) throws {
    // mandatory CORS settings
    let corsConfiguration = CORSMiddleware.Configuration(
        allowedOrigin: .all,
        allowedMethods: [.GET, .POST, .PUT, .OPTIONS, .DELETE, .PATCH],
        allowedHeaders: [
            .accept, .authorization, .contentType, .origin, .xRequestedWith, .userAgent,
            .accessControlAllowOrigin, .accessControlAllowCredentials,
        ],
        allowCredentials: true
    )
    let cors = CORSMiddleware(configuration: corsConfiguration)

    app.middleware.use(cors, at: .beginning)
    app.middleware.use(FileMiddleware(publicDirectory: app.directory.publicDirectory))

    // apply app session
    app.sessions.configuration.cookieName = "passkv_session"
    app.middleware.use(app.sessions.middleware)

    if app.environment == .testing {
        app.databases.use(
            .sqlite(.file(Environment.get("SQLITE_DATABASE_PATH") ?? "db.sqlite")), as: .sqlite)
    } else {
        // app.databases.use(.sqlite(.memory), as: .sqlite)
        app.databases.use(
            .sqlite(.file(Environment.get("SQLITE_DATABASE_PATH") ?? "db.sqlite")), as: .sqlite)
    }

    app.sessions.use(.fluent)

    app.migrations.add(JobMetadataMigrate())
    app.migrations.add(SessionRecord.migration)
    app.migrations.add(CreateUser())
    app.migrations.add(CreateWebAuthnCredential())

    app.queues.use(.fluent())
    try app.queues.startInProcessJobs(on: .default)

    app.queues.schedule(DeleteUsersJob()).hourly().at(0)
    try app.queues.startScheduledJobs()

    app.views.use(.leaf)
    app.webAuthn = WebAuthnManager(
        configuration: WebAuthnManager.Configuration(
            relyingPartyID: Environment.get("RP_ID") ?? "localhost",
            relyingPartyName: Environment.get("RP_DISPLAY_NAME") ?? "Vapor Passkey Demo",
            relyingPartyOrigin: Environment.get("RP_ORIGIN") ?? "http://localhost:8080"
        )
    )

    // register routes
    try routes(app)

    try app.autoMigrate().wait()
}
