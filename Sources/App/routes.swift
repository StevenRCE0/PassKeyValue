import Vapor

func routes(_ app: Application) throws {
    try app.register(collection: TestViewController())
    try app.register(collection: PasskeyController())
    try app.register(collection: KVController())
    try app.register(collection: WellKnownController())
}
