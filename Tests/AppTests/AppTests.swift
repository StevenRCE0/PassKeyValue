import Testing
import VaporTesting

@testable import App

@Suite("App Tests")
struct AppTests {
    @Test("Test BeginPasskeyRequest")
    func testBeginPasskeyRequest() async throws {
        try await withApp(configure: configure) { app in
            try await app.testing().test(
                .POST, "begin",
                beforeRequest: { req async throws in
                    let payload = BeginPasskeyRequest(stage: .authentication)
                    try req.content.encode(payload)
                },
                afterResponse: { res in
                    #expect(res.status == .ok)
                })
        }
    }
}
