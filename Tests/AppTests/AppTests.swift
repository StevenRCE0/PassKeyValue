@testable import App
import XCTVapor

final class AppTests: XCTestCase {
    func testBeginWithAuthenticationStage() throws {
        let app = Application(.testing)
        defer { app.shutdown() }
        try configure(app)

        try app.test(.POST, "begin", beforeRequest: { req in
            let payload = BeginPasskeyRequest(stage: .authentication)
            try req.content.encode(payload)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
        })
    }
}
