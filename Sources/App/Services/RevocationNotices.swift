import JWT
import Vapor

extension Application {
    struct RevocationRetries: StorageKey {
        typealias Value = [Duration]
    }

    var revocationRetries: [Duration] {
        get { storage[RevocationRetries.self] ?? [.seconds(5), .seconds(30), .seconds(120)] }
        set { storage[RevocationRetries.self] = newValue }
    }

    func announceRevocation(of grant: ThirdPartyGrant, to url: String) async throws {
        let notice = try ThirdPartyRevocation(grant: grant)
        let token = try await jwt.keys.sign(notice, kid: ThirdPartyAccessController.kid)
        Task { [self] in
            for delay in [Duration.zero] + revocationRetries {
                try? await Task.sleep(for: delay)
                let response = try? await client.post(URI(string: url)) { request in
                    request.headers.contentType = .jwt
                    request.body = .init(string: token)
                }
                if let response, (200..<300).contains(response.status.code) { return }
            }
            logger.warning("Gave up announcing the revocation of grant \(notice.grant) to \(url).")
        }
    }
}

extension HTTPMediaType {
    static let jwt = HTTPMediaType(type: "application", subType: "jwt")
}
