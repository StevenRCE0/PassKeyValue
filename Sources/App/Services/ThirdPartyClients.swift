import Vapor

extension Request {
    func thirdPartyClient(at clientID: String) async throws -> ThirdPartyClient {
        let unreadable = Abort(.badRequest, reason: "PassKeyValue couldn’t read that service’s description.")
        guard let url = URL(string: clientID), url.scheme == "https", let host = url.host else { throw unreadable }
        guard
            let response = try? await client.get(URI(string: clientID), beforeSend: { $0.timeout = .seconds(5) }),
            response.status == .ok,
            let body = response.body, body.readableBytes <= 64 * 1024,
            let document = try? JSONDecoder().decode(ThirdPartyClient.self, from: body),
            document.clientID == clientID
        else { throw unreadable }
        if let notices = document.revocationNoticeURI {
            guard let noticeURL = URL(string: notices), noticeURL.scheme == "https", noticeURL.host == host
            else { throw unreadable }
        }
        return document
    }
}
