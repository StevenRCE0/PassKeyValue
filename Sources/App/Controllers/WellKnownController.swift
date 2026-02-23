import Vapor

struct WellKnownController: RouteCollection {
    func boot(routes: any RoutesBuilder) throws {
        routes.get(".well-known", "apple-app-site-association", use: appleAppSiteAssociation)
    }

    private func appleAppSiteAssociation(req: Request) async throws -> Response {
        guard let appIdentifier = Environment.get("APPLE_APP_IDENTIFIER") else {
            return .init(status: .notFound)
        }

        let responseString =
            """
            {
                "applinks": {
                    "details": [
                        {
                            "appIDs": [
                                "\(appIdentifier)"
                            ],
                            "components": [
                            ]
                        }
                    ]
                },
                "webcredentials": {
                    "apps": [
                        "\(appIdentifier)"
                    ]
                }
            }
            """
        let response = try await responseString.encodeResponse(for: req)
        response.headers.contentType = HTTPMediaType(type: "application", subType: "json")
        return response
    }
}
