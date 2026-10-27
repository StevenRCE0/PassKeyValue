import Vapor

struct ThirdPartySettings: Sendable {
    var issuer: String
    var firstPartyDomains: [String]

    func isFirstParty(_ clientID: String) -> Bool {
        guard let host = URL(string: clientID)?.host?.lowercased() else { return false }
        return firstPartyDomains.contains { host == $0 || host.hasSuffix(".\($0)") }
    }

    static func fromEnvironment() -> ThirdPartySettings {
        ThirdPartySettings(
            issuer: Environment.get("RP_ORIGIN") ?? "http://localhost:8080",
            firstPartyDomains: (Environment.get("FIRST_PARTY_DOMAINS") ?? "")
                .split(separator: ",")
                .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
                .filter { !$0.isEmpty }
        )
    }
}

extension Application {
    private struct ThirdPartySettingsKey: StorageKey {
        typealias Value = ThirdPartySettings
    }

    var thirdParty: ThirdPartySettings {
        get { storage[ThirdPartySettingsKey.self] ?? .fromEnvironment() }
        set { storage[ThirdPartySettingsKey.self] = newValue }
    }
}
