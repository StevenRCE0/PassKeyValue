import Vapor

struct KVEntry: Content {
    let key: String
    let value: String
}

struct KVUpsertRequest: Content {
    let value: String
}

struct KVListResponse: Content {
    let items: [KVEntry]
}

struct KVGetResponse: Content {
    let item: KVEntry
}

struct KVUpsertResponse: Content {
    let item: KVEntry
}

struct KVUpdateResponse: Content {
    let item: KVEntry
}

struct KVDeleteResponse: Content {
    let deletedKey: String
    let present: [String: String]
}
