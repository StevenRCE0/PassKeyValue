import Vapor

struct KVEntry: Content {
    let key: User.KVKeyType
    let value: User.KVValueType
}

struct KVUpsertRequest: Content {
    let value: User.KVValueType
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
    let deletedKey: User.KVKeyType
    let present: User.KVType
}
