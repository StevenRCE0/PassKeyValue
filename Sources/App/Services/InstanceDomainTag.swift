import Leaf

struct InstanceDomainTag: LeafTag {
    let domain: String

    func render(_: LeafContext) throws -> LeafData {
        .string(domain)
    }
}
