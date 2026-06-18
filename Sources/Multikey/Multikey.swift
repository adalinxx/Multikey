import Foundation

/// Registered key types from the multicodec table.
/// https://github.com/multiformats/multicodec/blob/master/table.csv
public enum KeyType: UInt64, Sendable, Codable, CaseIterable {
    case ed25519    = 0xed
    case secp256k1  = 0xe7
    case p256       = 0x1200
    case p384       = 0x1201
    case p521       = 0x1202
    case mlDSA44    = 0x1205   // ML-DSA-44  (Dilithium level 2)
    case mlDSA65    = 0x1207   // ML-DSA-65  (Dilithium level 3)
    case mlDSA87    = 0x1208   // ML-DSA-87  (Dilithium level 5)

    public var name: String {
        switch self {
        case .ed25519:   return "ed25519"
        case .secp256k1: return "secp256k1"
        case .p256:      return "p256"
        case .p384:      return "p384"
        case .p521:      return "p521"
        case .mlDSA44:   return "ml-dsa-44"
        case .mlDSA65:   return "ml-dsa-65"
        case .mlDSA87:   return "ml-dsa-87"
        }
    }
}

/// A public key encoded as varint(keyType) + keyBytes.
/// Compatible with the multicodec/multikey spec.
public struct Multikey: Sendable, Equatable, Hashable {
    public let keyType: KeyType
    public let keyBytes: Data

    public init(keyType: KeyType, keyBytes: Data) {
        self.keyType = keyType
        self.keyBytes = keyBytes
    }

    // MARK: - Encoding

    public func encode() -> Data {
        var out = Data()
        out.append(contentsOf: uvarint(keyType.rawValue))
        out.append(keyBytes)
        return out
    }

    public var hexEncoded: String {
        encode().map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Decoding

    public static func decode(from data: Data) throws -> Multikey {
        var offset = 0
        let (code, bytesRead) = try readUvarint(data, offset: &offset)
        guard let keyType = KeyType(rawValue: code) else {
            throw MultikeyError.unknownKeyType(code)
        }
        let keyBytes = data[offset...]
        return Multikey(keyType: keyType, keyBytes: Data(keyBytes))
    }

    public static func decode(fromHex hex: String) throws -> Multikey {
        guard let data = Data(hexString: hex) else {
            throw MultikeyError.invalidEncoding
        }
        return try decode(from: data)
    }
}

// MARK: - Errors

public enum MultikeyError: Error, Sendable {
    case unknownKeyType(UInt64)
    case invalidEncoding
    case varintOverflow
    case varintTruncated
}

// MARK: - Varint helpers

private func uvarint(_ value: UInt64) -> [UInt8] {
    var v = value
    var bytes: [UInt8] = []
    while v >= 0x80 {
        bytes.append(UInt8(v & 0x7F) | 0x80)
        v >>= 7
    }
    bytes.append(UInt8(v))
    return bytes
}

private func readUvarint(_ data: Data, offset: inout Int) throws -> (UInt64, Int) {
    var result: UInt64 = 0
    var shift = 0
    let start = offset
    while offset < data.count {
        let byte = data[offset]
        offset += 1
        guard shift < 64 else { throw MultikeyError.varintOverflow }
        result |= UInt64(byte & 0x7F) << shift
        if byte & 0x80 == 0 { return (result, offset - start) }
        shift += 7
    }
    throw MultikeyError.varintTruncated
}

// MARK: - Hex helpers

private extension Data {
    init?(hexString: String) {
        let hex = hexString.hasPrefix("0x") ? String(hexString.dropFirst(2)) : hexString
        guard hex.count % 2 == 0 else { return nil }
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        self = data
    }
}
