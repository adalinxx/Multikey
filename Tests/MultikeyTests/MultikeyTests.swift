import XCTest
@testable import Multikey

final class MultikeyTests: XCTestCase {

    func testRoundTripEd25519() throws {
        let keyBytes = Data(repeating: 0xAB, count: 32)
        let mk = Multikey(keyType: .ed25519, keyBytes: keyBytes)
        let encoded = mk.encode()
        let decoded = try Multikey.decode(from: encoded)
        XCTAssertEqual(decoded.keyType, .ed25519)
        XCTAssertEqual(decoded.keyBytes, keyBytes)
    }

    func testRoundTripMLDSA65() throws {
        let keyBytes = Data(repeating: 0xCD, count: 1952)
        let mk = Multikey(keyType: .mlDSA65, keyBytes: keyBytes)
        let hex = mk.hexEncoded
        let decoded = try Multikey.decode(fromHex: hex)
        XCTAssertEqual(decoded.keyType, .mlDSA65)
        XCTAssertEqual(decoded.keyBytes, keyBytes)
    }

    func testEd25519PrefixByte() {
        let mk = Multikey(keyType: .ed25519, keyBytes: Data([0x01, 0x02]))
        let encoded = mk.encode()
        XCTAssertEqual(encoded[0], 0xed)
    }

    func testMultibyteVarintMLDSA65() {
        let mk = Multikey(keyType: .mlDSA65, keyBytes: Data())
        let encoded = mk.encode()
        XCTAssertGreaterThan(encoded.count, 1, "ML-DSA-65 code 0x1207 requires multi-byte varint")
    }

    func testUnknownKeyTypeThrows() {
        let unknown = Data([0xFF, 0xFF, 0x01, 0xAA])
        XCTAssertThrowsError(try Multikey.decode(from: unknown))
    }

    func testHexRoundTrip() throws {
        let keyBytes = Data((0..<32).map { UInt8($0) })
        let mk = Multikey(keyType: .secp256k1, keyBytes: keyBytes)
        let hex = mk.hexEncoded
        let decoded = try Multikey.decode(fromHex: hex)
        XCTAssertEqual(decoded, mk)
    }
}
