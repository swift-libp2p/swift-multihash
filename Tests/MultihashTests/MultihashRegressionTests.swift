//===----------------------------------------------------------------------===//
//
// This source file is part of the swift-libp2p open source project
//
// Copyright (c) 2022-2026 swift-libp2p project authors
// Licensed under MIT
//
// See LICENSE for license information
// See CONTRIBUTORS for the list of swift-libp2p project authors
//
// SPDX-License-Identifier: MIT
//
//===----------------------------------------------------------------------===//

import Foundation
import Multibase
import Multicodec
import Testing
import VarInt

@testable import Multihash

/// Regression tests covering bugs found during the multihash spec review:
///  - the encoder wrote single raw bytes instead of varints (corrupted any code/length >= 128, e.g. md5)
///  - md5 `defaultHashLength` was 20 instead of 16
///  - decode threw on unknown-but-well-formed codes instead of tolerating them
///  - the 2-byte empty `identity` multihash was rejected as "too short"
/// Plus tests for the new Hashable / Codable conformances and the digest / matches helpers.
@Suite("Multihash Regression Tests")
struct MultihashRegressionTests {

    // MARK: - Bug: varint code encoding (md5 == 0xd5)

    /// md5's multicodec code is 0xd5 (213) — the only supported algorithm with a code >= 128.
    /// Before the fix it was written as a single byte and the varint decoder mis-parsed it,
    /// leaving every property `nil`. This is the headline regression.
    @Test func md5RoundTrips() throws {
        let mh = try Multihash(raw: "multihash", hashedWith: .md5)

        // 0xd5 as a varint is [0xd5, 0x01] -> "d501"; length 16 == 0x10 -> "10"
        #expect(mh.hexString.hasPrefix("d50110"))
        #expect(mh.code == Int(Codecs.md5.code))
        #expect(mh.code == 0xd5)
        #expect(mh.name == "md5")
        #expect(mh.length == 16)
        let expectedDigest = "multihash".data(using: .utf8)!.md5()
        #expect(mh.digest.map({ Data($0) }) == expectedDigest)

        // Round-trips through a fresh decode
        #expect(try Multihash(mh.value) == mh)
    }

    // MARK: - Full algorithm matrix round-trip

    /// Every supported algorithm (plus identity) must encode and decode consistently.
    /// Previously only sha1 / sha2-256 / sha2-512 / sha3-512 were exercised.
    @Test func allSupportedAlgorithmsRoundTrip() throws {
        for algo in Codecs.supportedHashAlgorithms + [.identity] {
            let mh = try Multihash(raw: "multihash", hashedWith: algo)

            #expect(mh.code == Int(algo.code), "code mismatch for \(algo)")
            #expect(mh.name == algo.name, "name mismatch for \(algo)")

            let digest = try #require(mh.digest, "nil digest for \(algo)")
            #expect(mh.length == digest.count, "length/digest mismatch for \(algo)")

            let decoded = try decodeMultihashBuffer(mh.value)
            #expect(decoded.code == Int(algo.code))
            #expect(decoded.name == algo.name)
            #expect(decoded.digest == digest)
            #expect(try Multihash(mh.value) == mh)
        }
    }

    // MARK: - Bug: md5 default length

    @Test func defaultHashLengths() {
        #expect(Codecs.md5.defaultHashLength == 16)  // md5 is 128-bit = 16 bytes
        #expect(Codecs.sha1.defaultHashLength == 20)
        #expect(Codecs.sha2_256.defaultHashLength == 32)
        #expect(Codecs.sha2_512.defaultHashLength == 64)
        #expect(Codecs.sha3_224.defaultHashLength == 28)
        #expect(Codecs.keccak_512.defaultHashLength == 64)
    }

    // MARK: - Bug: tolerant decode of unknown-but-valid codes

    @Test func decodeToleratesUnknownCode() throws {
        let unknownCode: UInt64 = 0x7FFF_FF00  // not present in the multicodec table
        var buf = unknownCode.varIntBytes.bytes
        buf.append(contentsOf: 2.varIntBytes.bytes)
        buf.append(contentsOf: [0xAA, 0xBB])

        let decoded = try decodeMultihashBuffer(buf)  // must not throw
        #expect(decoded.code == Int(unknownCode))
        #expect(decoded.name == nil)
        #expect(decoded.length == 2)
        #expect(decoded.digest == [0xAA, 0xBB])
    }

    // MARK: - Bug: empty identity multihash

    @Test func emptyIdentityDecodes() throws {
        let decoded = try decodeMultihashBuffer([0x00, 0x00])
        #expect(decoded.code == 0x00)
        #expect(decoded.name == "identity")
        #expect(decoded.length == 0)
        #expect(decoded.digest.isEmpty)
    }

    // MARK: - Negative / robustness

    @Test func tooShortThrows() {
        #expect(throws: (any Error).self) { try decodeMultihashBuffer([0x11]) }
    }

    @Test func inconsistentLengthThrows() {
        // code sha1, claims 20 bytes but only 1 provided
        #expect(throws: (any Error).self) { try decodeMultihashBuffer([0x11, 0x14, 0x00]) }
    }

    // MARK: - New API: init(digest:code:)

    @Test func digestInitializerMatchesRawHashing() throws {
        let digest = Array("multihash".data(using: .utf8)!.sha1())
        let fromDigest = try Multihash(digest: digest, code: .sha1)
        let fromRaw = try Multihash(raw: "multihash", hashedWith: .sha1)
        #expect(fromDigest == fromRaw)
        #expect(fromDigest.asString(base: .base16) == "111488c2f11fb2ce392acb5b2986e640211c4690073e")
    }

    // MARK: - New API: matches()

    @Test func matchesVerifiesPayload() throws {
        let mh = try Multihash(raw: "multihash", hashedWith: .sha2_256)
        #expect(mh.matches(raw: Array("multihash".utf8)))
        #expect(!mh.matches(raw: Array("not multihash".utf8)))
    }

    // MARK: - New conformances: Hashable & Codable

    @Test func hashableUsableAsSetMember() throws {
        let a = try Multihash(raw: "multihash", hashedWith: .sha2_256)
        let b = try Multihash(raw: "multihash", hashedWith: .sha2_256)
        let c = try Multihash(raw: "different", hashedWith: .sha2_256)
        #expect(Set([a, b, c]).count == 2)
    }

    @Test func codableRoundTrip() throws {
        let mh = try Multihash(raw: "multihash", hashedWith: .sha2_512)
        let data = try JSONEncoder().encode(mh)
        let restored = try JSONDecoder().decode(Multihash.self, from: data)
        #expect(restored == mh)
    }

    // MARK: - String initializers (previously untested directly)

    @Test func hexStringInitializer() throws {
        let mh = try Multihash(hexString: "111488c2f11fb2ce392acb5b2986e640211c4690073e")
        #expect(mh.name == "sha1")
        #expect(mh.asString(base: .base58btc) == "5dsgvJGnvAfiR3K6HCBc4hcokSfmjj")
    }

    @Test func b58StringInitializer() throws {
        let mh = try Multihash(b58String: "5dsgvJGnvAfiR3K6HCBc4hcokSfmjj")
        #expect(mh.name == "sha1")
        #expect(mh.asString(base: .base16) == "111488c2f11fb2ce392acb5b2986e640211c4690073e")
    }
}
