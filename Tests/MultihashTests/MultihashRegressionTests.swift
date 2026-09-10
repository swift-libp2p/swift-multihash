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

import CryptoSwift
import Foundation
import Multibase
import Multicodec
import Testing
import VarInt

@testable import Multihash

/// Regression tests covering bugs found during the Multihash spec review:
///  - the encoder wrote single raw bytes instead of varints (corrupted any code/length >= 128, e.g. md5)
///  - md5's default hash length was 20 instead of 16
///  - decode threw on unknown-but-well-formed codes instead of tolerating them
///  - the 2-byte empty `identity` Multihash was rejected as "too short"
/// Plus tests for the Hashable / Codable conformances and the digest / matches helpers.
@Suite("Multihash Regression Tests")
struct MultihashRegressionTests {

    // MARK: - Bug: varint code encoding (md5 == 0xd5)

    /// md5's multicodec code is 0xd5 (213) — the only supported algorithm with a code >= 128.
    /// Before the fix it was written as a single byte and the VarInt decoder mis-parsed it,
    /// leaving every property `nil`.
    @Test func md5RoundTrips() throws {
        let mh = try Multihash(hashing: "multihash", with: .md5)

        // 0xd5 as a varint is [0xd5, 0x01] -> "d501"; length 16 == 0x10 -> "10"
        #expect(mh.asString(base: .base16).hasPrefix("d50110"))
        #expect(mh.code == Codecs.md5.code)
        #expect(mh.code == 0xd5)
        #expect(mh.hashName == "md5")
        #expect(mh.digestLength == 16)
        let expectedDigest = "multihash".data(using: .utf8)!.md5()
        #expect(Data(mh.digest) == expectedDigest)

        // Round-trips through a fresh decode
        #expect(try Multihash(mh.value) == mh)
    }

    // MARK: - Full algorithm matrix round-trip

    /// Every supported hash function must encode and decode consistently.
    /// Previously only sha1 / sha2-256 / sha2-512 / sha3-512 were exercised.
    @Test(arguments: HashFunction.allCases)
    func allSupportedAlgorithmsRoundTrip(function: HashFunction) throws {
        let mh = try Multihash(hashing: "multihash", with: function)

        #expect(mh.code == function.codec.code, "code mismatch for \(function)")
        #expect(mh.hashName == function.name, "name mismatch for \(function)")
        #expect(mh.hashFunction == function, "hashFunction mismatch for \(function)")
        #expect(mh.digestLength == mh.digest.count, "length/digest mismatch for \(function)")

        let decoded = try Multihash(mh.value)
        #expect(decoded.code == function.codec.code)
        #expect(decoded.hashName == function.name)
        #expect(decoded.digest == mh.digest)
        #expect(decoded == mh)
    }

    // MARK: - Bug: md5 default length

    @Test func defaultHashLengths() {
        #expect(HashFunction.md5.digestLength == 16)  // md5 is 128-bit = 16 bytes
        #expect(HashFunction.sha1.digestLength == 20)
        #expect(HashFunction.sha2_256.digestLength == 32)
        #expect(HashFunction.sha2_512.digestLength == 64)
        #expect(HashFunction.sha3_224.digestLength == 28)
        #expect(HashFunction.keccak_512.digestLength == 64)
        // identity's digest is as long as its input, so it has no fixed length
        #expect(HashFunction.identity.digestLength == nil)
    }

    /// Every hash function's advertised length must match what it actually produces.
    @Test(arguments: HashFunction.allCases)
    func digestLengthMatchesOutput(function: HashFunction) throws {
        guard let expected = function.digestLength else {
            #expect(function == .identity)
            return
        }
        #expect(try Multihash(hashing: "multihash", with: function).digestLength == expected)
    }

    // MARK: - Bug: tolerant decode of unknown-but-valid codes

    @Test func decodeToleratesUnknownCode() throws {
        let unknownCode: UInt64 = 0x7FFF_FF00  // not present in the multicodec table
        var buf = unknownCode.varIntBytes.bytes
        buf.append(contentsOf: 2.varIntBytes.bytes)
        buf.append(contentsOf: [0xAA, 0xBB])

        let decoded = try Multihash(buf)  // must not throw
        #expect(decoded.code == unknownCode)
        #expect(decoded.hashName == nil)
        #expect(decoded.algorithm == nil)
        #expect(decoded.hashFunction == nil)
        #expect(decoded.digestLength == 2)
        #expect(Array(decoded.digest) == [0xAA, 0xBB])
    }

    /// An unknown code can't be verified, and that has to be distinguishable from a mismatch.
    @Test func unknownCodeCannotBeVerified() throws {
        var buf = UInt64(0x7FFF_FF00).varIntBytes.bytes
        buf.append(contentsOf: 2.varIntBytes.bytes)
        buf.append(contentsOf: [0xAA, 0xBB])
        let mh = try Multihash(buf)

        #expect(mh.matches([0xAA, 0xBB]) == false)
        #expect(throws: MultihashError.self) { try mh.matching([0xAA, 0xBB]) }
    }

    /// A codec that exists but isn't a hash function this package can compute.
    @Test func unsupportedHashFunctionIsReported() throws {
        #expect(throws: MultihashError.unsupportedHashFunction(.blake3)) {
            try Multihash(hashing: "multihash", codec: .blake3)
        }
        #expect(throws: MultihashError.unsupportedHashFunction(.dag_pb)) {
            try Multihash(hashing: "multihash", codec: .dag_pb)
        }
        #expect(HashFunction(codec: .blake3) == nil)
        #expect(HashFunction(codec: .dag_pb) == nil)
    }

    // MARK: - Bug: empty identity Multihash

    @Test func emptyIdentityDecodes() throws {
        let decoded = try Multihash([0x00, 0x00])
        #expect(decoded.code == 0x00)
        #expect(decoded.hashName == "identity")
        #expect(decoded.digestLength == 0)
        #expect(decoded.digest.isEmpty)
    }

    // MARK: - Negative / robustness

    @Test func tooShortThrows() {
        #expect(throws: MultihashError.bufferTooShort) { try Multihash([0x11]) }
        #expect(throws: MultihashError.bufferTooShort) { try Multihash([UInt8]()) }
    }

    @Test func inconsistentLengthThrows() {
        // code sha1, claims 20 bytes but only 1 provided
        #expect(throws: MultihashError.inconsistentLength(20)) { try Multihash([0x11, 0x14, 0x00]) }
    }

    @Test func trailingBytesThrows() throws {
        let mh = try Multihash(hashing: "multihash", with: .sha1)
        #expect(throws: MultihashError.trailingBytes) { try Multihash(mh.value + [0xFF]) }
    }

    // MARK: - decode(prefixed:)

    /// The CIDv1 layout: `<version><content codec><multihash>`. The Multihash's own length prefix
    /// is what says where it ends, which is what `decode(prefixed:)` exists to use.
    @Test func decodePrefixedReadsMultihashOutOfACIDv1() throws {
        let mh = try Multihash(hashing: "multihash", with: .sha2_256)
        var cid: [UInt8] = [0x01]  // CIDv1
        cid.append(contentsOf: Codecs.dag_pb.asVarInt)
        cid.append(contentsOf: mh.value)

        // Walk the CID the way a consumer would
        let (codec, afterCodec) = try Codecs.decode(prefixed: cid.dropFirst())
        #expect(codec == .dag_pb)

        let (decoded, remaining) = try Multihash.decode(prefixed: afterCodec)
        #expect(decoded == mh)
        #expect(remaining.isEmpty)
    }

    /// A Multihash followed by more payload: the remainder must come back untouched.
    @Test func decodePrefixedReturnsTheRemainder() throws {
        let mh = try Multihash(hashing: "multihash", with: .sha1)
        let trailer: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]

        let (decoded, remaining) = try Multihash.decode(prefixed: mh.value + trailer)
        #expect(decoded == mh)
        #expect(Array(remaining) == trailer)

        // …and the same via the Collection helper
        let (viaHelper, rest) = try (mh.value + trailer).multihash()
        #expect(viaHelper == mh)
        #expect(Array(rest) == trailer)
    }

    @Test func decodePrefixedNeedsAWholeMultihash() throws {
        let mh = try Multihash(hashing: "multihash", with: .sha1)
        // Truncated mid-digest
        #expect(throws: MultihashError.self) { try Multihash.decode(prefixed: mh.value.dropLast()) }
        // Truncated mid-prefix: a lone continuation byte is an incomplete varint
        #expect(throws: MultihashError.bufferTooShort) { try Multihash.decode(prefixed: [0x80, 0x80]) }
    }

    // MARK: - Collection-generic input

    @Test func acceptsAnyByteCollection() throws {
        let mh = try Multihash(hashing: "multihash", with: .sha2_256)

        let fromArray = try Multihash(mh.value)
        let fromSlice = try Multihash(mh.value[...])
        let fromData = try Multihash(Data(mh.value))
        let fromDataSlice = try Multihash(Data([0xFF] + mh.value).dropFirst())
        let fromMultihash = try Multihash(mh)  // Multihash is itself a byte collection

        #expect(Set([mh, fromArray, fromSlice, fromData, fromDataSlice, fromMultihash]).count == 1)
    }

    @Test func isUsableAsAByteCollection() throws {
        let mh = try Multihash(hashing: "multihash", with: .sha1)

        #expect(Data(mh) == Data(mh.value))
        #expect(Array(mh) == mh.value)
        #expect(mh.count == mh.value.count)  // whole buffer, prefixes included
        #expect(mh.count == mh.digestLength + 2)  // sha1's code and length prefixes are 1 byte each
        #expect(mh.withUnsafeBytes { Array($0) } == mh.value)
    }

    // MARK: - init(digest:…)

    @Test func digestInitializerMatchesRawHashing() throws {
        let digest = Array("multihash".data(using: .utf8)!.sha1())
        let fromDigest = try Multihash(digest: digest, function: .sha1)
        let fromCodec = try Multihash(digest: digest, codec: .sha1)
        let fromRaw = try Multihash(hashing: "multihash", with: .sha1)

        #expect(fromDigest == fromRaw)
        #expect(fromCodec == fromRaw)
        #expect(fromDigest.asString(base: .base16) == "111488c2f11fb2ce392acb5b2986e640211c4690073e")
    }

    /// Truncation has to be reflected in the length prefix, not just the digest.
    @Test func truncatedDigestsRoundTrip() throws {
        let mh = try Multihash(hashing: "multihash", with: .sha2_256, truncatedTo: 10)
        #expect(mh.digestLength == 10)
        #expect(mh.digest.count == 10)
        #expect(try Multihash(mh.value) == mh)

        let full = try Multihash(hashing: "multihash", with: .sha2_256)
        #expect(Array(mh.digest) == Array(full.digest.prefix(10)))
    }

    // MARK: - Digest length check

    @Test func digestLongerThanTheHashFunctionIsRejected() throws {
        let sha256Digest = Array("multihash".data(using: .utf8)!.sha256())  // 32 bytes
        #expect(sha256Digest.count == 32)

        #expect(throws: MultihashError.digestTooLongForHashFunction(.md5, expected: 16, actual: 32)) {
            try Multihash(digest: sha256Digest, function: .md5)
        }
        #expect(throws: MultihashError.digestTooLongForHashFunction(.md5, expected: 16, actual: 32)) {
            try Multihash(digest: sha256Digest, codec: .md5)
        }

        // Ensure the correct error message is thrown
        let error = MultihashError.digestTooLongForHashFunction(.md5, expected: 16, actual: 32)
        #expect("\(error)" == "a 32 byte digest can't have come from md5, which produces 16 bytes")
    }

    /// Truncation is legal, so a *shorter* digest must still be accepted.
    /// The conformance fixtures in `TestValues.swift` depend on this (sha1 at 80 bits, …).
    @Test(arguments: HashFunction.allCases)
    func shorterDigestsAreAccepted(function: HashFunction) throws {
        // Skip `identity`
        guard function != .identity else { return }

        let expected = try #require(function.digestLength)
        let digest = Array(function.hash(Array("multihash".utf8)).prefix(expected / 2))

        let mh = try Multihash(digest: digest, function: function)
        #expect(mh.digestLength == expected / 2)
        #expect(try Multihash(digest: digest, codec: function.codec) == mh)

        // Exactly the full length is fine too, it's the boundary
        let full = function.hash(Array("multihash".utf8))
        #expect(try Multihash(digest: full, function: function).digestLength == expected)
    }

    /// `identity` has no fixed output length, so nothing is checked for it.
    @Test func identityAcceptsAnyDigestLength() throws {
        for length in [0, 1, 64, 1024] {
            let mh = try Multihash(digest: [UInt8](repeating: 0xAB, count: length), function: .identity)
            #expect(mh.digestLength == length)
        }
    }

    /// Codecs this package can't compute have no expected length, so the check is deliberately skipped.
    @Test func codecsWithoutAHashFunctionSkipTheCheck() throws {
        #expect(HashFunction(codec: .blake3) == nil)

        let mh = try Multihash(digest: [UInt8](repeating: 0xCD, count: 64), codec: .blake3)
        #expect(mh.digestLength == 64)
        #expect(mh.algorithm == .blake3)
        #expect(mh.hashFunction == nil)
        #expect(try Multihash(mh.value) == mh)
    }

    // MARK: - matches / matching

    @Test func matchesVerifiesPayload() throws {
        let mh = try Multihash(hashing: "multihash", with: .sha2_256)
        #expect(mh.matches(Array("multihash".utf8)))
        #expect(!mh.matches(Array("not multihash".utf8)))

        #expect(try mh.matching(Array("multihash".utf8)))
        #expect(try !mh.matching(Array("not multihash".utf8)))
    }

    /// A truncated Multihash verifies against an equally truncated digest.
    @Test func matchesHonoursTruncation() throws {
        let mh = try Multihash(hashing: "multihash", with: .sha2_256, truncatedTo: 10)
        #expect(mh.matches(Array("multihash".utf8)))
        #expect(!mh.matches(Array("not multihash".utf8)))
    }

    // MARK: - Conformances: Hashable & Codable

    @Test func hashableUsableAsSetMember() throws {
        let a = try Multihash(hashing: "multihash", with: .sha2_256)
        let b = try Multihash(hashing: "multihash", with: .sha2_256)
        let c = try Multihash(hashing: "different", with: .sha2_256)
        #expect(Set([a, b, c]).count == 2)
    }

    @Test func codableRoundTrip() throws {
        let mh = try Multihash(hashing: "multihash", with: .sha2_512)
        let data = try JSONEncoder().encode(mh)
        let restored = try JSONDecoder().decode(Multihash.self, from: data)
        #expect(restored == mh)

        // Encoded as Data, i.e. a single base64 string rather than an array of integers
        let json = try #require(String(data: data, encoding: .utf8))
        #expect(json.hasPrefix("\""))
        #expect(!json.hasPrefix("["))
    }

    /// 0.2.x wrote the buffer as `[UInt8]`. Anything already persisted has to keep decoding.
    @Test func codableDecodesLegacyByteArrayForm() throws {
        let mh = try Multihash(hashing: "multihash", with: .sha1)
        let legacy = "[" + mh.value.map(String.init).joined(separator: ",") + "]"

        let restored = try JSONDecoder().decode(Multihash.self, from: Data(legacy.utf8))
        #expect(restored == mh)
    }

    // MARK: - Descriptions

    @Test func descriptionIsTheCanonicalBase58String() throws {
        let mh = try Multihash(hashing: "multihash", with: .sha2_256)
        #expect(mh.description == "QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk")
        #expect("\(mh)" == mh.asString(base: .base58btc))
    }

    @Test func debugDescriptionSpellsOutTheParts() throws {
        let mh = try Multihash(hashing: "multihash", with: .sha1)
        #expect(mh.debugDescription == "Multihash: sha1 0x11 20 88c2f11fb2ce392acb5b2986e640211c4690073e")
        // The old implementation left a trailing newline behind
        #expect(!mh.debugDescription.hasSuffix("\n"))
    }

    @Test func debugDescriptionHandlesUnknownCodes() throws {
        var buf = UInt64(0x7FFF_FF00).varIntBytes.bytes
        buf.append(contentsOf: 1.varIntBytes.bytes)
        buf.append(0xAA)

        #expect(try Multihash(buf).debugDescription == "Multihash: unknown 0x7FFFFF00 1 aa")
    }

    // MARK: - String initializers

    @Test func multibaseInitializerRoundTrips() throws {
        let mh = try Multihash(hashing: "multihash", with: .sha1)

        for base in [BaseEncoding.base16, .base32, .base58btc, .base64] {
            let encoded = mh.asString(base: base, withMultibasePrefix: true)
            #expect(try Multihash(multibase: encoded) == mh, "round-trip failed for \(base)")
        }
    }

    /// `init(multibase:)` requires the prefix rather than guessing at it, which is what made the
    /// old `init(b58String:)` misread any base58btc Multihash starting with `z`.
    @Test func multibaseInitializerRequiresThePrefix() throws {
        let mh = try Multihash(hashing: "multihash", with: .sha1)
        let bare = mh.asString(base: .base58btc)  // "5dsgvJGnvAfiR3K6HCBc4hcokSfmjj", no prefix

        // Without the prefix the leading '5' names base10, which can't hold this string
        #expect(throws: (any Error).self) { try Multihash(multibase: bare) }
        // Decoding it explicitly is the replacement
        #expect(try Multihash(BaseEncoding.decode(bare, as: .base58btc)) == mh)
    }
}

// MARK: - Deprecated API

/// The 0.2.x surface is kept as shims so downstream keeps compiling while it migrates. These
/// exercise each one, so a shim that stops forwarding correctly fails here rather than downstream.
@Suite("Deprecated API Shims")
struct MultihashDeprecatedTests {

    @Test func bufferFunctions() throws {
        let digest = Array("multihash".data(using: .utf8)!.sha1())

        let encoded = try encodeMultihashBuffer(digest, asHashType: Codecs.sha1)
        #expect(try encoded == Multihash(digest: digest, function: .sha1).value)
        #expect(try encodeMultihashBuffer(digest, asHashType: "sha1") == encoded)
        #expect(try encodeMultihashBuffer(digest, code: Int(Codecs.sha1.code)) == encoded)

        let decoded = try decodeMultihashBuffer(encoded)
        #expect(decoded.code == Int(Codecs.sha1.code))
        #expect(decoded.name == "sha1")
        #expect(decoded.length == 20)
        #expect(decoded.digest == digest)
    }

    @Test func initializers() throws {
        let expected = try Multihash(hashing: "multihash", with: .sha1)

        #expect(try Multihash(raw: "multihash", hashedWith: .sha1) == expected)
        #expect(try Multihash(raw: "multihash".data(using: .utf8)!, hashedWith: .sha1) == expected)
        #expect(try Multihash(raw: Array("multihash".utf8), hashedWith: .sha1) == expected)
        #expect(try Multihash(multihash: "f111488c2f11fb2ce392acb5b2986e640211c4690073e") == expected)
        #expect(try Multihash(multihash: Data(expected.value)) == expected)
        #expect(try Multihash(hexString: "111488c2f11fb2ce392acb5b2986e640211c4690073e") == expected)
        #expect(try Multihash(b58String: "5dsgvJGnvAfiR3K6HCBc4hcokSfmjj") == expected)

        let digestHex = Array("multihash".data(using: .utf8)!.sha1())
            .asString(base: .base16, withMultibasePrefix: true)
        #expect(try Multihash(multibase: digestHex, codec: .sha1) == expected)
    }

    @Test func stringsAndMatching() throws {
        let mh = try Multihash(hashing: "multihash", with: .sha1)

        #expect(mh.hexString == "111488c2f11fb2ce392acb5b2986e640211c4690073e")
        #expect(mh.string == mh.hexString)
        #expect(mh.b58String == "5dsgvJGnvAfiR3K6HCBc4hcokSfmjj")
        #expect(mh.asMultibase(.base16) == "f111488c2f11fb2ce392acb5b2986e640211c4690073e")

        #expect(mh.matches(raw: Array("multihash".utf8)))
        #expect(mh.matches(raw: "multihash".data(using: .utf8)!))
        #expect(!mh.matches(raw: Array("nope".utf8)))
    }

    @Test func codecExtensions() {
        #expect(Codecs.md5.defaultHashLength == 16)
        #expect(Codecs.sha2_256.defaultHashLength == 32)
        #expect(Codecs.dag_pb.defaultHashLength == nil)
        #expect(Codecs.supportedHashAlgorithms.count == HashFunction.allCases.count - 1)
        #expect(Codecs.supportedHashAlgorithms.contains(.sha2_256))
        #expect(!Codecs.supportedHashAlgorithms.contains(.identity))
    }
}
