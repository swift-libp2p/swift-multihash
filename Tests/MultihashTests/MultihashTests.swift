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

@Suite("Multihash Tests")
struct MultihashTests {

    @Test func taggedHashListMatchesCurratedList() {
        let tagged = Set(Codecs.codecs(tagged: .multihash))
        let supported = Set(HashFunction.allCases.filter { $0 != .identity }.map(\.codec))

        #expect(tagged.isSuperset(of: supported))
    }

    @Test(arguments: MultihashTests.TestFixtures)
    func testHashFunctions(_ test: Fixture) throws {
        let codec = try Codecs(name: test.algorithm)
        let bytes = Int(test.bits)! / 8
        let mh = try Multihash(hashing: test.input, codec: codec, truncatedTo: bytes)

        #expect(mh.asString(base: .base16) == test.multihash)
        #expect(mh.hashName == test.algorithm)
        #expect(mh.digestLength == bytes)
        #expect(mh.digest.count == bytes)
        #expect(mh.code == codec.code)
    }

    @Test(arguments: MultihashTests.TestFixtures)
    func testHashFunctionsManually(_ test: Fixture) throws {
        let data = Array(test.input.data(using: .utf8)!)
        var hash: [UInt8]
        switch test.algorithm {
        case "sha1":
            hash = data.sha1()
        case "sha2-256":
            hash = data.sha2(.sha256)
        case "sha2-512":
            hash = data.sha2(.sha512)
        case "sha3-512":
            hash = data.sha3(.sha512)
        default:
            Issue.record("Unknown hash function \(test.algorithm)")
            return
        }

        let digest = hash.prefix(Int(test.bits)! / 8)
        let mh = try Multihash(digest: digest, codec: try Codecs(name: test.algorithm))
        #expect(mh.asString(base: .base16) == test.multihash)
    }

    @Test(arguments: HashFunction.allCases)
    func hashFunctionMatchesDirectHashing(function: HashFunction) throws {
        let input = Array("multihash".utf8)
        let digest = function.hash(input)

        if let expected = function.digestLength {
            #expect(digest.count == expected, "\(function) digest length")
        } else {
            // identity is the only variable length function
            #expect(function == .identity)
            #expect(digest == input)
        }

        // And the digest is what ends up in the multihash
        let mh = Multihash(hashing: input, with: function)
        #expect(Array(mh.digest) == digest)
        #expect(mh.digestLength == digest.count)
        #expect(mh.hashFunction == function)
    }

    // # sha1 - 0x11 - sha1("multihash")
    // 111488c2f11fb2ce392acb5b2986e640211c4690073e # sha1 in hex
    // CEKIRQXRD6ZM4OJKZNNSTBXGIAQRYRUQA47A==== # sha1 in base32
    // 5dsgvJGnvAfiR3K6HCBc4hcokSfmjj # sha1 in base58
    // ERSIwvEfss45KstbKYbmQCEcRpAHPg== # sha1 in base64

    @Test func testSHA1() throws {
        let originalHash = "multihash".data(using: .utf8)!.sha1()

        let multihash = try Multihash(hashing: "multihash", with: .sha1)
        #expect(multihash.debugDescription == "Multihash: sha1 0x11 20 88c2f11fb2ce392acb5b2986e640211c4690073e")
        #expect(multihash.asString(base: .base16) == "111488c2f11fb2ce392acb5b2986e640211c4690073e")
        #expect(multihash.asString(base: .base32PadUpper) == "CEKIRQXRD6ZM4OJKZNNSTBXGIAQRYRUQA47A====")
        #expect(multihash.asString(base: .base58btc) == "5dsgvJGnvAfiR3K6HCBc4hcokSfmjj")
        #expect(multihash.asString(base: .base64Pad) == "ERSIwvEfss45KstbKYbmQCEcRpAHPg==")

        #expect(multihash.hashName == "sha1")
        #expect(multihash.code == Codecs.sha1.code)
        #expect(Data(multihash.digest) == originalHash)
    }

    @Test func testSHA1Tests1() throws {
        let mh = try #require("multihash".data(using: .utf8))
        let originalHash = mh.sha1()
        let sha1 = try Multihash(digest: originalHash, codec: .sha1)

        #expect(sha1.asString(base: .base16) == "111488c2f11fb2ce392acb5b2986e640211c4690073e")
        #expect(sha1.asString(base: .base32PadUpper) == "CEKIRQXRD6ZM4OJKZNNSTBXGIAQRYRUQA47A====")
        #expect(sha1.asString(base: .base58btc) == "5dsgvJGnvAfiR3K6HCBc4hcokSfmjj")
        #expect(sha1.asString(base: .base64Pad) == "ERSIwvEfss45KstbKYbmQCEcRpAHPg==")

        // Round-trip through a fresh decode of the raw buffer
        let oh = try Multihash(sha1.value)
        #expect(oh.hashName == "sha1")
        #expect(oh.code == Codecs.sha1.code)
        #expect(Data(oh.digest) == originalHash)
        #expect(oh == sha1)
    }

    @Test func testSHA1Tests2() throws {
        let sha = "multihash".data(using: .utf8)!.sha1()

        let mh = try Multihash(hashing: "multihash", with: .sha1)
        #expect(mh.asString(base: .base16) == "111488c2f11fb2ce392acb5b2986e640211c4690073e")
        #expect(mh.asString(base: .base32PadUpper) == "CEKIRQXRD6ZM4OJKZNNSTBXGIAQRYRUQA47A====")
        #expect(mh.asString(base: .base58btc) == "5dsgvJGnvAfiR3K6HCBc4hcokSfmjj")
        #expect(mh.asString(base: .base64Pad) == "ERSIwvEfss45KstbKYbmQCEcRpAHPg==")

        #expect(mh.hashName == "sha1")
        #expect(mh.code == Codecs.sha1.code)
        #expect(Data(mh.digest) == sha)

        //'multihash' as a base16 hex string with the multibase 'f' prefix
        let bData = try #require("multihash".data(using: .utf8))
        let b = bData.sha1().asString(base: .base16, withMultibasePrefix: true)
        let mh2 = try Multihash(multibaseDigest: b, code: .sha1)
        #expect(mh2.asString(base: .base16) == "111488c2f11fb2ce392acb5b2986e640211c4690073e")
        #expect(mh2.asString(base: .base32PadUpper) == "CEKIRQXRD6ZM4OJKZNNSTBXGIAQRYRUQA47A====")
        #expect(mh2.asString(base: .base58btc) == "5dsgvJGnvAfiR3K6HCBc4hcokSfmjj")
        #expect(mh2.asString(base: .base64Pad) == "ERSIwvEfss45KstbKYbmQCEcRpAHPg==")

        #expect(mh2.hashName == "sha1")
        #expect(mh2.code == Codecs.sha1.code)
        #expect(Data(mh2.digest) == sha)

        //<base encoding> <hash type> <hash length> <hash>
        //       f             11           14        ...
        //   hex lower        sha1       20 bytes
        let mh3 = try Multihash(multibase: "f111488c2f11fb2ce392acb5b2986e640211c4690073e")
        #expect(mh3.asString(base: .base32PadUpper) == "CEKIRQXRD6ZM4OJKZNNSTBXGIAQRYRUQA47A====")
        #expect(mh3.asString(base: .base58btc) == "5dsgvJGnvAfiR3K6HCBc4hcokSfmjj")
        #expect(mh3.asString(base: .base64Pad) == "ERSIwvEfss45KstbKYbmQCEcRpAHPg==")

        #expect(mh3.hashName == "sha1")
        #expect(mh3.code == Codecs.sha1.code)
        #expect(Data(mh3.digest) == sha)

        let mh4 = try Multihash(multibase: "CCEKIRQXRD6ZM4OJKZNNSTBXGIAQRYRUQA47A====")
        #expect(mh4.asString(base: .base16) == "111488c2f11fb2ce392acb5b2986e640211c4690073e")
        #expect(mh4.asString(base: .base58btc) == "5dsgvJGnvAfiR3K6HCBc4hcokSfmjj")
        #expect(mh4.asString(base: .base64Pad) == "ERSIwvEfss45KstbKYbmQCEcRpAHPg==")

        #expect(mh4.hashName == "sha1")
        #expect(mh4.code == Codecs.sha1.code)
        #expect(Data(mh4.digest) == sha)

        // All four spell the same multihash
        #expect(Set([mh, mh2, mh3, mh4]).count == 1)
    }

    // # sha2-256 0x12 - sha2-256("multihash")
    // 12209cbc07c3f991725836a3aa2a581ca2029198aa420b9d99bc0e131d9f3e2cbe47 # sha2-256 in hex
    // CIQJZPAHYP4ZC4SYG2R2UKSYDSRAFEMYVJBAXHMZXQHBGHM7HYWL4RY= # sha256 in base32
    // QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk # sha256 in base58
    // EiCcvAfD+ZFyWDajqipYHKICkZiqQgudmbwOEx2fPiy+Rw== # sha256 in base64

    @Test func testSHA2_256() throws {
        let originalHash = "multihash".data(using: .utf8)!.sha256()

        let multihash = try Multihash(hashing: "multihash", with: .sha2_256)
        #expect(
            multihash.asString(base: .base16) == "12209cbc07c3f991725836a3aa2a581ca2029198aa420b9d99bc0e131d9f3e2cbe47"
        )
        #expect(
            multihash.asString(base: .base32PadUpper) == "CIQJZPAHYP4ZC4SYG2R2UKSYDSRAFEMYVJBAXHMZXQHBGHM7HYWL4RY="
        )
        #expect(multihash.asString(base: .base58btc) == "QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk")
        #expect(multihash.asString(base: .base64Pad) == "EiCcvAfD+ZFyWDajqipYHKICkZiqQgudmbwOEx2fPiy+Rw==")

        #expect(multihash.hashName == "sha2-256")
        #expect(multihash.code == Codecs.sha2_256.code)
        #expect(Data(multihash.digest) == originalHash)
    }

    @Test func testSHA2_256Tests1() throws {
        let mh = try #require("multihash".data(using: .utf8))
        let originalHash = mh.sha256()
        let sha256 = try Multihash(digest: originalHash, codec: .sha2_256)

        #expect(
            sha256.asString(base: .base16) == "12209cbc07c3f991725836a3aa2a581ca2029198aa420b9d99bc0e131d9f3e2cbe47"
        )
        #expect(
            sha256.asString(base: .base32PadUpper) == "CIQJZPAHYP4ZC4SYG2R2UKSYDSRAFEMYVJBAXHMZXQHBGHM7HYWL4RY="
        )
        #expect(sha256.asString(base: .base58btc) == "QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk")
        #expect(sha256.asString(base: .base64Pad) == "EiCcvAfD+ZFyWDajqipYHKICkZiqQgudmbwOEx2fPiy+Rw==")

        let oh = try Multihash(sha256.value)
        #expect(oh.hashName == "sha2-256")
        #expect(oh.code == Codecs.sha2_256.code)
        #expect(Data(oh.digest) == originalHash)
    }

    @Test func testSHA2_256Tests2() throws {
        let sha = "multihash".data(using: .utf8)!.sha256()

        let mh = try Multihash(hashing: "multihash", with: .sha2_256, using: .utf8)
        #expect(
            mh.asString(base: .base16) == "12209cbc07c3f991725836a3aa2a581ca2029198aa420b9d99bc0e131d9f3e2cbe47"
        )
        #expect(
            mh.asString(base: .base32PadUpper) == "CIQJZPAHYP4ZC4SYG2R2UKSYDSRAFEMYVJBAXHMZXQHBGHM7HYWL4RY="
        )
        #expect(mh.asString(base: .base58btc) == "QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk")
        #expect(mh.asString(base: .base64Pad) == "EiCcvAfD+ZFyWDajqipYHKICkZiqQgudmbwOEx2fPiy+Rw==")

        #expect(mh.hashName == "sha2-256")
        #expect(mh.code == Codecs.sha2_256.code)
        #expect(Data(mh.digest) == sha)
    }
}
