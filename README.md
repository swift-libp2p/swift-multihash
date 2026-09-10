# Multihash

[![](https://img.shields.io/badge/made%20by-Breth-blue.svg?style=flat-square)](https://breth.app)
[![](https://img.shields.io/badge/project-multiformats-blue.svg?style=flat-square)](https://github.com/multiformats/multiformats)
[![Swift Package Manager compatible](https://img.shields.io/badge/SPM-compatible-blue.svg?style=flat-square)](https://github.com/apple/swift-package-manager)
![Build & Test (macos and linux)](https://github.com/swift-libp2p/swift-multihash/actions/workflows/build+test.yml/badge.svg)

> Swift implementation of Multihash -> Self identifying hashes

## Table of Contents

- [Overview](#overview)
- [Install](#install)
- [Usage](#usage)
  - [Example](#example)
  - [API](#api)
- [Contributing](#contributing)
- [Credits](#credits)
- [License](#license)

## Overview
Multihash is a protocol for differentiating outputs from various well-established cryptographic hash functions, addressing size + encoding considerations.

#### For more details see 
- [https://github.com/multiformats/multihash](https://github.com/multiformats/multihash)

#### Note:
This package currently doesn't support Blake2b, Blake2s & Blake3. If you're up for the challenge, please feel free to add support!

## Install

Include the following dependency in your Package.swift file
```Swift
let package = Package(
    ...
    dependencies: [
        ...
        .package(url: "https://github.com/swift-libp2p/swift-multihash.git", .upToNextMinor(from: "0.3.0"))
    ],
    ...
        .target(
            ...
            dependencies: [
                ...
                .product(name: "Multihash", package: "swift-multihash"),
            ]),
    ...
)
```

## Usage

### Example

```Swift

import Multihash

/// Multihash Format
/// <uvarint hash function code><uvarint digest size in bytes><hash function output>

HashFunction.allCases
/// [.identity, .md5, .sha1, .sha2_256, .sha2_512, .sha3_224, .sha3_256, .sha3_384, .sha3_512,
///  .keccak_224, .keccak_256, .keccak_384, .keccak_512]

/// Hashing
let multihash = try Multihash(hashing: "multihash", with: .sha1)
multihash.asString(base: .base16)         // -> "111488c2f11fb2ce392acb5b2986e640211c4690073e"
multihash.asString(base: .base32PadUpper) // -> "CEKIRQXRD6ZM4OJKZNNSTBXGIAQRYRUQA47A===="
multihash.asString(base: .base58btc)      // -> "5dsgvJGnvAfiR3K6HCBc4hcokSfmjj"
multihash.asString(base: .base64Pad)      // -> "ERSIwvEfss45KstbKYbmQCEcRpAHPg=="

/// Hashing bytes never throws
let multihash = Multihash(hashing: payload, with: .sha2_256)
multihash.asString(base: .base16)         // -> "12209cbc07c3f991725836a3aa2a581ca2029198aa420b9d99bc0e131d9f3e2cbe47"
multihash.asString(base: .base58btc)      // -> "QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk"

/// Or wrap a digest you already have, without re-hashing it.
/// Throws if the digest is longer than the hash function can produce.
let digest = Array("multihash".utf8).sha1()
let mh = try Multihash(digest: digest, function: .sha1)

/// The parts are parsed once, at init, and are non-optional
mh.code                                   // -> 0x11        (UInt64)
mh.digestLength                           // -> 20          (Int)
mh.digest                                 // -> ArraySlice, zero-copy
mh.algorithm                              // -> Codecs.sha1
mh.hashName                               // -> "sha1"      (nil for codes outside the table)
mh.hashFunction                           // -> HashFunction.sha1

/// Decoding a Multihash

/// From a multibase compliant string. The base prefix is required, not guessed at.
///
/// "f111488c2f11fb2ce392acb5b2986e640211c4690073e"
///     f       11      14     88c2f11fb2ce392acb5b2986e640211c4690073e
/// <base16> <sha1> <20 bytes> <sha1 digest>
let mh = try Multihash(multibase: "f111488c2f11fb2ce392acb5b2986e640211c4690073e")

/// From a buffer that is exactly one multihash
let mh = try Multihash(buffer)            // any Collection<UInt8>: Array, ArraySlice, Data, …

/// From the front of a larger buffer — a CID, a multiaddr component, a framed message.
/// The digest length prefix says where the multihash ends, so the remainder comes back too.
let (mh, remaining) = try Multihash.decode(prefixed: buffer)
let (mh, remaining) = try buffer.multihash()   // same thing, as a Collection method

/// Verifying that a payload matches a hash
mh.matches(payload)                       // -> Bool, false if unverifiable
try mh.matching(payload)                  // throws .unsupportedHashFunction instead

```

### API

Every throwing member below is `throws(MultihashError)`. Multibase failures arrive wrapped as
`.invalidMultibase(MultibaseError)`, with the underlying cause preserved:

```Swift
do {
    let mh = try Multihash(multibase: string)
} catch {
    switch error {                                   // `error` is a MultihashError
    case .invalidMultibase(let cause): …             // and `cause` is a MultibaseError
    case .digestTooLongForHashFunction(_, let expected, let actual): …
    default: …
    }
}

// or match a specific nested cause directly
catch MultihashError.invalidMultibase(.unknownBase) { … }
```

```Swift

/// Hashing, non-throwing when using a HashFunction, throwing when using a Codec
Multihash(hashing: some Collection<UInt8>, with: HashFunction, truncatedTo: Int? = nil)
Multihash(hashing: some Collection<UInt8>, codec: Codecs, truncatedTo: Int? = nil) throws
Multihash(hashing: String, with: HashFunction, using: String.Encoding = .utf8, truncatedTo: Int? = nil) throws
Multihash(hashing: String, codec: Codecs, using: String.Encoding = .utf8, truncatedTo: Int? = nil) throws

/// Wrapping a precomputed digest.
/// Both throw if the digest is longer than the hash function can produce, shorter digests are allowed. 
/// A digest of the right length still proves nothing about the content, only `matching(_:)` against the original bytes does that.
Multihash(digest: some Collection<UInt8>, function: HashFunction) throws
Multihash(digest: some Collection<UInt8>, codec: Codecs) throws

/// Decoding
Multihash(_: some Collection<UInt8>) throws                        // the whole buffer is one multihash
Multihash.decode(prefixed:) -> (multihash: Multihash, remaining: SubSequence) throws
Collection<UInt8>.multihash() -> (multihash: Multihash, bytes: SubSequence) throws
Multihash(multibase: String) throws                                // prefix required
Multihash(multibaseDigest: String, code: Codecs) throws            // a bare digest, not a multihash
// ^ both report a bad multibase string as MultihashError.invalidMultibase(_:)

/// Properties, parsed once at init, non-optional
Multihash.value: [UInt8]          // the whole buffer, prefixes included
Multihash.code: UInt64
Multihash.digestLength: Int
Multihash.digest: ArraySlice<UInt8>   // a slice of `value`, no copy
Multihash.algorithm: Codecs?          // nil for codes outside the Multicodec table
Multihash.hashName: String?           // nil for codes outside the Multicodec table
Multihash.hashFunction: HashFunction? // nil if this package can't compute it

/// Strings
Multihash.asString(base: BaseEncoding, withMultibasePrefix: Bool = false) -> String
Multihash.description       // the base58btc form, e.g. "QmYtUc4iTC…"
Multihash.debugDescription  // "Multihash: sha1 0x11 20 88c2f11f…"

/// Verification
Multihash.matches(_: some Collection<UInt8>) -> Bool
Multihash.matching(_: some Collection<UInt8>) throws -> Bool  // distinguishes unverifiable from mismatched

/// HashFunction
HashFunction.allCases: [HashFunction]
HashFunction(codec: Codecs)   // -> HashFunction?
HashFunction.codec: Codecs
HashFunction.name: String
HashFunction.digestLength: Int?    // nil for .identity, whose output is as long as its input
HashFunction.hash(_: some Collection<UInt8>) -> [UInt8]

/// Multihash is a value type conforming to Sendable, Hashable, Codable,
/// RandomAccessCollection<UInt8> and ContiguousBytes, so it can be passed
/// anywhere bytes are expected:
/// - Data(mh)
/// - buffer.writeBytes(mh)
/// - try Multihash(otherMH)
///
/// NOTE: because of that, `count` and `first` refer to the entire buffer,
/// prefixes included. Use `digest` (or `digestLength`) for the digest alone.
```

## Contributing

Contributions are welcomed! This code is very much a proof of concept. I can guarantee you there's a better / safer way to accomplish the same results. Any suggestions, improvements, or even just critiques, are welcome! 

Let's make this code better together! 🤝

## Credits

- [Multiformats / Multihash](https://github.com/multiformats/multihash)
- [CryptoSwift](https://github.com/krzyzanowskim/CryptoSwift)

## License

[MIT](LICENSE) © 2026 Breth Inc.
