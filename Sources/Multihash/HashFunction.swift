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

// We use CryptoSwift due to swift-crypto not supporting the keccak variants of sha3
import CryptoSwift
import Multicodec

/// A hash algorithm this package can actually compute.
///
/// The multicodec table lists hundreds of codecs, and over a hundred of them are tagged
/// `multihash`, but only the ones below can be computed here. Naming them in their own type means
/// `Multihash(hashing:with:)` can't fail on an unsupported algorithm, so the mistake is caught at
/// compile time rather than surfacing as a runtime throw:
///
/// ```swift
/// let mh = Multihash(hashing: payload, with: .sha2_256)   // no `try` needed
/// ```
///
/// Use the optional ``init?(codec:)`` when a `Codecs` arrives from elsewhere.
///
/// - Note: Blake2b, Blake2s and Blake3 are not supported yet. Contributions welcome.
public enum HashFunction: String, CaseIterable, Hashable, Sendable {

    /// No hashing, the "digest" is the input exactly.
    ///
    /// Used to inline small payloads (e.g. an Ed25519 public key in a PeerID) where the value is
    /// smaller than a hash of it would be.
    case identity

    case md5
    case sha1
    case sha2_256
    case sha2_512
    case sha3_224
    case sha3_256
    case sha3_384
    case sha3_512
    case keccak_224
    case keccak_256
    case keccak_384
    case keccak_512

    /// The backing multicodec of this hash function.
    public var codec: Codecs {
        switch self {
        case .identity: .identity
        case .md5: .md5
        case .sha1: .sha1
        case .sha2_256: .sha2_256
        case .sha2_512: .sha2_512
        case .sha3_224: .sha3_224
        case .sha3_256: .sha3_256
        case .sha3_384: .sha3_384
        case .sha3_512: .sha3_512
        case .keccak_224: .keccak_224
        case .keccak_256: .keccak_256
        case .keccak_384: .keccak_384
        case .keccak_512: .keccak_512
        }
    }

    /// The hash function for `codec`, or `nil` if this package doesn't support  it.
    ///
    /// ```swift
    /// guard let function = HashFunction(codec: someCodec) else { throw … }
    /// ```
    public init?(codec: Codecs) {
        switch codec {
        case .identity: self = .identity
        case .md5: self = .md5
        case .sha1: self = .sha1
        case .sha2_256: self = .sha2_256
        case .sha2_512: self = .sha2_512
        case .sha3_224: self = .sha3_224
        case .sha3_256: self = .sha3_256
        case .sha3_384: self = .sha3_384
        case .sha3_512: self = .sha3_512
        case .keccak_224: self = .keccak_224
        case .keccak_256: self = .keccak_256
        case .keccak_384: self = .keccak_384
        case .keccak_512: self = .keccak_512
        default: return nil
        }
    }

    /// This hash function's name, according to the specs Multicodec table.
    public var name: String { self.codec.name }

    /// The number of bytes ``hash(_:)`` produces, or `nil` for ``identity``, whose output is as
    /// long as its input.
    public var digestLength: Int? {
        switch self {
        case .identity: nil
        case .md5: 16
        case .sha1: 20
        case .sha3_224, .keccak_224: 28
        case .sha2_256, .sha3_256, .keccak_256: 32
        case .sha3_384, .keccak_384: 48
        case .sha2_512, .sha3_512, .keccak_512: 64
        }
    }

    /// Hashes `bytes` with this function.
    ///
    /// - Returns: The digest or `bytes` exactly for ``identity``.
    public func hash(_ bytes: some Collection<UInt8>) -> [UInt8] {
        let input = Array(bytes)
        switch self {
        case .identity:
            return input
        case .md5:
            return input.md5()
        case .sha1:
            return input.sha1()
        case .sha2_256:
            return input.sha256()
        case .sha2_512:
            return input.sha512()
        case .sha3_224:
            return input.sha3(.sha224)
        case .sha3_256:
            return input.sha3(.sha256)
        case .sha3_384:
            return input.sha3(.sha384)
        case .sha3_512:
            return input.sha3(.sha512)
        case .keccak_224:
            return input.sha3(.keccak224)
        case .keccak_256:
            return input.sha3(.keccak256)
        case .keccak_384:
            return input.sha3(.keccak384)
        case .keccak_512:
            return input.sha3(.keccak512)
        }
    }
}

extension HashFunction: CustomStringConvertible {
    /// This hash function's name (ex: `sha2-256`) according to the specs Multicodec table.
    ///
    /// ```swift
    /// print("hashed with \(HashFunction.sha2_256)")  //hashed with sha2-256
    /// ```
    public var description: String { self.name }
}
