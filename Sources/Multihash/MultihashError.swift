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
import Multicodec

/// The errors thrown by this module.
public enum MultihashError: Error, Hashable, Sendable {

    /// No known codec goes by the given code or name.
    case unknownCode

    /// The buffer was shorter than necessary to read the VarInt prefixes and payload.
    ///
    /// - Note: This indicates a short read; the same buffer with more bytes may decode
    ///   successfully.
    case bufferTooShort

    /// A VarInt prefix isn't a valid, minimally encoded, 64 bit unsigned varint.
    case invalidVarInt

    /// The digest was too long to write a length prefix for.
    case lengthNotSupported

    /// The buffer's digest was shorter than its length prefix claimed.
    ///
    /// The associated value is the claimed length.
    ///
    /// - Note: Usually means the buffer holds something larger that merely *starts* with a
    ///   Multihash, such as a CID or a multiaddr component. Use `Multihash.decode(prefixed:)` for
    ///   those.
    case inconsistentLength(Int)

    /// The buffer held a complete Multihash followed by bytes that aren't part of it.
    ///
    /// - Note: Use `Multihash.decode(prefixed:)` to decode a Multihash out of a larger buffer and
    ///   get the remainder back.
    case trailingBytes

    /// The codec names a hash function this package can't compute.
    ///
    /// Either it isn't a hash function at all, or it's one that hasn't been implemented here yet
    /// (blake2b, blake2s and blake3). See `HashFunction` for the ones that are supported.
    case unsupportedHashFunction(Codecs)

    /// The string couldn't be represented in the requested encoding.
    case invalidStringEncoding(String.Encoding)
}

extension MultihashError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .unknownCode:
            "no known codec goes by that code or name"
        case .bufferTooShort:
            "the buffer was shorter than necessary to read the two VarInt prefixes"
        case .invalidVarInt:
            "a VarInt prefix isn't a valid, minimally encoded, 64 bit unsigned VarInt"
        case .lengthNotSupported:
            "the digest is too long to write a length prefix for"
        case .inconsistentLength(let length):
            "the digest is shorter than its length prefix claims (\(length) bytes)"
        case .trailingBytes:
            "the buffer holds a complete Multihash followed by bytes that aren't part of it"
        case .unsupportedHashFunction(let codec):
            "\(codec) isn't a hash function this package can compute"
        case .invalidStringEncoding(let encoding):
            "the string couldn't be represented in String.Encoding(rawValue: \(encoding.rawValue))"
        }
    }
}
