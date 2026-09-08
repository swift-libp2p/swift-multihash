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
//
//  Deprecated.swift
//
//  Compatibility shims for the pre-0.3.0 API
//

import Foundation
import Multibase
import Multicodec

// MARK: - Errors

extension MultihashError {

    @available(*, deprecated, renamed: "varIntBufferTooShort")
    public static var VarIntBufferTooShort: MultihashError { .bufferTooShort }

    @available(*, deprecated, renamed: "invalidVarInt")
    public static var VarIntTooLarge: MultihashError { .invalidVarInt }
}

// MARK: - Buffer Functions

/// - Note: The replacement parses once and exposes the parts as non-optional properties.
@available(*, deprecated, message: "Use `try Multihash(buf)`, or `Multihash.decode(prefixed:)`.")
public func decodeMultihashBuffer(_ buf: [UInt8]) throws -> DecodedMultihash {
    let mh = try Multihash(buf)
    return DecodedMultihash(code: Int(mh.code), name: mh.hashName, length: mh.digestLength, digest: Array(mh.digest))
}

@available(*, deprecated, message: "Use `try Multihash(digest: buf, code: Codecs(code: code)).value`.")
public func encodeMultihashBuffer(_ buf: [UInt8], code: Int?) throws -> [UInt8] {
    guard let code, let codec = try? Codecs(code: code) else { throw MultihashError.unknownCode }
    return try Multihash(digest: buf, codec: codec).value
}

@available(*, deprecated, message: "Use `try Multihash(digest: buf, code: asHashType).value`.")
public func encodeMultihashBuffer(_ buf: [UInt8], asHashType: Codecs) throws -> [UInt8] {
    try Multihash(digest: buf, codec: asHashType).value
}

@available(*, deprecated, message: "Use `try Multihash(digest: buf, code: Codecs(name: asHashType)).value`.")
public func encodeMultihashBuffer(_ buf: [UInt8], asHashType: String) throws -> [UInt8] {
    try Multihash(digest: buf, codec: try Codecs(name: asHashType)).value
}

/// The parts of a decoded multihash.
///
/// - Note: `Multihash` now carries these itself, non-optionally and without re-parsing on every
///   access. Use `mh.code`, `mh.name`, `mh.digestLength` and `mh.digest` instead.
@available(*, deprecated, message: "Use the `code`, `hashName`, `digestLength` and `digest` properties on `Multihash`.")
public struct DecodedMultihash {
    public let code: Int
    public let name: String?
    public let length: Int
    public let digest: [UInt8]
}

// MARK: - Initializers

extension Multihash {

    @available(*, deprecated, message: "Use `Multihash(multibase:)`, which requires the base prefix.")
    public init(multihash: String) throws {
        // Preserved verbatim: decodes whatever base the leading prefix names.
        let raw = try BaseEncoding.decode(multihash)
        try self.init(raw.data)
    }

    @available(*, deprecated, message: "Use `Multihash(_:)`, which takes any byte collection.")
    public init(multihash: Data) throws {
        try self.init(multihash)
    }

    /// - Note: The replacement doesn't guess at prefixes. Decode the string yourself with
    ///   `Array<UInt8>(decoding: str, as: .base16)` and pass the bytes to `Multihash(_:)`.
    @available(*, deprecated, message: "Use `try Multihash(Array<UInt8>(decoding: str, as: .base16))`.")
    public init(hexString str: String) throws {
        // Preserved verbatim, including the odd-length heuristic that treats the first character
        // as an already-present multibase prefix.
        let prefixed = str.count % 2 == 1 ? str : BaseEncoding.base16.charPrefix + str
        try self.init(try BaseEncoding.decode(prefixed).data)
    }

    /// - Note: The replacement doesn't guess at prefixes. This shim prepends `z` unless the string
    ///   already starts with one, which misreads any base58btc multihash that legitimately begins
    ///   with `z`.
    @available(*, deprecated, message: "Use `try Multihash(Array<UInt8>(decoding: str, as: .base58btc))`.")
    public init(b58String str: String) throws {
        // Preserved verbatim, prefix heuristic and all.
        let prefixed =
            str.hasPrefix(BaseEncoding.base58btc.charPrefix) ? str : BaseEncoding.base58btc.charPrefix + str
        try self.init(try BaseEncoding.decode(prefixed).data)
    }

    /// - Note: Renamed because the string holds a bare *digest*, not a multihash.
    @available(*, deprecated, renamed: "init(digestMultibase:code:)")
    public init(multibase: String, codec: Codecs) throws {
        try self.init(multibaseDigest: multibase, code: codec)
    }

    @available(*, deprecated, message: "Use `Multihash(hashing:codec:truncatedTo:)`.")
    public init(
        raw: String,
        hashedWith codec: Codecs,
        using encoding: String.Encoding = .utf8,
        customByteLength: Int? = nil
    ) throws {
        try self.init(hashing: raw, codec: codec, using: encoding, truncatedTo: customByteLength)
    }

    @available(*, deprecated, message: "Use `Multihash(hashing:codec:truncatedTo:)`.")
    public init(raw: Data, hashedWith codec: Codecs, customByteLength: Int? = nil) throws {
        try self.init(hashing: raw, codec: codec, truncatedTo: customByteLength)
    }

    @available(*, deprecated, message: "Use `Multihash(hashing:codec:truncatedTo:)`.")
    public init(raw d: [UInt8], hashedWith codec: Codecs, customByteLength: Int? = nil) throws {
        try self.init(hashing: d, codec: codec, truncatedTo: customByteLength)
    }
}

// MARK: - Strings

extension Multihash {

    @available(*, deprecated, message: "Use `asString(base:withMultibasePrefix: true)`.")
    public func asMultibase(_ base: BaseEncoding) -> String {
        self.asString(base: base, withMultibasePrefix: true)
    }

    @available(*, deprecated, message: "Use `asString(base: .base16)`.")
    public var hexString: String {
        self.asString(base: .base16)
    }

    @available(*, deprecated, message: "Use `asString(base: .base58btc)`, or `description`.")
    public var b58String: String {
        self.asString(base: .base58btc)
    }

    @available(*, deprecated, message: "Use `asString(base: .base16)`. `description` is now the base58btc form.")
    public var string: String {
        self.asString(base: .base16)
    }
}

// MARK: - Verification

extension Multihash {

    @available(*, deprecated, message: "Use `matches(_:)`, or `matching(_:)` to surface an unsupported algorithm.")
    public func matches(raw: [UInt8]) -> Bool {
        self.matches(raw)
    }

    @available(*, deprecated, message: "Use `matches(_:)`, or `matching(_:)` to surface an unsupported algorithm.")
    public func matches(raw: Data) -> Bool {
        self.matches(raw)
    }
}

// MARK: - Codecs

extension Codecs {

    /// - Note: Replaced by `HashFunction`, which lives in this module rather than extending
    ///   another package's type, and rules out unsupported algorithms at compile time.
    @available(*, deprecated, message: "Use `HashFunction.allCases`, or `HashFunction.allCases.map(\\.codec)`.")
    public static var supportedHashAlgorithms: [Codecs] {
        HashFunction.allCases.filter { $0 != .identity }.map(\.codec)
    }

    @available(*, deprecated, message: "Use `HashFunction(codec: self)?.digestLength`.")
    public var defaultHashLength: Int? {
        HashFunction(codec: self)?.digestLength
    }
}
