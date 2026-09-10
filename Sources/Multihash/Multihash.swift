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
import VarInt

/// A self describing hash.
///
/// The wire format is three parts back to back:
/// ```
/// <uVarInt hash function code><uVarInt digest length in bytes><digest>
/// ```
///
/// ```swift
/// let mh = Multihash(hashing: "multihash".utf8, with: .sha1)
/// mh.hashName                             // "sha1"
/// mh.code                             // 0x11
/// mh.digestLength                           // 20
/// mh.asString(base: .base16)          // "111488c2f11fb2ce392acb5b2986e640211c4690073e"
/// ```
///
/// Multihash conforms to `RandomAccessCollection` using its `value`, so it can be used wherever a
/// collection of bytes is needed.
///
/// ```swift
/// Data(mh)                   // Foundation
/// buffer.writeBytes(mh)      // NIO ByteBuffer
/// mh.asString(base: .base58btc)
/// ```
///
/// - Warning: Because of that conformance, `count` and `first` refer to the *entire* buffer,
///   prefixes included. Use ``digest`` (and `digest.count`, or ``digestLength``) for the digest alone.
public struct Multihash: Sendable, Hashable, CustomStringConvertible, CustomDebugStringConvertible {

    /// The entire Multihash buffer, prefixes included.
    public let value: [UInt8]

    /// The code of the hash function used to compute the digest (ex: `0x11` for sha1).
    public let code: UInt64

    /// The length of the digest in bytes.
    ///
    /// - Note: Always equal to `digest.count`.
    public let digestLength: Int

    /// The digest, without the hash function and length prefixes.
    ///
    /// A slice of ``value``, so reading it doesn't copy. Use `Data(mh.digest)` or
    /// `Array(mh.digest)` when a standalone buffer is needed.
    public var digest: ArraySlice<UInt8> { self.value[self.digestStart...] }

    /// The codec of the hash function used to compute the digest, or `nil` if ``code`` isn't in
    /// the multicodec table.
    ///
    /// A well formed Multihash carrying an unknown code still decodes, it just can't be named.
    public var algorithm: Codecs? { Codecs(rawValue: self.code) }

    /// The name of the hash function used to compute the digest (ex: `sha2-256`), or `nil` if
    /// ``code`` isn't in the multicodec table.
    public var hashName: String? { self.algorithm?.name }

    /// The hash function used to compute the digest, or `nil` if this package can't compute it.
    public var hashFunction: HashFunction? {
        self.algorithm.flatMap(HashFunction.init(codec:))
    }

    /// Where the digest starts in ``value``, a.k.a the combined width of the two VarInt prefixes.
    private let digestStart: Int

    private init(value: [UInt8], code: UInt64, length: Int, digestStart: Int) {
        self.value = value
        self.code = code
        self.digestLength = length
        self.digestStart = digestStart
    }
}

// MARK: - Decoding

extension Multihash {

    /// Decodes the Multihash at the front of `bytes`, along with whatever follows it.
    ///
    /// ```swift
    /// let (multihash, rest) = try Multihash.decode(prefixed: buffer)
    /// ```
    ///
    /// Mirrors `Codecs.decode(prefixed:)`.
    ///
    /// - Parameter bytes: A buffer beginning with a Multihash.
    /// - Returns: The Multihash, and a slice of everything after it.
    /// - Throws:
    ///   - ``bufferTooShort`` or ``varIntBufferTooShort`` if `bytes` ends part way
    ///   through the Multihash
    ///   - ``invalidVarInt`` if a prefix isn't a valid minimally encoded 64 bit uVarInt
    ///   - ``lengthNotSupported`` if the claimed digest length is too large to represent.
    ///
    /// - Note: A well formed Multihash whose code isn't in the multicodec table decodes fine; its
    ///   ``hashName`` is simply `nil`.
    public static func decode<Bytes: Collection<UInt8>>(
        prefixed bytes: Bytes
    ) throws(MultihashError) -> (multihash: Multihash, remaining: Bytes.SubSequence) {
        // A multihash is at minimum two bytes: a code varint and a length varint. An empty
        // `identity` digest is the shortest legal one, `0x00 0x00`.
        let available = bytes.count
        if available < 2 { throw MultihashError.bufferTooShort }

        var reader = VarIntReader(bytes)
        let code = try Multihash.readPrefix(&reader)
        let claimedLength = try Multihash.readPrefix(&reader)

        // We dont support lengths larger than Int32.max
        guard claimedLength <= UInt64(Int32.max) else { throw MultihashError.lengthNotSupported }
        let length = Int(claimedLength)

        let digestStart = reader.bytesConsumed
        let afterDigest = digestStart + length
        guard afterDigest <= available else { throw MultihashError.inconsistentLength(length) }

        var value = [UInt8]()
        value.reserveCapacity(afterDigest)
        value.append(contentsOf: bytes.prefix(afterDigest))

        let multihash = Multihash(value: value, code: code, length: length, digestStart: digestStart)
        return (multihash, bytes.dropFirst(afterDigest))
    }

    /// Reads one uVarInt prefix using a VarIntReader.
    private static func readPrefix<Bytes: Collection<UInt8>>(
        _ reader: inout VarIntReader<Bytes>
    ) throws(MultihashError) -> UInt64 {
        do {
            return try reader.readUVarInt()
        } catch VarIntError.needsMoreBytes {
            // The buffer ended part way through the prefix
            throw MultihashError.bufferTooShort
        } catch {
            // The prefix didn't fit in 64 bits, or wasn't minimally encoded
            throw MultihashError.invalidVarInt
        }
    }

    /// Initializes a Multihash from a buffer that is exactly one Multihash and nothing else.
    ///
    /// ```swift
    /// let mh = try Multihash(buffer)
    /// ```
    ///
    /// - Parameter bytes: The Multihash buffer, prefixes included.
    /// - Throws:
    ///   - ``MultihashError/trailingBytes`` if anything follows the digest
    ///   - any other ``MultihashError``.
    ///
    /// - Note: Use ``decode(prefixed:)`` when the Multihash is embedded in a larger buffer.
    public init(_ bytes: some Collection<UInt8>) throws(MultihashError) {
        let (multihash, remaining) = try Multihash.decode(prefixed: bytes)
        guard remaining.isEmpty else { throw MultihashError.trailingBytes }
        self = multihash
    }
}

extension Collection<UInt8> {

    /// The Multihash at the front of this buffer, and the bytes that follow it.
    ///
    /// ```swift
    /// let (multihash, rest) = try buffer.multihash()
    /// ```
    ///
    /// - Returns: The Multihash, and a slice of this buffer after it.
    /// - Throws: see ``Multihash/decode(prefixed:)``
    public func multihash() throws(MultihashError) -> (multihash: Multihash, bytes: SubSequence) {
        let (multihash, remaining) = try Multihash.decode(prefixed: self)
        return (multihash: multihash, bytes: remaining)
    }
}

// MARK: - Encoding

extension Multihash {

    /// Wraps an already computed digest, without re-hashing it.
    ///
    /// ```swift
    /// let digest = Array("multihash".utf8).sha1()  // 88c2f11fb2ce392acb5b2986e640211c4690073e
    /// let mh = Multihash(digest: digest, function: .sha1)
    /// mh.asString(base: .base16)  // "111488c2f11fb2ce392acb5b2986e640211c4690073e"
    /// ```
    ///
    /// - Parameters:
    ///   - digest: The precomputed digest.
    ///   - function: The hash function that produced `digest`.
    /// - Throws:
    ///   - ``MultihashError/digestTooLongForHashFunction(_:expected:actual:)`` if `digest` is
    ///   longer than `function` can produce.
    ///
    /// - Note: Wrapped Multihashes should be treated as unverified / untrusted until proven valid
    ///   using ``matches(_:)`` or ``matching(_:)`` against the original bytes
    public init(digest: some Collection<UInt8>, function: HashFunction) throws(MultihashError) {
        try Multihash.checkDigestLength(digest.count, against: function)
        self = Multihash.encoding(digest: digest, code: function.codec.code)!
    }

    /// Wraps an already computed digest, without re-hashing it.
    ///
    /// - Parameters:
    ///   - digest: The precomputed digest. Truncated digests are legal and are wrapped as-is.
    ///   - codec: The codec of the hash function that produced `digest`.
    /// - Throws:
    ///   - ``MultihashError/digestTooLongForHashFunction(_:expected:actual:)`` if `digest` is
    ///   longer than `codec`'s hash function can produce
    ///   - ``MultihashError/lengthNotSupported`` if it is too long to write a length prefix for.
    ///
    /// - Note: Wrapped Multihashes should be treated as unverified / untrusted until proven valid
    ///   using ``matches(_:)`` or ``matching(_:)`` against the original bytes
    public init(digest: some Collection<UInt8>, codec: Codecs) throws(MultihashError) {
        if let function = HashFunction(codec: codec) {
            try Multihash.checkDigestLength(digest.count, against: function)
        }
        guard let multihash = Multihash.encoding(digest: digest, code: codec.code) else {
            throw MultihashError.lengthNotSupported
        }
        self = multihash
    }

    /// Rejects a digest longer than `function` can produce.
    ///
    /// Shorter is legal, the spec permits truncation. ``HashFunction/identity`` has no fixed
    /// length, so nothing is checked for it.
    private static func checkDigestLength(
        _ length: Int,
        against function: HashFunction
    ) throws(MultihashError) {
        guard let expected = function.digestLength, length > expected else { return }
        throw .digestTooLongForHashFunction(function, expected: expected, actual: length)
    }

    /// Builds the Multihash buffer for `digest` under `code`, or `nil` if the digest is too long
    /// for its length prefix.
    private static func encoding(digest: some Collection<UInt8>, code: UInt64) -> Multihash? {
        let length = digest.count
        // The digest length is stored as a VarInt, keep it within the range the decoder accepts.
        guard length <= Int(Int32.max) else { return nil }

        // Both prefixes MUST be uVarInts so codes & lengths >= 128 (md5 == 0xd5) round-trip.
        let codePrefix = code.varIntBytes
        let lengthPrefix = UInt64(length).varIntBytes
        let digestStart = codePrefix.count + lengthPrefix.count

        var value = [UInt8]()
        value.reserveCapacity(digestStart + length)
        value.append(contentsOf: codePrefix)
        value.append(contentsOf: lengthPrefix)
        value.append(contentsOf: digest)

        return Multihash(value: value, code: code, length: length, digestStart: digestStart)
    }
}

// MARK: - Hashing

extension Multihash {

    /// Hashes `bytes` and prefixes the digest.
    ///
    /// ```swift
    /// let mh = Multihash(hashing: "multihash".utf8, with: .sha2_256)
    /// mh.asString(base: .base58btc)  // "QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk"
    /// ```
    ///
    /// - Parameters:
    ///   - bytes: The bytes to hash.
    ///   - function: The hash function to hash `bytes` with.
    ///   - truncatedTo: Keep only the leading `truncatedTo` bytes of the digest. `nil` keeps the
    ///     whole digest.
    public init(
        hashing bytes: some Collection<UInt8>,
        with function: HashFunction,
        truncatedTo length: Int? = nil
    ) {
        let digest = function.hash(bytes)
        let truncated = length.map { digest.prefix($0) } ?? digest[...]
        // this only ever returns nil if the digest exceeds the hash function's digest
        // length which can't happen here so force unwrapping the optional is okay
        self = Multihash.encoding(digest: truncated, code: function.codec.code)!
    }

    /// Hashes `bytes` and wraps the digest.
    ///
    /// - Parameters:
    ///   - bytes: The bytes to hash.
    ///   - codec: The codec of the hash function to hash `bytes` with.
    ///   - truncatedTo: Keep only the leading `truncatedTo` bytes of the digest.
    /// - Throws:
    ///   - ``MultihashError/unsupportedHashFunction(_:)`` if `codec` isn't a hash function
    ///     this package can compute.
    public init(
        hashing bytes: some Collection<UInt8>,
        codec: Codecs,
        truncatedTo length: Int? = nil
    ) throws(MultihashError) {
        guard let function = HashFunction(codec: codec) else {
            throw MultihashError.unsupportedHashFunction(codec)
        }
        self.init(hashing: bytes, with: function, truncatedTo: length)
    }

    /// Hashes a string's encoded bytes and wraps the digest.
    ///
    /// ```swift
    /// let mh = try Multihash(hashing: "multihash", with: .sha2_256)
    /// mh.asString(base: .base16)  // "12209cbc07c3f991725836a3aa2a581ca2029198aa420b9d99bc0e131d9f3e2cbe47"
    /// ```
    ///
    /// - Parameters:
    ///   - string: The string whose bytes should be hashed.
    ///   - function: The hash function to hash the bytes with.
    ///   - encoding: The encoding to convert `string` into bytes with (defaults to utf8).
    ///   - truncatedTo: Keep only the leading `truncatedTo` bytes of the digest.
    /// - Throws:
    ///   - ``MultihashError/invalidStringEncoding(_:)`` if `string` can't be represented in
    ///     `encoding`.
    public init(
        hashing string: String,
        with function: HashFunction,
        using encoding: String.Encoding = .utf8,
        truncatedTo length: Int? = nil
    ) throws(MultihashError) {
        guard let data = string.data(using: encoding) else {
            throw MultihashError.invalidStringEncoding(encoding)
        }
        self.init(hashing: data, with: function, truncatedTo: length)
    }

    /// Hashes a string's encoded bytes and wraps the digest.
    ///
    /// - Parameters:
    ///   - string: The string whose bytes should be hashed.
    ///   - codec: The codec of the hash function to hash `bytes` with.
    ///   - encoding: The encoding to convert `string` into bytes with (defaults to utf8).
    ///   - truncatedTo: Keep only the leading `truncatedTo` bytes of the digest.
    /// - Throws:
    ///   - ``MultihashError/unsupportedHashFunction(_:)`` if `codec` isn't a hash function
    ///   this package can compute
    ///   - ``MultihashError/invalidStringEncoding(_:)`` if `string` can't be represented in `encoding`.
    public init(
        hashing string: String,
        codec: Codecs,
        using encoding: String.Encoding = .utf8,
        truncatedTo length: Int? = nil
    ) throws(MultihashError) {
        guard let function = HashFunction(codec: codec) else {
            throw MultihashError.unsupportedHashFunction(codec)
        }
        try self.init(hashing: string, with: function, using: encoding, truncatedTo: length)
    }
}

// MARK: - Strings

extension Multihash {

    /// Initializes a Multihash from a Multibase encoded Multihash string.
    ///
    /// ```swift
    /// // "f111488c2f11fb2ce392acb5b2986e640211c4690073e"
    /// //    f       11      14     88c2f11fb2ce392acb5b2986e640211c4690073e
    /// // <base16> <sha1> <20 bytes> <sha1 digest>
    /// let mh = try Multihash(multibase: "f111488c2f11fb2ce392acb5b2986e640211c4690073e")
    /// mh.hashName   // "sha1"
    /// mh.code   // 0x11
    /// ```
    ///
    /// - Parameter string: A Multibase encoded Multihash, *including* its base prefix. The prefix
    ///   is what identifies the base, so it is required rather than guessed at.
    /// - Throws:
    ///   - ``MultihashError/invalidMultibase(_:)`` if `string` isn't valid Multibase.
    ///   - Any other ``MultihashError`` if the decoded bytes aren't a valid Multihash.
    public init(multibase string: String) throws(MultihashError) {
        try self.init(Multihash.decodeMultibase(string))
    }

    /// Initializes a Multihash from a Multibase encoded *digest*, prefixing it appropriately.
    ///
    /// ```swift
    /// let digest = Array("multihash".utf8).sha1().asString(base: .base16, withMultibasePrefix: true)
    /// let mh = try Multihash(multibaseDigest: digest, code: .sha1)
    /// ```
    ///
    /// - Parameters:
    ///   - string: A Multibase encoded digest, including its base prefix.
    ///   - code: The codec of the hash function that produced the digest.
    /// - Throws:
    ///   - ``MultihashError/invalidMultibase(_:)`` if `string` isn't valid Multibase.
    ///   - Any other ``MultihashError`` if the decoded digest can't be prefixed with `code`.
    public init(multibaseDigest string: String, code: Codecs) throws(MultihashError) {
        try self.init(digest: Multihash.decodeMultibase(string), codec: code)
    }

    /// Decodes a Multibase string, reporting failures as ``MultihashError/invalidMultibase(_:)``.
    ///
    /// Multibase has its own typed error, so it gets folded into this module's error here rather
    /// than at each call site. That is what lets the Multibase initializers use typed throws.
    private static func decodeMultibase(_ string: String) throws(MultihashError) -> [UInt8] {
        do {
            return try string.multibase().bytes
        } catch {
            throw .invalidMultibase(error)
        }
    }

    /// The entire Multihash (prefixes included) as a string in the specified base.
    ///
    /// ```swift
    /// mh.asString(base: .base16)                             // "111488c2…"
    /// mh.asString(base: .base16, withMultibasePrefix: true)  // "f111488c2…"
    /// ```
    ///
    /// - Parameters:
    ///   - base: The base to encode into.
    ///   - withMultibasePrefix: Whether to include the Multibase prefix identifying `base`.
    public func asString(base: BaseEncoding, withMultibasePrefix prefix: Bool = false) -> String {
        self.value.asString(base: base, withMultibasePrefix: prefix)
    }

    /// The Multihash as a base58btc string, the form Multihashes are conventionally written in.
    ///
    /// ```swift
    /// print(mh)  // "QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk"
    /// ```
    ///
    /// - Note: This is the bare base58btc string, without the `z` Multibase prefix, matching how
    ///   PeerIDs and CIDv0s are written. Use `asString(base:withMultibasePrefix: true)` for a
    ///   Multibase compliant string.
    public var description: String {
        self.asString(base: .base58btc)
    }

    /// The Multihash's parts spelled out, for debugging.
    ///
    /// ```swift
    /// "Multihash: sha1 0x11 20 88c2f11fb2ce392acb5b2986e640211c4690073e"
    /// ```
    public var debugDescription: String {
        let name = self.hashName ?? "unknown"
        let code = String(self.code, radix: 16, uppercase: true)
        let digest = self.digest.asString(base: .base16)
        return "Multihash: \(name) 0x\(code) \(self.digestLength) \(digest)"
    }
}

// MARK: - Verification

extension Multihash {

    /// Whether hashing `bytes` with this Multihash's hash function reproduces this exact Multihash.
    ///
    /// Useful for checking that a payload matches a hash it was advertised under. The digest length
    /// is honoured, so a truncated Multihash compares against an equally truncated digest.
    ///
    /// - Returns: `false` if the bytes don't match, *and* `false` if this Multihash's hash function
    ///   can't be computed here. Use ``matching(_:)`` to tell those two apart.
    public func matches(_ bytes: some Collection<UInt8>) -> Bool {
        (try? self.matching(bytes)) ?? false
    }

    /// Whether hashing `bytes` with this Multihash's hash function reproduces this exact Multihash.
    ///
    /// - Throws:
    ///   - ``MultihashError/unsupportedHashFunction(_:)`` if this Multihash's hash function
    ///   isn't one this package can compute, so an unverifiable payload can be told apart from a
    ///   mismatched one.
    public func matching(_ bytes: some Collection<UInt8>) throws(MultihashError) -> Bool {
        guard let function = self.hashFunction else {
            throw MultihashError.unsupportedHashFunction(self.algorithm ?? .identity)
        }
        // Compare digests directly
        return function.hash(bytes).prefix(self.digestLength).elementsEqual(self.digest)
    }
}

// MARK: - Conformances

extension Multihash {
    /// Compares the raw Multihash buffers.
    ///
    /// Everything is derived from the digest, so just compare them.
    public static func == (lhs: Multihash, rhs: Multihash) -> Bool {
        lhs.value == rhs.value
    }

    /// Hashes the raw Multihash buffer. See ``==(_:_:)``.
    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.value)
    }
}

extension Multihash: RandomAccessCollection {
    public typealias Element = UInt8
    public typealias Index = Int

    /// - Warning: An index into the *entire* buffer, prefixes included, not into the digest.
    public var startIndex: Int { self.value.startIndex }

    /// - Warning: An index into the *entire* buffer, prefixes included, not into the digest.
    public var endIndex: Int { self.value.endIndex }

    public subscript(position: Int) -> UInt8 { self.value[position] }
}

extension Multihash: ContiguousBytes {
    /// Calls `body` with a contiguous view of the entire Multihash buffer, prefixes included.
    ///
    /// - Note: The pointer is only valid for the duration of the call.
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try self.value.withUnsafeBytes(body)
    }
}

extension Multihash: Codable {
    /// Decodes a Multihash from its raw Multihash byte buffer.
    ///
    /// Reads the `Data` form written by ``encode(to:)``, and falls back to the `[UInt8]` form
    /// written by 0.2.x so previously persisted values still decode.
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let data = try? container.decode(Data.self) {
            try self.init(data)
        } else {
            try self.init(try container.decode([UInt8].self))
        }
    }

    /// Encodes the Multihash as its raw Multihash byte buffer.
    ///
    /// Written as `Data`, which keeps binary coders compact and becomes a single base64 string in
    /// JSON rather than an array of integers.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(Data(self.value))
    }
}
