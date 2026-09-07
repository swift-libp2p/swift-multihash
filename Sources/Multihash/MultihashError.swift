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

public enum MultihashError: Error {
    case unknownCode
    case hashTooShort
    case hashTooLong
    case VarIntBufferTooShort
    case VarIntTooLarge
    case lengthNotSupported
    case hexConversionFail
    case inconsistentLength(Int)
}

extension MultihashError {
    var description: String {
        get {
            switch self {
            case .unknownCode:
                return "Unknown multihash code."
            case .hashTooShort:
                return "Multihash too short. Must be at least 2 bytes"
            case .hashTooLong:
                return "Multihash too long. Digest length exceeds Int32.max"
            case .VarIntBufferTooShort:
                return "Unsigned Variable Integer buffer too short."
            case .VarIntTooLarge:
                return "Unsigned Variable int is too big. Max is 64 bits."
            case .lengthNotSupported:
                return "Multihash digest length is too large to encode"
            case .hexConversionFail:
                return "Error occurred in hex conversion."
            case .inconsistentLength(let len):
                return "Multihash length inconsistent. \(len)"
            }
        }
    }
}
