// Messages.swift
// secure_enclave_plus
//
// Platform channel contract constants and codec helpers.
// These values must exactly match the Dart constants in `constants.dart`.
// Changing a value here without updating the Dart counterpart will silently
// break the method channel.

import Flutter
import Foundation

// MARK: - Channel

enum SecureEnclaveChannel {
    static let name = "secure_enclave_plus"
}

// MARK: - Method Names

enum SecureEnclaveMethod {
    static let generateKeyPair = "generateKeyPair"
    static let removeKey = "removeKey"
    static let isKeyCreated = "isKeyCreated"
    static let getPublicKey = "getPublicKey"
    static let encrypt = "encrypt"
    static let encryptWithPublicKey = "encryptWithPublicKey"
    static let decrypt = "decrypt"
    static let sign = "sign"
    static let verify = "verify"
}

// MARK: - Argument Keys

enum SecureEnclaveArgKey {
    static let tag = "tag"
    static let password = "password"
    static let message = "message"
    static let publicKey = "publicKey"
    static let plainText = "plainText"
    static let signature = "signature"
    static let accessControl = "accessControl"
    static let options = "options"
}

// MARK: - Result Keys

enum SecureEnclaveResultKey {
    static let error = "error"
    static let data = "data"
    static let code = "code"
    static let desc = "desc"
}

// MARK: - Codec

/// Helpers for encoding native results into the map format expected by Dart.
enum SecureEnclaveCodec {
    /// Encodes a successful result.
    static func success(data: Any?) -> [String: Any?] {
        return [
            SecureEnclaveResultKey.error: nil,
            SecureEnclaveResultKey.data: data,
        ]
    }

    /// Encodes an error result from a Swift `Error`.
    static func error(from error: Error) -> [String: Any?] {
        let code: Int
        if error is SecureEnclaveError {
            code = 0
        } else {
            code = (error as NSError).code
        }
        return [
            SecureEnclaveResultKey.error: [
                SecureEnclaveResultKey.code: NSNumber(value: code),
                SecureEnclaveResultKey.desc: error.localizedDescription,
            ],
            SecureEnclaveResultKey.data: nil,
        ]
    }

    /// Extracts the tag string from method call arguments.
    static func tag(from args: [String: Any]) throws -> String {
        guard let tag = args[SecureEnclaveArgKey.tag] as? String else {
            throw SecureEnclaveError.invalidArgument("Missing or invalid 'tag'")
        }
        return tag
    }

    /// Extracts the optional password from method call arguments.
    /// Returns `nil` for both missing values and empty strings.
    static func password(from args: [String: Any]) -> String? {
        guard let pwd = args[SecureEnclaveArgKey.password] as? String,
              !pwd.isEmpty
        else {
            return nil
        }
        return pwd
    }
}
