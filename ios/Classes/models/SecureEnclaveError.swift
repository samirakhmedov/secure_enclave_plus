// SecureEnclaveError.swift
// secure_enclave_plus
//
// Structured error type for all Secure Enclave operations.
// Replaces the legacy `CustomError` with specific, meaningful error cases.

import Foundation

/// Errors that can occur during Secure Enclave operations.
enum SecureEnclaveError: LocalizedError {
    /// The tag string could not be converted to UTF-8 data.
    case invalidTag

    /// No key was found in the Keychain for the requested tag.
    case keyNotFound

    /// The public key could not be extracted from the private key reference.
    case publicKeyUnavailable

    /// The Keychain item was not a `SecKey` as expected.
    case unexpectedKeyType

    /// The provided Base64 public key data could not be used to construct a `SecKey`.
    case invalidPublicKey

    /// The encryption algorithm is not supported by this key.
    case algorithmNotSupported

    /// Encryption failed after the algorithm check passed.
    case encryptionFailed

    /// Decryption failed after the algorithm check passed.
    case decryptionFailed

    /// Signature creation failed.
    case signingFailed

    /// An invalid or missing argument was received from the Dart layer.
    case invalidArgument(String)

    /// A catch-all for errors that don't fit other cases.
    case runtime(String)

    var errorDescription: String? {
        switch self {
        case .invalidTag:
            return "Invalid tag: could not encode tag as UTF-8 data."
        case .keyNotFound:
            return "No key found in the Keychain for the given tag."
        case .publicKeyUnavailable:
            return "Could not extract the public key from the stored private key."
        case .unexpectedKeyType:
            return "Keychain item is not a SecKey."
        case .invalidPublicKey:
            return "The provided public key data is invalid or cannot be used."
        case .algorithmNotSupported:
            return "The requested algorithm is not supported by this key."
        case .encryptionFailed:
            return "Encryption failed."
        case .decryptionFailed:
            return "Decryption failed."
        case .signingFailed:
            return "Signature creation failed."
        case .invalidArgument(let detail):
            return "Invalid argument: \(detail)"
        case .runtime(let detail):
            return detail
        }
    }
}
