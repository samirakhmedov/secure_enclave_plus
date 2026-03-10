// SecureEnclaveCore.swift
// secure_enclave_plus
//
// Originally created by Angga Arya Saputra on 18/08/22.
// Refactored by Samir Akhmedov — 2025.
//
// Core cryptographic operations backed by Apple's Secure Enclave.
//
// ## What is the Secure Enclave?
//
// The Secure Enclave is a hardware-isolated coprocessor embedded in Apple SoCs
// (A7 and later, M1 and later). It has its own boot ROM, AES engine, and
// protected memory. Private keys generated inside the Secure Enclave **never
// leave the hardware** — all cryptographic operations (signing, decryption)
// happen inside the coprocessor. The host CPU only ever receives results, not
// key material.
//
// On the iOS Simulator there is no Secure Enclave hardware, so this code falls
// back to the software Keychain (`kSecAttrTokenIDSecureEnclave` is omitted).
// Keys created on the simulator are functionally equivalent but lack the
// hardware isolation guarantee.
//
// ## Key type
//
// The Secure Enclave only supports **P-256 (secp256r1)** elliptic curve keys.
// This is a hardware constraint — no other key type or size is available.
//
// ## Algorithms
//
// - **Encryption / Decryption**:
//   `eciesEncryptionCofactorVariableIVX963SHA256AESGCM`
//   This is ECIES (Elliptic Curve Integrated Encryption Scheme) using:
//     - Cofactor Diffie-Hellman for key agreement
//     - Variable-length IV (initialization vector)
//     - X9.63 KDF with SHA-256 for key derivation
//     - AES-GCM for authenticated symmetric encryption
//   Apple recommends this algorithm for Secure Enclave–backed encryption.
//
// - **Signing / Verification**:
//   `ecdsaSignatureMessageX962SHA256`
//   This is ECDSA (Elliptic Curve Digital Signature Algorithm) using:
//     - SHA-256 hash of the message
//     - X9.62 DER-encoded signature format
//   This is the standard signing algorithm for P-256 keys.

import Flutter
import Foundation
import LocalAuthentication

/// Protocol defining the Secure Enclave operations.
@available(iOS 12.0, *)
protocol SecureEnclaveCoreProtocol {
    func generateKeyPair(accessControl: AccessControlParam) throws -> SecKey
    func removeKey(tag: String) throws -> Bool
    func isKeyCreated(tag: String, password: String?) throws -> Bool
    func getPublicKey(tag: String, password: String?) throws -> String
    func encrypt(message: String, tag: String, password: String?) throws -> FlutterStandardTypedData
    func encryptWithPublicKey(message: String, publicKey: String) throws -> FlutterStandardTypedData
    func decrypt(message: Data, tag: String, password: String?) throws -> String
    func sign(tag: String, password: String?, message: Data) throws -> String
    func verify(tag: String, password: String?, plainText: String, signature: String) throws -> Bool
}

@available(iOS 12.0, *)
class SecureEnclaveCore: SecureEnclaveCoreProtocol {

    // MARK: - Encryption Algorithm

    /// ECIES with cofactor DH, variable IV, X9.63 KDF (SHA-256), AES-GCM.
    /// This is the recommended algorithm for Secure Enclave–backed encryption.
    private let encryptionAlgorithm: SecKeyAlgorithm =
        .eciesEncryptionCofactorVariableIVX963SHA256AESGCM

    /// ECDSA with SHA-256 in X9.62 DER format.
    private let signingAlgorithm: SecKeyAlgorithm =
        .ecdsaSignatureMessageX962SHA256

    // MARK: - Key Generation

    /// Generates an EC P-256 key pair and stores it in the Keychain.
    ///
    /// On a physical device the private key is created inside the Secure Enclave
    /// (`kSecAttrTokenIDSecureEnclave`). On the simulator this attribute is
    /// omitted, so the key lives in the software Keychain instead.
    ///
    /// The key is stored permanently (`kSecAttrIsPermanent`) under the
    /// application tag from [accessControl]. Access is governed by the
    /// `SecAccessControlCreateFlags` built from the Dart-side options.
    ///
    /// If [AccessControlOption.applicationPassword] is included, an `LAContext`
    /// is configured with the custom password as an additional credential.
    func generateKeyPair(accessControl: AccessControlParam) throws -> SecKey {
        guard let tagData = accessControl.tag.data(using: .utf8) else {
            throw SecureEnclaveError.invalidTag
        }

        // Build the access control object with the requested flags.
        var accessError: Unmanaged<CFError>?
        guard let secAccessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            // Keys are only accessible when the device is unlocked and are not
            // synced to other devices via iCloud Keychain.
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            accessControl.option,
            &accessError
        ) else {
            throw accessError!.takeRetainedValue() as Error
        }

        // Base key generation parameters — P-256 is the only curve supported
        // by the Secure Enclave hardware.
        var params: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tagData,
                kSecAttrAccessControl as String: secAccessControl,
            ],
        ]

        // On physical devices, require the Secure Enclave hardware.
        // On the simulator, omit this attribute to use the software Keychain.
        #if !targetEnvironment(simulator)
        params[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        #endif

        // If applicationPassword is requested, attach an LAContext with the
        // custom credential so the system uses it instead of showing a
        // biometric prompt for this specific operation.
        if accessControl.option.contains(.applicationPassword) {
            let context = LAContext()
            let passwordData = accessControl.password?.data(using: .utf8)
            context.setCredential(passwordData, type: .applicationPassword)
            params[kSecUseAuthenticationContext as String] = context
        }

        var createError: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateRandomKey(params as CFDictionary, &createError) else {
            throw createError!.takeRetainedValue() as Error
        }

        return secKey
    }

    // MARK: - Key Removal

    /// Removes the key pair identified by [tag] from the Keychain.
    ///
    /// Returns `true` if the key was deleted, `false` if it was not found.
    /// Throws for any other Keychain error (e.g., permission issues).
    func removeKey(tag: String) throws -> Bool {
        guard let tagData = tag.data(using: .utf8) else {
            throw SecureEnclaveError.invalidTag
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData,
        ]

        let status = SecItemDelete(query as CFDictionary)

        if status == errSecSuccess {
            return true
        } else if status == errSecNotAvailable || status == errSecItemNotFound {
            return false
        } else {
            throw NSError(
                domain: NSOSStatusErrorDomain,
                code: Int(status),
                userInfo: [
                    NSLocalizedDescriptionKey:
                        SecCopyErrorMessageString(status, nil) ?? "Undefined Keychain error"
                        as Any
                ]
            )
        }
    }

    // MARK: - Key Retrieval

    /// Retrieves the private key reference from the Keychain.
    ///
    /// This builds a Keychain query that:
    /// - Filters by `kSecClassKey` (cryptographic keys only)
    /// - Matches the application tag
    /// - Filters by EC key type
    /// - Returns at most one match (`kSecMatchLimitOne`)
    /// - Returns a `SecKey` reference (`kSecReturnRef`)
    ///
    /// If an application password was set during key generation, the same
    /// password must be provided here via an `LAContext`.
    ///
    /// Returns `nil` if the key does not exist (`errSecItemNotFound`).
    /// Throws for any other Keychain error.
    internal func getSecKey(tag: String, password: String?) throws -> SecKey? {
        guard let tagData = tag.data(using: .utf8) else {
            throw SecureEnclaveError.invalidTag
        }

        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnRef as String: true,
        ]

        if let password = password {
            let context = LAContext()
            let passwordData = password.data(using: .utf8)
            context.setCredential(passwordData, type: .applicationPassword)
            query[kSecUseAuthenticationContext as String] = context
        }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        if status == errSecItemNotFound {
            return nil
        }

        guard status == errSecSuccess else {
            throw NSError(
                domain: NSOSStatusErrorDomain,
                code: Int(status),
                userInfo: [
                    NSLocalizedDescriptionKey:
                        SecCopyErrorMessageString(status, nil) ?? "Undefined Keychain error"
                        as Any
                ]
            )
        }

        // After errSecSuccess with kSecReturnRef, the item is always a SecKey.
        return (item as! SecKey)
    }

    // MARK: - Key Status

    /// Checks whether a key pair exists for the given [tag].
    ///
    /// Returns `false` only when the key genuinely does not exist
    /// (`errSecItemNotFound`). All other errors are propagated to the caller
    /// so that issues like wrong passwords or Keychain corruption are not
    /// silently swallowed.
    func isKeyCreated(tag: String, password: String?) throws -> Bool {
        do {
            let key = try getSecKey(tag: tag, password: password)
            return key != nil
        } catch let error as NSError where error.code == Int(errSecItemNotFound) {
            return false
        }
    }

    // MARK: - Public Key

    /// Retrieves the Base64-encoded public key for the given [tag].
    ///
    /// Extracts the public key from the stored private key reference using
    /// `SecKeyCopyPublicKey`, then serializes it with
    /// `SecKeyCopyExternalRepresentation`.
    func getPublicKey(tag: String, password: String?) throws -> String {
        guard let secKey = try getSecKey(tag: tag, password: password) else {
            throw SecureEnclaveError.keyNotFound
        }

        guard let publicKey = SecKeyCopyPublicKey(secKey) else {
            throw SecureEnclaveError.publicKeyUnavailable
        }

        var error: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw error?.takeRetainedValue() ?? SecureEnclaveError.publicKeyUnavailable
        }

        return keyData.base64EncodedString()
    }

    // MARK: - Encryption

    /// Encrypts [message] using the public key of the key pair stored under [tag].
    ///
    /// The message is converted to UTF-8 data, then encrypted with ECIES using
    /// the Secure Enclave–backed public key.
    func encrypt(message: String, tag: String, password: String?) throws -> FlutterStandardTypedData {
        guard let secKey = try getSecKey(tag: tag, password: password) else {
            throw SecureEnclaveError.keyNotFound
        }

        guard let publicKey = SecKeyCopyPublicKey(secKey) else {
            throw SecureEnclaveError.publicKeyUnavailable
        }

        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, encryptionAlgorithm) else {
            throw SecureEnclaveError.algorithmNotSupported
        }

        guard let clearTextData = message.data(using: .utf8) else {
            throw SecureEnclaveError.runtime("Could not encode message as UTF-8")
        }

        var error: Unmanaged<CFError>?
        guard let cipherTextData = SecKeyCreateEncryptedData(
            publicKey, encryptionAlgorithm, clearTextData as CFData, &error
        ) as Data? else {
            if let err = error { throw err.takeRetainedValue() as Error }
            throw SecureEnclaveError.encryptionFailed
        }

        return FlutterStandardTypedData(bytes: cipherTextData)
    }

    /// Encrypts [message] using an external Base64-encoded public key.
    ///
    /// This allows encrypting data intended for another device's Secure Enclave
    /// without needing access to the private key.
    func encryptWithPublicKey(message: String, publicKey: String) throws -> FlutterStandardTypedData {
        guard let publicKeyData = Data(base64Encoded: publicKey, options: []) else {
            throw SecureEnclaveError.invalidPublicKey
        }

        let publicKeyParams: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256,
        ]

        guard let secPublicKey = SecKeyCreateWithData(
            publicKeyData as CFData, publicKeyParams as CFDictionary, nil
        ) else {
            throw SecureEnclaveError.invalidPublicKey
        }

        guard SecKeyIsAlgorithmSupported(secPublicKey, .encrypt, encryptionAlgorithm) else {
            throw SecureEnclaveError.algorithmNotSupported
        }

        guard let clearTextData = message.data(using: .utf8) else {
            throw SecureEnclaveError.runtime("Could not encode message as UTF-8")
        }

        var error: Unmanaged<CFError>?
        guard let cipherTextData = SecKeyCreateEncryptedData(
            secPublicKey, encryptionAlgorithm, clearTextData as CFData, &error
        ) as Data? else {
            if let err = error { throw err.takeRetainedValue() as Error }
            throw SecureEnclaveError.encryptionFailed
        }

        return FlutterStandardTypedData(bytes: cipherTextData)
    }

    // MARK: - Decryption

    /// Decrypts [message] using the private key stored under [tag].
    ///
    /// The private key never leaves the Secure Enclave — decryption happens
    /// inside the coprocessor. Only the resulting plaintext is returned.
    func decrypt(message: Data, tag: String, password: String?) throws -> String {
        guard let secKey = try getSecKey(tag: tag, password: password) else {
            throw SecureEnclaveError.keyNotFound
        }

        guard SecKeyIsAlgorithmSupported(secKey, .decrypt, encryptionAlgorithm) else {
            throw SecureEnclaveError.algorithmNotSupported
        }

        var error: Unmanaged<CFError>?
        guard let plainTextData = SecKeyCreateDecryptedData(
            secKey, encryptionAlgorithm, message as CFData, &error
        ) as Data? else {
            if let err = error { throw err.takeRetainedValue() as Error }
            throw SecureEnclaveError.decryptionFailed
        }

        return String(decoding: plainTextData, as: UTF8.self)
    }

    // MARK: - Signing

    /// Creates an ECDSA signature of [message] using the private key stored
    /// under [tag].
    ///
    /// The signing happens inside the Secure Enclave — the private key never
    /// leaves the hardware. Returns the signature as a Base64-encoded string
    /// in X9.62 DER format.
    func sign(tag: String, password: String?, message: Data) throws -> String {
        guard let secKey = try getSecKey(tag: tag, password: password) else {
            throw SecureEnclaveError.keyNotFound
        }

        var error: Unmanaged<CFError>?
        guard let signatureData = SecKeyCreateSignature(
            secKey, signingAlgorithm, message as CFData, &error
        ) else {
            if let err = error { throw err.takeRetainedValue() as Error }
            throw SecureEnclaveError.signingFailed
        }

        return (signatureData as Data).base64EncodedString(options: [])
    }

    // MARK: - Verification

    /// Verifies that [signature] is a valid ECDSA signature of [plainText]
    /// produced by the key pair stored under [tag].
    ///
    /// The public key is extracted from the stored key pair and used for
    /// verification. Returns `false` if the signature is invalid or if the
    /// Base64 data cannot be decoded.
    func verify(
        tag: String, password: String?, plainText: String, signature: String
    ) throws -> Bool {
        guard Data(base64Encoded: signature) != nil else {
            return false
        }

        let publicKeyB64 = try getPublicKey(tag: tag, password: password)

        guard let publicKeyData = Data(base64Encoded: publicKeyB64, options: []) else {
            throw SecureEnclaveError.invalidPublicKey
        }

        let publicKeyParams: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256,
        ]

        guard let secPublicKey = SecKeyCreateWithData(
            publicKeyData as CFData, publicKeyParams as CFDictionary, nil
        ) else {
            return false
        }

        guard let messageData = plainText.data(using: .utf8) else {
            return false
        }

        guard let signatureData = Data(base64Encoded: signature, options: []) else {
            return false
        }

        return SecKeyVerifySignature(
            secPublicKey, signingAlgorithm,
            messageData as CFData, signatureData as CFData, nil
        )
    }
}
