library secure_enclave_plus;

import 'dart:typed_data';

import 'src/models/access_control_model.dart';
import 'src/models/result_model.dart';
import 'src/platform/host_api.dart';

export 'src/models/access_control_model.dart';
export 'src/models/access_control_option.dart';
export 'src/models/error_model.dart';
export 'src/models/result_model.dart';

/// Flutter interface to Apple's Secure Enclave.
///
/// Provides key generation, encryption, decryption, signing, and verification
/// using elliptic-curve keys stored in the device's Secure Enclave hardware
/// (or in the software Keychain on the iOS Simulator).
///
/// All operations return a [ResultModel] that contains either a typed value
/// or an [ErrorModel] describing the failure.
class SecureEnclavePlus {
  final SecureEnclavePlusHostApi _api;

  SecureEnclavePlus({SecureEnclavePlusHostApi? api})
      : _api = api ?? SecureEnclavePlusHostApiImpl();

  /// Generates a new EC P-256 key pair in the Secure Enclave.
  ///
  /// The key is stored permanently in the Keychain under the tag specified in
  /// [accessControl]. Access to the key is governed by the flags in
  /// [AccessControlModel.options].
  Future<ResultModel<bool>> generateKeyPair({
    required AccessControlModel accessControl,
  }) {
    return _api.generateKeyPair(accessControl: accessControl);
  }

  /// Removes the key pair identified by [tag] from the Keychain.
  Future<ResultModel<bool>> removeKey(String tag) {
    return _api.removeKey(tag);
  }

  /// Checks whether a key pair exists for the given [tag].
  Future<ResultModel<bool?>> isKeyCreated({
    required String tag,
    String? password,
  }) {
    return _api.isKeyCreated(tag: tag, password: password);
  }

  /// Retrieves the Base64-encoded public key for the given [tag].
  ///
  /// The returned public key can be shared with other parties so they can
  /// encrypt data that only this device's Secure Enclave can decrypt.
  Future<ResultModel<String?>> getPublicKey({
    required String tag,
    String? password,
  }) {
    return _api.getPublicKey(tag: tag, password: password);
  }

  /// Encrypts [message] using the public key of the key pair stored under
  /// [tag].
  ///
  /// Uses ECIES with cofactor DH, X9.63 KDF (SHA-256), and AES-GCM.
  Future<ResultModel<Uint8List?>> encrypt({
    required String message,
    required String tag,
    String? password,
  }) {
    return _api.encrypt(message: message, tag: tag, password: password);
  }

  /// Encrypts [message] using an external Base64-encoded [publicKey].
  ///
  /// This allows encryption without access to the private key — useful for
  /// encrypting data intended for another device's Secure Enclave.
  Future<ResultModel<Uint8List?>> encryptWithPublicKey({
    required String message,
    required String publicKey,
  }) {
    return _api.encryptWithPublicKey(message: message, publicKey: publicKey);
  }

  /// Decrypts [message] using the private key stored under [tag].
  Future<ResultModel<String?>> decrypt({
    required Uint8List message,
    required String tag,
    String? password,
  }) {
    return _api.decrypt(message: message, tag: tag, password: password);
  }

  /// Creates an ECDSA signature of [message] using the private key stored
  /// under [tag].
  ///
  /// Returns the signature as a Base64-encoded string.
  Future<ResultModel<String?>> sign({
    required Uint8List message,
    required String tag,
    String? password,
  }) {
    return _api.sign(message: message, tag: tag, password: password);
  }

  /// Verifies that [signature] is a valid ECDSA signature of [plainText]
  /// produced by the key pair stored under [tag].
  Future<ResultModel<bool?>> verify({
    required String plainText,
    required String signature,
    required String tag,
    String? password,
  }) {
    return _api.verify(
      plainText: plainText,
      signature: signature,
      tag: tag,
      password: password,
    );
  }
}

/// Migration convenience alias for the renamed class.
typedef SecureEnclave = SecureEnclavePlus;
