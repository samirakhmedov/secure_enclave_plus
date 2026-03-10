/// Constants for the platform channel contract between Dart and Swift.
///
/// These values must exactly match the corresponding constants defined in
/// `Messages.swift` on the native side. Changing a value here without updating
/// the Swift counterpart will silently break the method channel.
abstract final class SecureEnclaveChannel {
  static const String name = 'secure_enclave_plus';
}

/// Method names invoked over the platform channel.
abstract final class SecureEnclaveMethod {
  static const String generateKeyPair = 'generateKeyPair';
  static const String removeKey = 'removeKey';
  static const String isKeyCreated = 'isKeyCreated';
  static const String getPublicKey = 'getPublicKey';
  static const String encrypt = 'encrypt';
  static const String encryptWithPublicKey = 'encryptWithPublicKey';
  static const String decrypt = 'decrypt';
  static const String sign = 'sign';
  static const String verify = 'verify';
}

/// Argument keys used in method channel call payloads.
abstract final class SecureEnclaveArgKey {
  static const String tag = 'tag';
  static const String password = 'password';
  static const String message = 'message';
  static const String publicKey = 'publicKey';
  static const String plainText = 'plainText';
  static const String signature = 'signature';
  static const String accessControl = 'accessControl';
  static const String options = 'options';
}

/// Keys used in the result map returned from the native side.
abstract final class SecureEnclaveResultKey {
  static const String error = 'error';
  static const String data = 'data';
  static const String code = 'code';
  static const String desc = 'desc';
}
