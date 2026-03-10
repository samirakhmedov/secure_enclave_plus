import 'dart:typed_data';

import '../constants.dart';
import '../models/access_control_model.dart';

/// Message for [SecureEnclaveMethod.generateKeyPair].
class GenerateKeyPairMessage {
  final AccessControlModel accessControl;

  GenerateKeyPairMessage({required this.accessControl});

  Map<String, dynamic> encode() {
    return {
      SecureEnclaveArgKey.accessControl: accessControl.toMap(),
    };
  }
}

/// Message for [SecureEnclaveMethod.removeKey].
class TagMessage {
  final String tag;

  TagMessage({required this.tag});

  Map<String, dynamic> encode() {
    return {
      SecureEnclaveArgKey.tag: tag,
    };
  }
}

/// Message for methods that take a tag and optional password:
/// [SecureEnclaveMethod.isKeyCreated], [SecureEnclaveMethod.getPublicKey].
class TagWithPasswordMessage {
  final String tag;
  final String? password;

  TagWithPasswordMessage({required this.tag, this.password});

  Map<String, dynamic> encode() {
    return {
      SecureEnclaveArgKey.tag: tag,
      SecureEnclaveArgKey.password: password,
    };
  }
}

/// Message for [SecureEnclaveMethod.encrypt].
class EncryptMessage {
  final String message;
  final String tag;
  final String? password;

  EncryptMessage({
    required this.message,
    required this.tag,
    this.password,
  });

  Map<String, dynamic> encode() {
    return {
      SecureEnclaveArgKey.message: message,
      SecureEnclaveArgKey.tag: tag,
      SecureEnclaveArgKey.password: password,
    };
  }
}

/// Message for [SecureEnclaveMethod.encryptWithPublicKey].
class EncryptWithPublicKeyMessage {
  final String message;
  final String publicKey;

  EncryptWithPublicKeyMessage({
    required this.message,
    required this.publicKey,
  });

  Map<String, dynamic> encode() {
    return {
      SecureEnclaveArgKey.message: message,
      SecureEnclaveArgKey.publicKey: publicKey,
    };
  }
}

/// Message for [SecureEnclaveMethod.decrypt].
class DecryptMessage {
  final Uint8List message;
  final String tag;
  final String? password;

  DecryptMessage({
    required this.message,
    required this.tag,
    this.password,
  });

  Map<String, dynamic> encode() {
    return {
      SecureEnclaveArgKey.message: message,
      SecureEnclaveArgKey.tag: tag,
      SecureEnclaveArgKey.password: password,
    };
  }
}

/// Message for [SecureEnclaveMethod.sign].
class SignMessage {
  final Uint8List message;
  final String tag;
  final String? password;

  SignMessage({
    required this.message,
    required this.tag,
    this.password,
  });

  Map<String, dynamic> encode() {
    return {
      SecureEnclaveArgKey.message: message,
      SecureEnclaveArgKey.tag: tag,
      SecureEnclaveArgKey.password: password,
    };
  }
}

/// Message for [SecureEnclaveMethod.verify].
class VerifyMessage {
  final String plainText;
  final String signature;
  final String tag;
  final String? password;

  VerifyMessage({
    required this.plainText,
    required this.signature,
    required this.tag,
    this.password,
  });

  Map<String, dynamic> encode() {
    return {
      SecureEnclaveArgKey.plainText: plainText,
      SecureEnclaveArgKey.signature: signature,
      SecureEnclaveArgKey.tag: tag,
      SecureEnclaveArgKey.password: password,
    };
  }
}
