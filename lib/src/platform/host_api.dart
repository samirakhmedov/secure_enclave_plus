import 'package:flutter/services.dart';

import '../constants.dart';
import '../models/access_control_model.dart';
import '../models/result_model.dart';
import 'messages.dart';

/// Abstract contract for the Secure Enclave host API.
///
/// This defines the typed interface that the native platform must implement.
/// All methods return a [ResultModel] that wraps either a success value or
/// an [ErrorModel].
abstract class SecureEnclavePlusHostApi {
  Future<ResultModel<bool>> generateKeyPair({
    required AccessControlModel accessControl,
  });

  Future<ResultModel<bool>> removeKey(String tag);

  Future<ResultModel<bool?>> isKeyCreated({
    required String tag,
    String? password,
  });

  Future<ResultModel<String?>> getPublicKey({
    required String tag,
    String? password,
  });

  Future<ResultModel<Uint8List?>> encrypt({
    required String message,
    required String tag,
    String? password,
  });

  Future<ResultModel<Uint8List?>> encryptWithPublicKey({
    required String message,
    required String publicKey,
  });

  Future<ResultModel<String?>> decrypt({
    required Uint8List message,
    required String tag,
    String? password,
  });

  Future<ResultModel<String?>> sign({
    required Uint8List message,
    required String tag,
    String? password,
  });

  Future<ResultModel<bool?>> verify({
    required String plainText,
    required String signature,
    required String tag,
    String? password,
  });
}

/// MethodChannel-based implementation of [SecureEnclavePlusHostApi].
///
/// Communicates with the native Swift layer over a [MethodChannel] using
/// typed [messages] and [constants] — no raw strings appear in the
/// invocation logic.
class SecureEnclavePlusHostApiImpl implements SecureEnclavePlusHostApi {
  final MethodChannel _channel;

  SecureEnclavePlusHostApiImpl({MethodChannel? channel})
      : _channel = channel ?? const MethodChannel(SecureEnclaveChannel.name);

  /// Invokes a method channel call and decodes the result map.
  Future<ResultModel<T>> _invoke<T>({
    required String method,
    required Map<String, dynamic> arguments,
    required T Function(dynamic) decoder,
  }) async {
    final result = await _channel.invokeMethod<dynamic>(method, arguments);
    return ResultModel.fromMap(
      map: Map<String, dynamic>.from(result),
      decoder: decoder,
    );
  }

  @override
  Future<ResultModel<bool>> generateKeyPair({
    required AccessControlModel accessControl,
  }) {
    return _invoke(
      method: SecureEnclaveMethod.generateKeyPair,
      arguments: GenerateKeyPairMessage(accessControl: accessControl).encode(),
      decoder: (raw) => raw as bool? ?? false,
    );
  }

  @override
  Future<ResultModel<bool>> removeKey(String tag) {
    return _invoke(
      method: SecureEnclaveMethod.removeKey,
      arguments: TagMessage(tag: tag).encode(),
      decoder: (raw) => raw as bool? ?? false,
    );
  }

  @override
  Future<ResultModel<bool?>> isKeyCreated({
    required String tag,
    String? password,
  }) {
    return _invoke(
      method: SecureEnclaveMethod.isKeyCreated,
      arguments: TagWithPasswordMessage(tag: tag, password: password).encode(),
      decoder: (raw) => raw as bool?,
    );
  }

  @override
  Future<ResultModel<String?>> getPublicKey({
    required String tag,
    String? password,
  }) {
    return _invoke(
      method: SecureEnclaveMethod.getPublicKey,
      arguments: TagWithPasswordMessage(tag: tag, password: password).encode(),
      decoder: (raw) => raw as String?,
    );
  }

  @override
  Future<ResultModel<Uint8List?>> encrypt({
    required String message,
    required String tag,
    String? password,
  }) {
    return _invoke(
      method: SecureEnclaveMethod.encrypt,
      arguments: EncryptMessage(message: message, tag: tag, password: password)
          .encode(),
      decoder: (raw) => raw as Uint8List?,
    );
  }

  @override
  Future<ResultModel<Uint8List?>> encryptWithPublicKey({
    required String message,
    required String publicKey,
  }) {
    return _invoke(
      method: SecureEnclaveMethod.encryptWithPublicKey,
      arguments: EncryptWithPublicKeyMessage(
        message: message,
        publicKey: publicKey,
      ).encode(),
      decoder: (raw) => raw as Uint8List?,
    );
  }

  @override
  Future<ResultModel<String?>> decrypt({
    required Uint8List message,
    required String tag,
    String? password,
  }) {
    return _invoke(
      method: SecureEnclaveMethod.decrypt,
      arguments: DecryptMessage(message: message, tag: tag, password: password)
          .encode(),
      decoder: (raw) => raw as String?,
    );
  }

  @override
  Future<ResultModel<String?>> sign({
    required Uint8List message,
    required String tag,
    String? password,
  }) {
    return _invoke(
      method: SecureEnclaveMethod.sign,
      arguments:
          SignMessage(message: message, tag: tag, password: password).encode(),
      decoder: (raw) => raw as String?,
    );
  }

  @override
  Future<ResultModel<bool?>> verify({
    required String plainText,
    required String signature,
    required String tag,
    String? password,
  }) {
    return _invoke(
      method: SecureEnclaveMethod.verify,
      arguments: VerifyMessage(
        plainText: plainText,
        signature: signature,
        tag: tag,
        password: password,
      ).encode(),
      decoder: (raw) => raw as bool?,
    );
  }
}
