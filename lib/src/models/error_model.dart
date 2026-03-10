import '../constants.dart';

/// Represents an error returned from the native Secure Enclave layer.
///
/// [code] is the native error code (e.g., `OSStatus` values on iOS).
/// [desc] is a human-readable description of the error.
class ErrorModel {
  final int code;
  final String desc;

  ErrorModel(this.code, this.desc);

  factory ErrorModel.fromMap(Map<String, dynamic> map) {
    return ErrorModel(
      map[SecureEnclaveResultKey.code] as int,
      map[SecureEnclaveResultKey.desc] as String,
    );
  }
}
