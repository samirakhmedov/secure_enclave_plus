import '../constants.dart';
import 'error_model.dart';

/// Generic result wrapper for all Secure Enclave operations.
///
/// Every method returns a [ResultModel] that contains either an [error] or
/// a typed [value] decoded from the raw platform channel response.
class ResultModel<T> {
  final ErrorModel? error;
  final dynamic _rawData;
  final T Function(dynamic rawData) decoder;

  ResultModel(this.error, this._rawData, this.decoder);

  factory ResultModel.fromMap({
    required Map<String, dynamic>? map,
    required T Function(dynamic rawData) decoder,
  }) {
    final rawError = map?[SecureEnclaveResultKey.error];
    return ResultModel(
      rawError == null
          ? null
          : ErrorModel.fromMap(Map<String, dynamic>.from(rawError)),
      map?[SecureEnclaveResultKey.data],
      decoder,
    );
  }

  /// The decoded result value. Access this only when [error] is `null`.
  T get value => decoder(_rawData);
}
