import '../constants.dart';
import 'access_control_option.dart';

/// Configuration for key pair generation in the Secure Enclave.
///
/// [tag] is a unique identifier used to store and retrieve the key pair from
/// the Keychain. [options] defines the access control policy (biometry,
/// passcode, etc.). [password] is only required when using
/// [AccessControlOption.applicationPassword].
class AccessControlModel {
  final String? password;
  final List<AccessControlOption> options;
  final String tag;

  AccessControlModel({
    this.password,
    required this.tag,
    required this.options,
  });

  /// Serializes this model to a map for the platform channel.
  Map<String, dynamic> toMap() {
    return {
      SecureEnclaveArgKey.password: password,
      SecureEnclaveArgKey.options: options.map((o) => o.name).toList(),
      SecureEnclaveArgKey.tag: tag,
    };
  }
}
