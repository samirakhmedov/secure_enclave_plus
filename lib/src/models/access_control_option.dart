/// Flags that control access requirements for Secure Enclave key operations.
///
/// These map directly to Apple's `SecAccessControlCreateFlags`. Multiple flags
/// can be combined using [AccessControlOption.or] and [AccessControlOption.and]
/// to create compound access policies.
///
/// See: https://developer.apple.com/documentation/security/secaccesscontrolcreateflags
enum AccessControlOption {
  /// Require the device passcode for key access.
  devicePasscode,

  /// Accept any enrolled biometric (Touch ID or Face ID), including
  /// biometrics enrolled after key creation.
  biometryAny,

  /// Accept only the biometric set that was enrolled at the time of key
  /// creation. If biometrics change, the key becomes inaccessible.
  biometryCurrentSet,

  /// Require user presence via biometry or passcode.
  userPresence,

  /// Allow a paired Apple Watch to satisfy the access requirement.
  watch,

  /// Restrict the access control to private key usage operations only.
  privateKeyUsage,

  /// Use a custom application-level password (set via `LAContext`) as an
  /// additional credential for key access.
  applicationPassword,

  /// Combine the preceding flags with OR logic (any one flag suffices).
  or,

  /// Combine the preceding flags with AND logic (all flags must be met).
  and,
}
