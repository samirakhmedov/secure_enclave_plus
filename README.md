# secure_enclave_plus

A Flutter plugin for Apple's [Secure Enclave](https://support.apple.com/en-ie/guide/security/sec59b0b31ff/web) — a hardware-isolated coprocessor integrated into Apple SoCs that generates and stores cryptographic keys. Private keys created in the Secure Enclave never leave the hardware, even if the application processor is compromised.

This package supports iOS. On the iOS Simulator, keys are stored in the software Keychain instead of the Secure Enclave hardware (the simulator lacks a Secure Enclave).

## Acknowledgments

This package is a fork of [`secure_enclave`](https://pub.dev/packages/secure_enclave) originally created by **Angga Arya Saputra**. The original work provided the foundation for key generation, encryption, decryption, signing, and verification via Apple's Security framework. This fork refactors the codebase for type safety, documentation, and reduced dependencies.

## Features

| Operation | Description |
|---|---|
| `isKeyCreated` | Check whether a key pair exists for a given tag |
| `generateKeyPair` | Generate an EC P-256 key pair in the Secure Enclave |
| `getPublicKey` | Retrieve the Base64-encoded public key |
| `encrypt` | Encrypt a message using the stored key pair |
| `encryptWithPublicKey` | Encrypt a message using an external Base64-encoded public key |
| `decrypt` | Decrypt a previously encrypted message |
| `sign` | Create an ECDSA signature |
| `verify` | Verify an ECDSA signature |
| `removeKey` | Remove a key pair from the Secure Enclave |

### Access Control Flags

All flags from [`SecAccessControlCreateFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags) are supported:

- `devicePasscode` — Require device passcode
- `biometryAny` — Accept any enrolled biometric
- `biometryCurrentSet` — Accept only the currently enrolled biometric set
- `userPresence` — Require user presence (biometry or passcode)
- `watch` — Allow Apple Watch for authentication
- `privateKeyUsage` — Restrict access control to private key operations
- `applicationPassword` — Use a custom application-level password
- `or` — Combine flags with OR logic
- `and` — Combine flags with AND logic

### Algorithms

- **Encryption**: ECIES with cofactor Diffie-Hellman, variable IV, X9.63 KDF (SHA-256), and AES-GCM
- **Signing**: ECDSA over SHA-256 in X9.62 DER format

## Usage

### Check tag status

```dart
final secureEnclave = SecureEnclavePlus();
final result = await secureEnclave.isKeyCreated(tag: 'my_key');
print(result.value); // true or false
```

### Generate key pair

```dart
final secureEnclave = SecureEnclavePlus();

final result = await secureEnclave.generateKeyPair(
  accessControl: AccessControlModel(
    tag: 'my_key',
    options: [
      AccessControlOption.privateKeyUsage,
      AccessControlOption.biometryAny,
    ],
  ),
);

if (result.error != null) {
  print(result.error!.desc);
} else {
  print('Key pair generated: ${result.value}');
}
```

### Generate key pair with application password

```dart
final result = await secureEnclave.generateKeyPair(
  accessControl: AccessControlModel(
    tag: 'my_key',
    password: 'my_secret_password',
    options: [
      AccessControlOption.applicationPassword,
      AccessControlOption.privateKeyUsage,
    ],
  ),
);
```

### Get public key

```dart
final result = await secureEnclave.getPublicKey(tag: 'my_key');
print(result.value); // Base64-encoded public key
```

### Encrypt

```dart
final result = await secureEnclave.encrypt(
  message: 'Hello, Secure Enclave!',
  tag: 'my_key',
);

if (result.error == null) {
  final Uint8List encrypted = result.value!;
}
```

### Encrypt with external public key

```dart
final result = await secureEnclave.encryptWithPublicKey(
  message: 'Hello!',
  publicKey: 'Base64EncodedPublicKeyHere',
);
```

### Decrypt

```dart
final result = await secureEnclave.decrypt(
  message: encryptedBytes, // Uint8List
  tag: 'my_key',
);
print(result.value); // Decrypted string
```

### Sign

```dart
final result = await secureEnclave.sign(
  message: Uint8List.fromList('Hello'.codeUnits),
  tag: 'my_key',
);
print(result.value); // Base64-encoded signature
```

### Verify

```dart
final result = await secureEnclave.verify(
  plainText: 'Hello',
  signature: signatureString, // Base64-encoded
  tag: 'my_key',
);
print(result.value); // true or false
```

## License

BSD 3-Clause License. See [LICENSE](LICENSE) for details.
