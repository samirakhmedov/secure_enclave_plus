## 1.0.0

- Fork of `secure_enclave` by Angga Arya Saputra — full refactor
- Rename package to `secure_enclave_plus`
- Remove `json_serializable`, `build_runner`, `json_annotation`, `convert` dependencies
- Remove `plugin_platform_interface` dependency
- Replace raw string method channels with strongly typed constants
- Add typed message classes for all platform channel calls
- Fix force unwraps in Swift (use `guard let` throughout)
- Fix `isKeyCreated` swallowing all errors (now only returns `false` for missing keys)
- Replace `CustomError` with structured `SecureEnclaveError` enum
- Add documentation explaining Secure Enclave internals, algorithms, and keychain queries
- Remove debug `print()` statements
- Fix `null` vs empty string password handling
- Remove unused `Base.swift` protocol and `AccessControlFactory.swift`
- Remove macOS platform declaration (no native implementation exists)
- Format all Dart and Swift code
- Bump minimum iOS to 12.0, Dart SDK to >=3.0.0

## 0.1.2

- Forked from secure_enclave by Angga Arya Saputra

## 0.1.1

*07-09-2022*
- bug fix

## 0.1.0

*02-09-2022*
- refactor package
- add sign & verify
- add more flags
- add documentation
- update readme

## 0.0.3+rev1

*19-08-2022*
- update readme

## 0.0.3

*19-08-2022*
- simplify encrypt and decrypt method
- add appPassword option

## 0.0.2+rev1

*05-07-2022*
- separate encryptWithPublicKey and encrypt function

## 0.0.2

*05-07-2022*
- refactor input parameter
- macOS partial support
- customisable SecAccessControlCreateFlags

## 0.0.1

*24-06-2022*
- init
- encryption
- decryption
