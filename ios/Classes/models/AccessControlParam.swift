// AccessControlParam.swift
// secure_enclave_plus
//
// Typed representation of access control configuration received from Dart.
// Converts the raw dictionary into strongly typed Swift properties.

import Foundation

/// Holds the parsed access control parameters for key pair generation.
///
/// Created from the dictionary sent over the method channel. The [option]
/// property is a bitmask of `SecAccessControlCreateFlags` built from the
/// string option names provided by the Dart layer.
@available(iOS 12.0, *)
class AccessControlParam {
    let password: String?
    let tag: String
    var option: SecAccessControlCreateFlags = []

    /// Creates an `AccessControlParam` from a method channel dictionary.
    ///
    /// - Throws: `SecureEnclaveError.invalidArgument` if required keys are
    ///   missing or have unexpected types.
    init(map: [String: Any]) throws {
        guard let tag = map[SecureEnclaveArgKey.tag] as? String else {
            throw SecureEnclaveError.invalidArgument("Missing or invalid 'tag' in accessControl")
        }
        guard let optionStrings = map[SecureEnclaveArgKey.options] as? [String] else {
            throw SecureEnclaveError.invalidArgument("Missing or invalid 'options' in accessControl")
        }

        self.tag = tag

        // Password may be nil or empty — both are treated as "no password".
        if let pwd = map[SecureEnclaveArgKey.password] as? String, !pwd.isEmpty {
            self.password = pwd
        } else {
            self.password = nil
        }

        buildOptions(from: optionStrings)
    }

    /// Maps Dart option name strings to native `SecAccessControlCreateFlags`.
    ///
    /// The string values must match the Dart `AccessControlOption` enum names.
    private func buildOptions(from optionStrings: [String]) {
        for opt in optionStrings {
            switch opt {
            case "devicePasscode":
                option.insert(.devicePasscode)
            case "biometryAny":
                option.insert(.biometryAny)
            case "biometryCurrentSet":
                option.insert(.biometryCurrentSet)
            case "userPresence":
                option.insert(.userPresence)
            case "privateKeyUsage":
                option.insert(.privateKeyUsage)
            case "applicationPassword":
                option.insert(.applicationPassword)
            case "or":
                option.insert(.or)
            case "and":
                option.insert(.and)
            default:
                break
            }
        }
    }
}
