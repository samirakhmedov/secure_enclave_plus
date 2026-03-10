// SecureEnclavePlusPlugin.swift
// secure_enclave_plus
//
// Flutter plugin entry point. Dispatches method channel calls to
// SecureEnclaveCore and encodes the results back to Dart.

import Flutter
import UIKit

@available(iOS 12.0, *)
public class SecureEnclavePlusPlugin: NSObject, FlutterPlugin {
    private let core = SecureEnclaveCore()

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(
            name: SecureEnclaveChannel.name,
            binaryMessenger: registrar.messenger()
        )
        let instance = SecureEnclavePlusPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        do {
            guard let args = call.arguments as? [String: Any] else {
                throw SecureEnclaveError.invalidArgument("Arguments must be a dictionary")
            }

            switch call.method {
            case SecureEnclaveMethod.generateKeyPair:
                try handleGenerateKeyPair(args: args, result: result)

            case SecureEnclaveMethod.removeKey:
                try handleRemoveKey(args: args, result: result)

            case SecureEnclaveMethod.isKeyCreated:
                try handleIsKeyCreated(args: args, result: result)

            case SecureEnclaveMethod.getPublicKey:
                try handleGetPublicKey(args: args, result: result)

            case SecureEnclaveMethod.encrypt:
                try handleEncrypt(args: args, result: result)

            case SecureEnclaveMethod.encryptWithPublicKey:
                try handleEncryptWithPublicKey(args: args, result: result)

            case SecureEnclaveMethod.decrypt:
                try handleDecrypt(args: args, result: result)

            case SecureEnclaveMethod.sign:
                try handleSign(args: args, result: result)

            case SecureEnclaveMethod.verify:
                try handleVerify(args: args, result: result)

            default:
                result(FlutterMethodNotImplemented)
                return
            }
        } catch {
            result(SecureEnclaveCodec.error(from: error))
        }
    }

    // MARK: - Method Handlers

    private func handleGenerateKeyPair(args: [String: Any], result: FlutterResult) throws {
        guard let acMap = args[SecureEnclaveArgKey.accessControl] as? [String: Any] else {
            throw SecureEnclaveError.invalidArgument("Missing 'accessControl'")
        }
        let param = try AccessControlParam(map: acMap)
        _ = try core.generateKeyPair(accessControl: param)
        result(SecureEnclaveCodec.success(data: true))
    }

    private func handleRemoveKey(args: [String: Any], result: FlutterResult) throws {
        let tag = try SecureEnclaveCodec.tag(from: args)
        let success = try core.removeKey(tag: tag)
        result(SecureEnclaveCodec.success(data: success))
    }

    private func handleIsKeyCreated(args: [String: Any], result: FlutterResult) throws {
        let tag = try SecureEnclaveCodec.tag(from: args)
        let password = SecureEnclaveCodec.password(from: args)
        let exists = try core.isKeyCreated(tag: tag, password: password)
        result(SecureEnclaveCodec.success(data: exists))
    }

    private func handleGetPublicKey(args: [String: Any], result: FlutterResult) throws {
        let tag = try SecureEnclaveCodec.tag(from: args)
        let password = SecureEnclaveCodec.password(from: args)
        let key = try core.getPublicKey(tag: tag, password: password)
        result(SecureEnclaveCodec.success(data: key))
    }

    private func handleEncrypt(args: [String: Any], result: FlutterResult) throws {
        guard let message = args[SecureEnclaveArgKey.message] as? String else {
            throw SecureEnclaveError.invalidArgument("Missing 'message'")
        }
        let tag = try SecureEnclaveCodec.tag(from: args)
        let password = SecureEnclaveCodec.password(from: args)
        let encrypted = try core.encrypt(message: message, tag: tag, password: password)
        result(SecureEnclaveCodec.success(data: encrypted))
    }

    private func handleEncryptWithPublicKey(args: [String: Any], result: FlutterResult) throws {
        guard let message = args[SecureEnclaveArgKey.message] as? String else {
            throw SecureEnclaveError.invalidArgument("Missing 'message'")
        }
        guard let publicKey = args[SecureEnclaveArgKey.publicKey] as? String else {
            throw SecureEnclaveError.invalidArgument("Missing 'publicKey'")
        }
        let encrypted = try core.encryptWithPublicKey(message: message, publicKey: publicKey)
        result(SecureEnclaveCodec.success(data: encrypted))
    }

    private func handleDecrypt(args: [String: Any], result: FlutterResult) throws {
        guard let messageData = args[SecureEnclaveArgKey.message] as? FlutterStandardTypedData else {
            throw SecureEnclaveError.invalidArgument("Missing 'message'")
        }
        let tag = try SecureEnclaveCodec.tag(from: args)
        let password = SecureEnclaveCodec.password(from: args)
        let decrypted = try core.decrypt(message: messageData.data, tag: tag, password: password)
        result(SecureEnclaveCodec.success(data: decrypted))
    }

    private func handleSign(args: [String: Any], result: FlutterResult) throws {
        guard let messageData = args[SecureEnclaveArgKey.message] as? FlutterStandardTypedData else {
            throw SecureEnclaveError.invalidArgument("Missing 'message'")
        }
        let tag = try SecureEnclaveCodec.tag(from: args)
        let password = SecureEnclaveCodec.password(from: args)
        let signature = try core.sign(tag: tag, password: password, message: messageData.data)
        result(SecureEnclaveCodec.success(data: signature))
    }

    private func handleVerify(args: [String: Any], result: FlutterResult) throws {
        let tag = try SecureEnclaveCodec.tag(from: args)
        guard let plainText = args[SecureEnclaveArgKey.plainText] as? String else {
            throw SecureEnclaveError.invalidArgument("Missing 'plainText'")
        }
        guard let signature = args[SecureEnclaveArgKey.signature] as? String else {
            throw SecureEnclaveError.invalidArgument("Missing 'signature'")
        }
        let password = SecureEnclaveCodec.password(from: args)
        let verified = try core.verify(
            tag: tag, password: password, plainText: plainText, signature: signature
        )
        result(SecureEnclaveCodec.success(data: verified))
    }
}
