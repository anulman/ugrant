import CryptoKit
import Foundation
import LocalAuthentication
import Security
let wrapMaterialService = "dev.ugrant.secure-enclave.wrap-material"
let wrapMaterialVersion = 1
let wrapMaterialInfo = Data("ugrant-secure-enclave-wrap-material".utf8)
func emitError(reason: String, message: String) {
    let payload = ["reason": reason, "message": message]
    if let data = try? JSONSerialization.data(withJSONObject: payload, options: []) {
        FileHandle.standardError.write(data)
        FileHandle.standardError.write(Data("\n".utf8))
        return
    }
    FileHandle.standardError.write(Data((reason + ": " + message + "\n").utf8))
}
func reasonForStatus(_ status: OSStatus) -> String {
    switch status {
    case errSecUserCanceled:
        return "user_cancelled"
    case errSecItemNotFound:
        return "key_missing"
    case errSecAuthFailed, errSecInteractionNotAllowed, errSecInteractionRequired:
        return "access_denied"
    case errSecUnimplemented, errSecNotAvailable:
        return "unavailable"
    default:
        return "unavailable"
    }
}
func reasonForNSError(_ error: NSError) -> String {
    if error.domain == LAError.errorDomain {
        switch error.code {
        case LAError.userCancel.rawValue:
            return "user_cancelled"
        case LAError.authenticationFailed.rawValue,
             LAError.notInteractive.rawValue,
             LAError.appCancel.rawValue,
             LAError.systemCancel.rawValue:
            return "access_denied"
        case LAError.passcodeNotSet.rawValue,
             LAError.biometryNotAvailable.rawValue,
             LAError.biometryNotEnrolled.rawValue,
             LAError.biometryLockout.rawValue:
            return "unavailable"
        default:
            break
        }
    }
    return reasonForStatus(OSStatus(error.code))
}
func fail(_ message: String, reason: String = "unavailable") -> Never {
    emitError(reason: reason, message: message)
    exit(1)
}
func secError(_ error: Unmanaged<CFError>?) -> (reason: String, message: String) {
    guard let error else { return ("unavailable", "unknown Security error") }
    let value = error.takeRetainedValue()
    let nsError = value as Error as NSError
    return (reasonForNSError(nsError), String(describing: value))
}
func appTag(_ keyVersion: Int) -> String {
    "dev.ugrant.secure-enclave.dek:\(keyVersion)"
}
func randomData(_ count: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    guard status == errSecSuccess else { fail("SecRandomCopyBytes failed: \(status)", reason: reasonForStatus(status)) }
    return Data(bytes)
}
func deleteKey(tag: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: Data(tag.utf8),
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    ]
    let status = SecItemDelete(query as CFDictionary)
    if status != errSecSuccess && status != errSecItemNotFound {
        fail("SecItemDelete failed: \(status)", reason: reasonForStatus(status))
    }
}
func deleteWrapMaterial(tag: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: wrapMaterialService,
        kSecAttrAccount as String: tag,
    ]
    let status = SecItemDelete(query as CFDictionary)
    if status != errSecSuccess && status != errSecItemNotFound {
        fail("SecItemDelete wrap material failed: \(status)", reason: reasonForStatus(status))
    }
}
func createEphemeralPrivateKey() -> SecKey {
    var error: Unmanaged<CFError>?
    let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: false,
        ],
    ]
    guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
        let failure = secError(error)
        fail("ephemeral key generation failed: \(failure.message)", reason: failure.reason)
    }
    return key
}
func createSecureEnclavePrivateKey(tag: String, requireUserPresence: Bool) -> SecKey {
    var accessError: Unmanaged<CFError>?
    let flags: SecAccessControlCreateFlags = requireUserPresence ? [.privateKeyUsage, .userPresence] : [.privateKeyUsage]
    guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &accessError) else {
        let failure = secError(accessError)
        fail("SecAccessControlCreateWithFlags failed: \(failure.message)", reason: failure.reason)
    }

    let privateKeyAttrs: [String: Any] = [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: Data(tag.utf8),
        kSecAttrAccessControl as String: access,
    ]
    let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: privateKeyAttrs,
    ]

    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
        let failure = secError(error)
        fail("secure enclave key generation failed: \(failure.message)", reason: failure.reason)
    }
    return key
}
func loadSecureEnclavePrivateKey(tag: String) -> SecKey {
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: Data(tag.utf8),
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecReturnRef as String: true,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess, let key = item as! SecKey? else {
        fail("SecItemCopyMatching failed: \(status)", reason: reasonForStatus(status))
    }
    return key
}
func publicKeyData(_ key: SecKey) -> Data {
    guard let pub = SecKeyCopyPublicKey(key) else { fail("missing public key") }
    var error: Unmanaged<CFError>?
    guard let data = SecKeyCopyExternalRepresentation(pub, &error) as Data? else {
        let failure = secError(error)
        fail("public key export failed: \(failure.message)", reason: failure.reason)
    }
    return data
}
func loadWrapMaterial(tag: String) -> Data? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: wrapMaterialService,
        kSecAttrAccount as String: tag,
        kSecReturnData as String: true,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess, let data = item as? Data else {
        fail("SecItemCopyMatching wrap material failed: \(status)", reason: reasonForStatus(status))
    }
    return data
}
func storeWrapMaterial(tag: String, payload: [String: Any]) {
    let data: Data
    do {
        data = try JSONSerialization.data(withJSONObject: payload, options: [])
    } catch {
        fail("wrap material serialization failed: \(error)")
    }
    deleteWrapMaterial(tag: tag)
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: wrapMaterialService,
        kSecAttrAccount as String: tag,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecValueData as String: data,
    ]
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else {
        fail("SecItemAdd wrap material failed: \(status)", reason: reasonForStatus(status))
    }
}
func publicKeyFromData(_ data: Data) -> SecKey {
    var error: Unmanaged<CFError>?
    let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        kSecAttrKeySizeInBits as String: 256,
    ]
    guard let key = SecKeyCreateWithData(data as CFData, attrs as CFDictionary, &error) else {
        let failure = secError(error)
        fail("public key import failed: \(failure.message)", reason: failure.reason)
    }
    return key
}
func keyExchangeContext() -> LAContext {
    let context = LAContext()
    context.interactionNotAllowed = false
    return context
}
func sharedSecret(privateKey: SecKey, publicKey: SecKey) -> Data {
    let algorithm = SecKeyAlgorithm.ecdhKeyExchangeStandard
    guard SecKeyIsAlgorithmSupported(privateKey, .keyExchange, algorithm) else {
        fail("ECDH key exchange is not supported for this key", reason: "unavailable")
    }
    var error: Unmanaged<CFError>?
    let context = keyExchangeContext()
    let params = NSMutableDictionary()
    params[kSecUseAuthenticationContext] = context
    guard let data = SecKeyCopyKeyExchangeResult(privateKey, algorithm, publicKey, params, &error) as Data? else {
        let failure = secError(error)
        fail("key exchange failed: \(failure.message)", reason: failure.reason)
    }
    return data
}
func wrapKey(privateKey: SecKey, publicKey: SecKey) -> SymmetricKey {
    let algorithm = SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA256
    guard SecKeyIsAlgorithmSupported(privateKey, .keyExchange, algorithm) else {
        fail("ECDH X9.63 SHA-256 key exchange is not supported for this key", reason: "unavailable")
    }
    var error: Unmanaged<CFError>?
    let context = keyExchangeContext()
    let params = NSMutableDictionary()
    params[SecKeyKeyExchangeParameter.requestedSize] = 32
    params[SecKeyKeyExchangeParameter.sharedInfo] = wrapMaterialInfo
    params[kSecUseAuthenticationContext] = context
    guard let data = SecKeyCopyKeyExchangeResult(privateKey, algorithm, publicKey, params, &error) as Data? else {
        let failure = secError(error)
        fail("wrap key derivation failed: \(failure.message)", reason: failure.reason)
    }
    return SymmetricKey(data: data)
}
func sealWrapMaterial(secret: Data, key: SymmetricKey) -> [String: Any] {
    do {
        let sealed = try AES.GCM.seal(secret, using: key)
        let nonce = sealed.nonce.withUnsafeBytes { Data($0) }
        let ciphertext = sealed.ciphertext + sealed.tag
        return [
            "version": wrapMaterialVersion,
            "nonce_b64": nonce.base64EncodedString(),
            "ciphertext_b64": ciphertext.base64EncodedString(),
        ]
    } catch {
        fail("AES-GCM seal failed: \(error)")
    }
}
func openWrapMaterial(payload: [String: Any], key: SymmetricKey) -> Data {
    guard let version = payload["version"] as? Int, version == wrapMaterialVersion else {
        fail("unsupported wrap material version")
    }
    guard let nonceB64 = payload["nonce_b64"] as? String,
          let ciphertextB64 = payload["ciphertext_b64"] as? String,
          let nonceData = Data(base64Encoded: nonceB64),
          let combined = Data(base64Encoded: ciphertextB64),
          combined.count >= 16 else {
        fail("wrap material payload is invalid")
    }
    do {
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: nonceData),
            ciphertext: Data(combined.dropLast(16)),
            tag: Data(combined.suffix(16))
        )
        return try AES.GCM.open(box, using: key)
    } catch {
        fail("AES-GCM open failed: \(error)")
    }
}
func emit(_ payload: [String: Any]) {
    do {
        let data = try JSONSerialization.data(withJSONObject: payload, options: [])
        FileHandle.standardOutput.write(data)
    } catch {
        fail("JSON serialization failed: \(error)")
    }
}
let args = CommandLine.arguments
if args.count < 2 { fail("missing mode") }
switch args[1] {
case "create":
    if args.count != 4 { fail("usage: create <key-version> <require-user-presence>") }
    guard let keyVersion = Int(args[2]) else { fail("invalid key version") }
    let requireUserPresence = args[3] == "1" || args[3].lowercased() == "true"
    let tag = appTag(keyVersion)
    let enclaveKey = createSecureEnclavePrivateKey(tag: tag, requireUserPresence: requireUserPresence)
    let ephemeralPrivate = createEphemeralPrivateKey()
    let ephemeralPubB64 = publicKeyData(ephemeralPrivate).base64EncodedString()
    let wrapSecret = randomData(32)
    let key = wrapKey(privateKey: ephemeralPrivate, publicKey: SecKeyCopyPublicKey(enclaveKey)!)
    var payload = sealWrapMaterial(secret: wrapSecret, key: key)
    payload["ephemeral_pub_b64"] = ephemeralPubB64
    storeWrapMaterial(tag: tag, payload: payload)
    emit([
        "secret_b64": wrapSecret.base64EncodedString(),
        "secret_ref": "macos-secure-enclave:tag=\(tag)",
        "ephemeral_pub_b64": ephemeralPubB64,
        "require_user_presence": requireUserPresence,
    ])
case "load":
    if args.count != 4 { fail("usage: load <tag> <ephemeral-pub-b64>") }
    guard let ephemeralPub = Data(base64Encoded: args[3]) else { fail("invalid ephemeral public key base64") }
    let enclaveKey = loadSecureEnclavePrivateKey(tag: args[2])
    let secret: Data
    if let stored = loadWrapMaterial(tag: args[2]) {
        let raw: Any
        do {
            raw = try JSONSerialization.jsonObject(with: stored, options: [])
        } catch {
            fail("wrap material JSON is invalid: \(error)")
        }
        guard let payload = raw as? [String: Any] else {
            fail("wrap material JSON is invalid")
        }
        if let storedEphemeral = payload["ephemeral_pub_b64"] as? String, storedEphemeral != args[3] {
            fail("stored wrap material does not match wrapped-key metadata")
        }
        secret = openWrapMaterial(payload: payload, key: wrapKey(privateKey: enclaveKey, publicKey: publicKeyFromData(ephemeralPub)))
    } else {
        secret = sharedSecret(privateKey: enclaveKey, publicKey: publicKeyFromData(ephemeralPub))
    }
    emit([
        "secret_b64": secret.base64EncodedString(),
        "secret_ref": "macos-secure-enclave:tag=\(args[2])",
    ])
case "delete":
    if args.count != 3 { fail("usage: delete <tag>") }
    deleteWrapMaterial(tag: args[2])
    deleteKey(tag: args[2])
default:
    fail("unknown mode: \(args[1])")
}
