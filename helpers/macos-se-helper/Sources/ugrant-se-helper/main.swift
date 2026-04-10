import CryptoKit
import Foundation
import LocalAuthentication
import Security
let wrapMaterialService = "dev.ugrant.secure-enclave.wrap-material"
let debugLoggingEnabled = ProcessInfo.processInfo.environment["UGRANT_SE_DEBUG"] == "1"
func debugLog(_ message: String) {
    guard debugLoggingEnabled else { return }
    FileHandle.standardError.write(Data(("[ugrant-se-helper] " + message + "\n").utf8))
}
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
func createSecureEnclavePrivateKey(tag: String, requireUserPresence: Bool, permanent: Bool = true) -> SecKey {
    var accessError: Unmanaged<CFError>?
    let flags: SecAccessControlCreateFlags = requireUserPresence ? [.privateKeyUsage, .userPresence] : [.privateKeyUsage]
    guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &accessError) else {
        let failure = secError(accessError)
        fail("SecAccessControlCreateWithFlags failed: \(failure.message)", reason: failure.reason)
    }

    var privateKeyAttrs: [String: Any] = [
        kSecAttrIsPermanent as String: permanent,
        kSecAttrAccessControl as String: access,
    ]
    if permanent {
        privateKeyAttrs[kSecAttrLabel as String] = tag
        privateKeyAttrs[kSecAttrApplicationTag as String] = Data(tag.utf8)
    }
    let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: privateKeyAttrs,
    ]

    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
        let failure = secError(error)
        let permanence = permanent ? "persistent" : "temporary"
        fail("\(permanence) secure enclave key generation failed: \(failure.message)", reason: failure.reason)
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

func persistSecureEnclavePrivateKey(_ key: SecKey, tag: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecValueRef as String: key,
        kSecAttrApplicationTag as String: Data(tag.utf8),
        kSecAttrLabel as String: tag,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    ]
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else {
        fail("SecItemAdd persisted secure enclave key failed: \(status)", reason: reasonForStatus(status))
    }
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
func publicKeyHashHex(_ key: SecKey) -> String {
    let digest = SHA256.hash(data: publicKeyData(key))
    return digest.map { String(format: "%02x", $0) }.joined()
}
func findCtkPrivateKey(label: String, expectedPublicKeyHash: String? = nil) -> SecKey? {
    let candidateQueries: [[String: Any]] = [
        [
            kSecClass as String: kSecClassKey,
            kSecAttrLabel as String: label,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ],
        [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ],
    ]

    for (queryIndex, query) in candidateQueries.enumerated() {
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        debugLog("findCtkPrivateKey query#\(queryIndex + 1) status=\(status) label=\(label) expectedHash=\(expectedPublicKeyHash ?? "<none>")")
        if status == errSecItemNotFound { continue }
        guard status == errSecSuccess else {
            fail("SecItemCopyMatching CTK key failed: \(status)", reason: reasonForStatus(status))
        }

        let keys: [SecKey]
        if let many = item as? [SecKey] {
            keys = many
        } else if let one = item as! SecKey? {
            keys = [one]
        } else {
            fail("CTK key lookup returned unexpected result", reason: "unavailable")
        }

        debugLog("findCtkPrivateKey query#\(queryIndex + 1) candidateCount=\(keys.count)")
        for key in keys {
            guard let publicKey = SecKeyCopyPublicKey(key) else { continue }
            let hash = publicKeyHashHex(publicKey)
            debugLog("findCtkPrivateKey candidate hash=\(hash)")
            if let expectedPublicKeyHash, hash.caseInsensitiveCompare(expectedPublicKeyHash) != ComparisonResult.orderedSame {
                continue
            }
            debugLog("findCtkPrivateKey matched candidate hash=\(hash) via query#\(queryIndex + 1)")
            return key
        }
    }
    return nil
}
func loadCtkPrivateKey(label: String, expectedPublicKeyHash: String? = nil, retries: Int = 20, retryDelaySeconds: Double = 0.1) -> SecKey {
    debugLog("loadCtkPrivateKey start label=\(label) expectedHash=\(expectedPublicKeyHash ?? "<none>") retries=\(retries) delay=\(retryDelaySeconds)")
    for attempt in 0...max(0, retries) {
        debugLog("loadCtkPrivateKey attempt \(attempt + 1)/\(max(0, retries) + 1)")
        if let key = findCtkPrivateKey(label: label, expectedPublicKeyHash: expectedPublicKeyHash) {
            debugLog("loadCtkPrivateKey success on attempt \(attempt + 1)")
            return key
        }
        debugLog("loadCtkPrivateKey miss on attempt \(attempt + 1)")
        if attempt < retries {
            Thread.sleep(forTimeInterval: retryDelaySeconds)
        }
    }
    fail("CTK key not found for label \(label) after \(max(0, retries) + 1) attempts", reason: "key_missing")
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
func runScAuth(_ args: [String]) -> String {
    debugLog("runScAuth starting: /usr/sbin/sc_auth \(args.joined(separator: " "))")
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: "/usr/sbin/sc_auth")
    proc.arguments = args
    let out = Pipe()
    let err = Pipe()
    proc.standardOutput = out
    proc.standardError = err
    do {
        try proc.run()
    } catch {
        fail("failed to launch sc_auth: \(error)")
    }
    proc.waitUntilExit()
    let stdout = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    let stderr = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    debugLog("runScAuth finished status=\(proc.terminationStatus) stdout=\(stdout.isEmpty ? "<empty>" : stdout.replacingOccurrences(of: "\n", with: "\\n")) stderr=\(stderr.isEmpty ? "<empty>" : stderr.replacingOccurrences(of: "\n", with: "\\n"))")
    guard proc.terminationStatus == 0 else {
        fail("sc_auth failed: \(stderr.isEmpty ? stdout : stderr)")
    }
    return stdout
}
func parseCtkIdentities(_ text: String) -> [[String: String]] {
    let lines = text.split(whereSeparator: \ .isNewline).map(String.init).filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
    guard lines.count >= 2 else { return [] }
    return lines.dropFirst().compactMap { line in
        let parts = line.split(whereSeparator: \ .isWhitespace).map(String.init)
        guard parts.count >= 6 else { return nil }
        return [
            "key_type": parts[0],
            "public_key_hash": parts[1],
            "protection": parts[2],
            "label": parts[3],
            "common_name": parts[4],
            "valid": parts.last ?? "",
        ]
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
    let enclaveKey = createSecureEnclavePrivateKey(tag: tag, requireUserPresence: requireUserPresence, permanent: true)
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
case "create-temp":
    if args.count != 3 { fail("usage: create-temp <require-user-presence>") }
    let requireUserPresence = args[2] == "1" || args[2].lowercased() == "true"
    let tag = "temp.\(UUID().uuidString)"
    let enclaveKey = createSecureEnclavePrivateKey(tag: tag, requireUserPresence: requireUserPresence, permanent: false)
    emit([
        "public_key_b64": publicKeyData(SecKeyCopyPublicKey(enclaveKey)!).base64EncodedString(),
        "require_user_presence": requireUserPresence,
    ])
case "create-persist-test":
    if args.count != 4 { fail("usage: create-persist-test <key-version> <require-user-presence>") }
    guard let keyVersion = Int(args[2]) else { fail("invalid key version") }
    let requireUserPresence = args[3] == "1" || args[3].lowercased() == "true"
    let tag = appTag(keyVersion)
    let enclaveKey = createSecureEnclavePrivateKey(tag: tag, requireUserPresence: requireUserPresence, permanent: false)
    persistSecureEnclavePrivateKey(enclaveKey, tag: tag)
    let loaded = loadSecureEnclavePrivateKey(tag: tag)
    emit([
        "public_key_b64": publicKeyData(SecKeyCopyPublicKey(loaded)!).base64EncodedString(),
        "secret_ref": "macos-secure-enclave:tag=\(tag)",
        "require_user_presence": requireUserPresence,
    ])
case "create-ctk":
    if args.count != 4 { fail("usage: create-ctk <label> <require-user-presence>") }
    let label = args[2]
    let requireUserPresence = args[3] == "1" || args[3].lowercased() == "true"
    let protection = requireUserPresence ? "bio" : "none"
    _ = runScAuth(["create-ctk-identity", "-l", label, "-k", "p-256", "-t", protection])
    let identities = parseCtkIdentities(runScAuth(["list-ctk-identities"]))
    guard let match = identities.first(where: { $0["label"] == label }) else {
        fail("created CTK identity not found after sc_auth create")
    }
    emit([
        "secret_ref": "macos-ctk-secure-enclave:label=\(label);hash=\(match["public_key_hash"] ?? "")",
        "label": label,
        "public_key_hash": match["public_key_hash"] ?? "",
        "require_user_presence": requireUserPresence,
    ])
case "create-ctk-wrap":
    if args.count != 4 { fail("usage: create-ctk-wrap <label> <require-user-presence>") }
    let label = args[2]
    let requireUserPresence = args[3] == "1" || args[3].lowercased() == "true"
    let protection = requireUserPresence ? "bio" : "none"
    debugLog("create-ctk-wrap start label=\(label) requireUserPresence=\(requireUserPresence) protection=\(protection)")
    _ = runScAuth(["create-ctk-identity", "-l", label, "-k", "p-256", "-t", protection, "-N", "ugrant", "-O", "ugrant", "-U", "Secure Enclave", "-L", "Local", "-S", "Local", "-C", "US"])
    debugLog("create-ctk-wrap identity created, listing identities")
    let identities = parseCtkIdentities(runScAuth(["list-ctk-identities"]))
    debugLog("create-ctk-wrap identities count=\(identities.count)")
    guard let match = identities.first(where: { $0["label"] == label }), let publicKeyHash = match["public_key_hash"], !publicKeyHash.isEmpty else {
        fail("created CTK identity not found after sc_auth create")
    }
    debugLog("create-ctk-wrap matched label=\(label) publicKeyHash=\(publicKeyHash)")
    let enclaveKey = loadCtkPrivateKey(label: label)
    debugLog("create-ctk-wrap CTK private key loaded (label-only bootstrap path)")
    let ephemeralPrivate = createEphemeralPrivateKey()
    let ephemeralPubB64 = publicKeyData(ephemeralPrivate).base64EncodedString()
    debugLog("create-ctk-wrap ephemeral key generated pubB64Length=\(ephemeralPubB64.count)")
    let wrapSecret = randomData(32)
    debugLog("create-ctk-wrap wrap secret generated length=\(wrapSecret.count)")
    let key = wrapKey(privateKey: ephemeralPrivate, publicKey: SecKeyCopyPublicKey(enclaveKey)!)
    debugLog("create-ctk-wrap derived wrap key")
    var payload = sealWrapMaterial(secret: wrapSecret, key: key)
    payload["ephemeral_pub_b64"] = ephemeralPubB64
    debugLog("create-ctk-wrap storing wrap material")
    storeWrapMaterial(tag: label, payload: payload)
    debugLog("create-ctk-wrap success")
    emit([
        "secret_b64": wrapSecret.base64EncodedString(),
        "secret_ref": "macos-ctk-secure-enclave:label=\(label);hash=\(publicKeyHash)",
        "ephemeral_pub_b64": ephemeralPubB64,
        "require_user_presence": requireUserPresence,
    ])
case "list-ctk":
    emit(["identities": parseCtkIdentities(runScAuth(["list-ctk-identities"]))])
case "load-ctk":
    if args.count != 5 { fail("usage: load-ctk <label> <public-key-hash> <ephemeral-pub-b64>") }
    debugLog("load-ctk start label=\(args[2]) publicKeyHash=\(args[3]) ephemeralPubB64Length=\(args[4].count)")
    guard let ephemeralPub = Data(base64Encoded: args[4]) else { fail("invalid ephemeral public key base64") }
    debugLog("load-ctk decoded ephemeral public key bytes=\(ephemeralPub.count)")
    let enclaveKey = loadCtkPrivateKey(label: args[2], expectedPublicKeyHash: args[3])
    debugLog("load-ctk CTK private key loaded")
    let secret: Data
    if let stored = loadWrapMaterial(tag: args[2]) {
        debugLog("load-ctk found stored wrap material bytes=\(stored.count)")
        let raw: Any
        do {
            raw = try JSONSerialization.jsonObject(with: stored, options: [])
        } catch {
            fail("wrap material JSON is invalid: \(error)")
        }
        guard let payload = raw as? [String: Any] else {
            fail("wrap material JSON is invalid")
        }
        if let storedEphemeral = payload["ephemeral_pub_b64"] as? String, storedEphemeral != args[4] {
            fail("stored wrap material does not match wrapped-key metadata")
        }
        debugLog("load-ctk deriving wrap key from stored material")
        secret = openWrapMaterial(payload: payload, key: wrapKey(privateKey: enclaveKey, publicKey: publicKeyFromData(ephemeralPub)))
        debugLog("load-ctk unwrapped stored material successfully")
    } else {
        debugLog("load-ctk no stored wrap material, using raw shared secret path")
        secret = sharedSecret(privateKey: enclaveKey, publicKey: publicKeyFromData(ephemeralPub))
        debugLog("load-ctk derived shared secret successfully")
    }
    emit([
        "secret_b64": secret.base64EncodedString(),
        "secret_ref": "macos-ctk-secure-enclave:label=\(args[2]);hash=\(args[3])",
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
case "delete-ctk-wrap":
    if args.count != 3 { fail("usage: delete-ctk-wrap <label>") }
    deleteWrapMaterial(tag: args[2])
default:
    fail("unknown mode: \(args[1])")
}
