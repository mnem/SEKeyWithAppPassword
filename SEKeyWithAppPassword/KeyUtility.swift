//
//  KeyUtility.swift
//  SEKeyWithAppPassword
//
//  Created by David Wagner on 09/07/2019.
//  Copyright © 2019 David Wagner. All rights reserved.
//

import Foundation
import LocalAuthentication
import CommonCrypto

// MARK:- Error enums
enum KeychainError: Error {
    case unhandledError(status: OSStatus)
}

enum KeyOperationError: Error {
    case unhandledError(status: OSStatus)
    case couldNotCopyPublicKey
    case signatureFailedVerification
}

// MARK:- Key creation
func createKeyUsingSecKeyGeneratePair(tag: Data, password: Data?) throws -> KeyHolder {
    try deleteTaggedKey(tag: tag)
    let attributes = try createKeyAttributesWithTag(tag, password: password)
    var privateKey: SecKey?
    let result = SecKeyGeneratePair(attributes as CFDictionary, nil, &privateKey)
    guard result == errSecSuccess, let key = privateKey else {
        throw KeyOperationError.unhandledError(status: result)
    }
    
    return KeyHolder(key: key)
}

func createKeyUsingSecKeyCreateRandom(tag: Data, password: Data?) throws -> KeyHolder {
    try deleteTaggedKey(tag: tag)
    let attributes = try createKeyAttributesWithTag(tag, password: password)
    var error: Unmanaged<CFError>?
    let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error)
    guard let key = privateKey else {
        throw error!.takeRetainedValue() as Error
    }
    
    return KeyHolder(key: key)
}

// MARK:- Keys and signing
class KeyHolder {
    let key: SecKey
    
    init(key: SecKey) {
        self.key = key
    }
    
    func signAndVerify() throws {
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            throw KeyOperationError.couldNotCopyPublicKey
        }
        
        let dataToSign = "Hello, World!".data(using: .utf8)!
        let dataToSignHash = sha256(data: dataToSign)
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureDigestX962SHA256, dataToSignHash as CFData, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        
        let valid = SecKeyVerifySignature(publicKey, .ecdsaSignatureDigestX962SHA256, dataToSignHash as CFData, signature, &error)
        guard error == nil else {
            throw error!.takeRetainedValue() as Error
        }
        guard valid else {
            throw KeyOperationError.signatureFailedVerification
        }
    }
}

// MARK:- Internal utilities
fileprivate func createKeyAttributesWithTag(_ tag: Data, password: Data?) throws -> [String : Any] {
    var error: Unmanaged<CFError>?
    let a = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                            password == nil ?
                                                .privateKeyUsage :
                                                [[.privateKeyUsage, .applicationPassword]],
                                            &error)
    guard let access = a else {
        throw error!.takeRetainedValue() as Error
    }
    
    let context = LAContext()
    if let password = password {
        context.setCredential(password, type: .applicationPassword)
    }
    
    #if targetEnvironment(simulator)
    return [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessControl as String: access,
            kSecUseAuthenticationContext as String: context,
        ]
    ]
    #else
    return [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessControl as String: access,
            kSecUseAuthenticationContext as String: context,
        ]
    ]
    #endif
}

fileprivate func deleteTaggedKey(tag: Data) throws {
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag,
    ]
    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
        throw KeychainError.unhandledError(status: status)
    }
}

fileprivate func sha256(data : Data) -> Data {
    var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
    data.withUnsafeBytes {
        _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
    }
    return Data(hash)
}
