/**
 * Cryptographic Service using Web Crypto API
 * Implements E2EE Primitives for the Hybrid Encrypted Document Sharing Platform
 */

// Helper: Convert ArrayBuffer to Base64 String
export const arrayBufferToBase64 = (buffer) => {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
};

// Helper: Convert Base64 String to ArrayBuffer
export const base64ToArrayBuffer = (base64) => {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
};

// 1. Generate RSA-4096 Key Pair
export const generateRSAKeyPair = async () => {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 4096,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true, // exportable
        ["encrypt", "decrypt"]
    );
    return keyPair;
};

// 2. Export RSA Public Key to JWK string
export const exportPublicKey = async (publicKey) => {
    const exported = await window.crypto.subtle.exportKey("jwk", publicKey);
    return JSON.stringify(exported);
};

// 3. Import RSA Public Key from JWK string
export const importPublicKey = async (jwkString) => {
    const jwk = JSON.parse(jwkString);
    return await window.crypto.subtle.importKey(
        "jwk",
        jwk,
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        true,
        ["encrypt"]
    );
};

// 4. Derive Key from Password using PBKDF2
export const deriveKeyFromPassword = async (password, saltBuffer) => {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );

    return await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: saltBuffer,
            iterations: 100000,
            hash: "SHA-256",
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
};

// 5. Wrap (Encrypt) RSA Private Key with derived Password Key
export const wrapPrivateKey = async (privateKey, passwordKey) => {
    const exportedPrivate = await window.crypto.subtle.exportKey("pkcs8", privateKey);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        passwordKey,
        exportedPrivate
    );
    return {
        encryptedPrivateKey: arrayBufferToBase64(encrypted),
        iv: arrayBufferToBase64(iv.buffer)
    };
};

// 6. Unwrap (Decrypt) RSA Private Key
export const unwrapPrivateKey = async (encryptedBase64, ivBase64, passwordKey) => {
    const encrypted = base64ToArrayBuffer(encryptedBase64);
    const iv = new Uint8Array(base64ToArrayBuffer(ivBase64));
    
    const decryptedPKCS8 = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        passwordKey,
        encrypted
    );

    return await window.crypto.subtle.importKey(
        "pkcs8",
        decryptedPKCS8,
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        true,
        ["decrypt"]
    );
};

// 7. Generate AES-256-GCM Key (for File Encryption)
export const generateAESKey = async () => {
    return await window.crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256,
        },
        true,
        ["encrypt", "decrypt"]
    );
};

// 8. Encrypt File ArrayBuffer with AES-GCM
export const encryptFile = async (fileBuffer, aesKey) => {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedContent = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        aesKey,
        fileBuffer
    );
    return {
        ciphertext: encryptedContent,
        iv: arrayBufferToBase64(iv.buffer)
    };
};

// 9. Decrypt File ArrayBuffer with AES-GCM
export const decryptFile = async (ciphertextBuffer, ivBase64, aesKey) => {
    const iv = new Uint8Array(base64ToArrayBuffer(ivBase64));
    return await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        aesKey,
        ciphertextBuffer
    );
};

// 10. Encrypt AES Key with RSA Public Key
export const encryptAESKeyWithRSA = async (aesKey, rsaPublicKey) => {
    const exportedAES = await window.crypto.subtle.exportKey("raw", aesKey);
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        rsaPublicKey,
        exportedAES
    );
    return arrayBufferToBase64(encrypted);
};

// 11. Decrypt AES Key with RSA Private Key
export const decryptAESKeyWithRSA = async (encryptedAESBase64, rsaPrivateKey) => {
    const encryptedAES = base64ToArrayBuffer(encryptedAESBase64);
    const decryptedRaw = await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        rsaPrivateKey,
        encryptedAES
    );
    return await window.crypto.subtle.importKey(
        "raw",
        decryptedRaw,
        { name: "AES-GCM" },
        true,
        ["encrypt", "decrypt"]
    );
};

export const generateSalt = () => {
    return arrayBufferToBase64(window.crypto.getRandomValues(new Uint8Array(16)));
};
