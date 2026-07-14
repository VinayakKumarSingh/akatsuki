import axios from 'axios';
import {
  generateRSAKeyPair,
  generateSalt,
  deriveKeyFromPassword,
  exportPublicKey,
  wrapPrivateKey,
  unwrapPrivateKey
} from '../utils/crypto';

const API_BASE = '/api/auth';

export const registerUser = async (username, password, securityQuestion, securityAnswer) => {
    // 1. Generate local RSA keys
    const rsaKeyPair = await generateRSAKeyPair();
    
    // 2. Export public key for sharing
    const rsaPublicKeyStr = await exportPublicKey(rsaKeyPair.publicKey);
    
    // 3. Generate salt & derive key from password to wrap the private key safely
    const saltStr = generateSalt();
    const saltBuffer = window.atob(saltStr).split('').map(c => c.charCodeAt(0));
    const derivedKey = await deriveKeyFromPassword(password, new Uint8Array(saltBuffer).buffer);
    
    // 4. Wrap private key
    const { encryptedPrivateKey, iv } = await wrapPrivateKey(rsaKeyPair.privateKey, derivedKey);
    // Combine IV and encrypted private key for storage (Format: iv:encrypted_data)
    const storedPrivateKey = `${iv}:${encryptedPrivateKey}`;

    // 5. Generate recovery salt & derive key from normalized security answer to wrap recovery private key
    const normalizedAnswer = securityAnswer.toLowerCase().replace(/\s+/g, '');
    const recoverySaltStr = generateSalt();
    const recoverySaltBuffer = window.atob(recoverySaltStr).split('').map(c => c.charCodeAt(0));
    const recoveryDerivedKey = await deriveKeyFromPassword(normalizedAnswer, new Uint8Array(recoverySaltBuffer).buffer);

    const { encryptedPrivateKey: recoveryEncPrivateKey, iv: recoveryIv } = await wrapPrivateKey(rsaKeyPair.privateKey, recoveryDerivedKey);
    const storedPrivateKeyRecovery = `${recoveryIv}:${recoveryEncPrivateKey}`;

    // 6. Send to server
    const payload = {
        username,
        password, // Used by Django to verify auth/generate JWT, not for decrypting our keys
        salt: saltStr,
        rsa_public_key: rsaPublicKeyStr,
        encrypted_rsa_private_key: storedPrivateKey,
        security_question: securityQuestion,
        security_answer: securityAnswer,
        recovery_salt: recoverySaltStr,
        encrypted_rsa_private_key_recovery: storedPrivateKeyRecovery
    };

    const response = await axios.post(`${API_BASE}/register/`, payload);
    return response.data;
};

export const loginUser = async (username, password, otpCode = null) => {
    const payload = { username, password };
    if (otpCode) {
        payload.otp_code = otpCode;
    }
    const response = await axios.post(`${API_BASE}/login/`, payload);
    if (response.data.access) {
        localStorage.setItem('access_token', response.data.access);
        localStorage.setItem('refresh_token', response.data.refresh);
        
        // Fetch user key details to obtain and store the user_id
        const userKeysRes = await axios.get('/api/keys/me/', {
            headers: { Authorization: `Bearer ${response.data.access}` }
        });
        localStorage.setItem('user_id', userKeysRes.data.user_id);
    }
    return response.data;
};

export const logoutUser = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('user_id');
    localStorage.removeItem('decrypted_private_key'); // clear memory
};

export const changePassword = async (oldPassword, newPassword, myKeys) => {
    // 1. Un-wrap existing RSA private key using OLD password
    const oldSaltBuffer = new Uint8Array(
        window.atob(myKeys.salt).split('').map(c => c.charCodeAt(0))
    ).buffer;
    const oldDerivedKey = await deriveKeyFromPassword(oldPassword, oldSaltBuffer);
    
    const [privIvBase64, privEncBase64] = myKeys.encrypted_rsa_private_key.split(':');
    const rsaPrivateKey = await unwrapPrivateKey(privEncBase64, privIvBase64, oldDerivedKey);

    // 2. Re-wrap RSA private key using NEW password
    const newSaltStr = generateSalt();
    const newSaltBuffer = window.atob(newSaltStr).split('').map(c => c.charCodeAt(0));
    const newDerivedKey = await deriveKeyFromPassword(newPassword, new Uint8Array(newSaltBuffer).buffer);
    
    const { encryptedPrivateKey, iv } = await wrapPrivateKey(rsaPrivateKey, newDerivedKey);
    const newStoredPrivateKey = `${iv}:${encryptedPrivateKey}`;

    // 3. Send to server
    const token = localStorage.getItem('access_token');
    const payload = {
        old_password: oldPassword,
        new_password: newPassword,
        new_salt: newSaltStr,
        new_encrypted_rsa_private_key: newStoredPrivateKey
    };

    const response = await axios.post(`${API_BASE}/change-password/`, payload, {
        headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
};

export const getSecurityQuestion = async (username) => {
    const response = await axios.post(`${API_BASE}/forgot-password/question/`, { username });
    return response.data; // { security_question }
};

export const verifySecurityAnswer = async (username, securityAnswer) => {
    const response = await axios.post(`${API_BASE}/forgot-password/verify/`, { username, security_answer: securityAnswer });
    return response.data; // { recovery_salt, encrypted_rsa_private_key_recovery }
};

export const resetPasswordWithRecovery = async (username, securityAnswer, newPassword, newSalt, newEncryptedPrivateKey) => {
    const payload = {
        username,
        security_answer: securityAnswer,
        new_password: newPassword,
        new_salt: newSalt,
        new_encrypted_rsa_private_key: newEncryptedPrivateKey
    };
    const response = await axios.post(`${API_BASE}/forgot-password/reset/`, payload);
    return response.data;
};
