import axios from 'axios';
import {
  generateRSAKeyPair,
  generateSalt,
  deriveKeyFromPassword,
  exportPublicKey,
  wrapPrivateKey
} from '../utils/crypto';

const API_BASE = '/api/auth';

export const registerUser = async (username, password) => {
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

    // 5. Send to server
    const payload = {
        username,
        password, // Used by Django to verify auth/generate JWT, not for decrypting our keys
        salt: saltStr,
        rsa_public_key: rsaPublicKeyStr,
        encrypted_rsa_private_key: storedPrivateKey,
    };

    const response = await axios.post(`${API_BASE}/register/`, payload);
    return response.data;
};

export const loginUser = async (username, password) => {
    const response = await axios.post(`${API_BASE}/login/`, { username, password });
    if (response.data.access) {
        localStorage.setItem('access_token', response.data.access);
        localStorage.setItem('refresh_token', response.data.refresh);
    }
    return response.data;
};

export const logoutUser = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('decrypted_private_key'); // clear memory
};
