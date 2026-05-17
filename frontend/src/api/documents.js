import axios from 'axios';
import {
  generateAESKey,
  encryptFile,
  encryptAESKeyWithRSA,
  importPublicKey,
  arrayBufferToBase64
} from '../utils/crypto';

const API_BASE = '/api';

const getAuthHeaders = () => {
    return {
        Authorization: `Bearer ${localStorage.getItem('access_token')}`
    };
};

export const fetchPublicUsers = async () => {
    const res = await axios.get(`${API_BASE}/keys/public/`, { headers: getAuthHeaders() });
    return res.data;
};

export const uploadEncryptedDocument = async (file, recipientId, recipientPublicKeyJwkStr) => {
    // 1. Generate AES Key
    const aesKey = await generateAESKey();

    // 2. Encrypt File Content
    const fileBuffer = await file.arrayBuffer();
    const { ciphertext, iv } = await encryptFile(fileBuffer, aesKey);

    // 3. Encrypt Filename (for privacy)
    // We reuse encryptFile logic for strings by encoding it
    const enc = new TextEncoder();
    const nameBuffer = enc.encode(file.name);
    const { ciphertext: encNameBuffer, iv: nameIv } = await encryptFile(nameBuffer, aesKey);
    const encryptedFilename = `${nameIv}:${arrayBufferToBase64(encNameBuffer)}`;

    // 4. Encrypt AES Key with Recipient's RSA Public Key
    const recipientPubKey = await importPublicKey(recipientPublicKeyJwkStr);
    const encryptedAESKey = await encryptAESKeyWithRSA(aesKey, recipientPubKey);

    const keys = [
        {
            key_type: 'RSA',
            recipient_id: recipientId,
            encrypted_key: encryptedAESKey
        }
    ];

    // 4b. Also encrypt the AES Key with the Sender's (our own) RSA Public Key
    // so the sender can decrypt and read the file they just uploaded!
    const myKeys = await fetchMyKeys();
    const myPubKey = await importPublicKey(myKeys.rsa_public_key);
    const myEncryptedAESKey = await encryptAESKeyWithRSA(aesKey, myPubKey);
    
    keys.push({
        key_type: 'RSA',
        // recipient_id: null, (Django will just ignore or we don't provide it, but it's better to provide it if we have it. Wait, fetchMyKeys doesn't return user_id right now. But we can just omit recipient_id, and it will be null, and the sender can still iterate and decrypt it!)
        encrypted_key: myEncryptedAESKey
    });

    // 5. Upload via FormData
    const formData = new FormData();
    const encryptedBlob = new Blob([ciphertext], { type: 'application/octet-stream' });
    formData.append('file_path', encryptedBlob, 'encrypted.bin');
    formData.append('encrypted_filename', encryptedFilename);
    formData.append('iv', iv);
    formData.append('keys', JSON.stringify(keys));

    const res = await axios.post(`${API_BASE}/documents/`, formData, {
        headers: {
            ...getAuthHeaders(),
            'Content-Type': 'multipart/form-data'
        }
    });

    return res.data;
};

export const fetchMyKeys = async () => {
    const res = await axios.get(`${API_BASE}/keys/me/`, { headers: getAuthHeaders() });
    return res.data;
};

export const downloadCiphertext = async (url) => {
    const res = await axios.get(url, {
        responseType: 'arraybuffer'
    });
    return res.data;
};
