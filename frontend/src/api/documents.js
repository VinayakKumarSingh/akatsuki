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

    // Prepare Keys array (we can also encrypt for ourselves so we can read it later, but let's stick to recipient for now)
    const keys = [
        {
            key_type: 'RSA',
            recipient_id: recipientId,
            encrypted_key: encryptedAESKey
        }
    ];

    // 5. Upload via FormData
    const formData = new FormData();
    const encryptedBlob = new Blob([ciphertext], { type: 'application/octet-stream' });
    formData.append('file', encryptedBlob);
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
