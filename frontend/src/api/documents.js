import axios from 'axios';
import {
  generateAESKey,
  encryptFile,
  encryptAESKeyWithRSA,
  importPublicKey,
  arrayBufferToBase64,
  encryptAuditLog
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

export const uploadEncryptedDocument = async (file, recipientId, recipientPublicKeyJwkStr, permissions = 'DOWNLOAD', documentId = null) => {
    // 1. Generate AES Key
    const aesKey = await generateAESKey();

    // 2. Encrypt File Content
    const fileBuffer = await file.arrayBuffer();
    const { ciphertext, iv } = await encryptFile(fileBuffer, aesKey);

    // 3. Encrypt Filename (for privacy)
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
            encrypted_key: encryptedAESKey,
            permissions: permissions
        }
    ];

    // 4b. Also encrypt the AES Key with the Sender's RSA Public Key
    const myKeys = await fetchMyKeys();
    const myPubKey = await importPublicKey(myKeys.rsa_public_key);
    const myEncryptedAESKey = await encryptAESKeyWithRSA(aesKey, myPubKey);
    
    keys.push({
        key_type: 'RSA',
        encrypted_key: myEncryptedAESKey,
        permissions: 'DOWNLOAD' // Sender always has download permissions
    });

    // 5. Upload via FormData
    const formData = new FormData();
    const encryptedBlob = new Blob([ciphertext], { type: 'application/octet-stream' });
    formData.append('file', encryptedBlob, 'encrypted.bin');
    formData.append('encrypted_filename', encryptedFilename);
    formData.append('iv', iv);
    formData.append('keys', JSON.stringify(keys));
    if (documentId) {
        formData.append('document_id', documentId);
    }

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

export const downloadCiphertext = async (docId, versionId = null) => {
    const url = versionId 
        ? `${API_BASE}/documents/${docId}/download/?version_id=${versionId}`
        : `${API_BASE}/documents/${docId}/download/`;
    const res = await axios.get(url, { 
        headers: getAuthHeaders(),
        responseType: 'arraybuffer' 
    });
    return res.data;
};

// Access Requests Workflow
export const requestAccess = async (docId) => {
    const res = await axios.post(`${API_BASE}/documents/${docId}/request-access/`, {}, { headers: getAuthHeaders() });
    return res.data;
};

export const fetchPendingRequests = async () => {
    const res = await axios.get(`${API_BASE}/requests/pending/`, { headers: getAuthHeaders() });
    return res.data;
};

export const approveAccessRequest = async (reqId, encryptedKey, permissions = 'DOWNLOAD') => {
    const res = await axios.post(`${API_BASE}/requests/${reqId}/approve/`, {
        encrypted_key: encryptedKey,
        permissions: permissions
    }, { headers: getAuthHeaders() });
    return res.data;
};

export const denyAccessRequest = async (reqId) => {
    const res = await axios.post(`${API_BASE}/requests/${reqId}/deny/`, {}, { headers: getAuthHeaders() });
    return res.data;
};

// Audit Log Helpers
export const createAuditLog = async (action, documentId, detailsStr) => {
    try {
        const myKeys = await fetchMyKeys();
        const pubKey = await importPublicKey(myKeys.rsa_public_key);
        const payload = JSON.stringify({
            action,
            document_id: documentId,
            details: detailsStr,
            timestamp: new Date().toISOString()
        });
        const encryptedLog = await encryptAuditLog(payload, pubKey);
        
        await axios.post(`${API_BASE}/audit-logs/`, {
            encrypted_log: encryptedLog
        }, { headers: getAuthHeaders() });
    } catch (err) {
        console.error("Failed to create audit log", err);
    }
};

export const fetchAuditLogs = async () => {
    const res = await axios.get(`${API_BASE}/audit-logs/`, { headers: getAuthHeaders() });
    return res.data;
};

// Zero-Knowledge Document Version Upload Helper
export const uploadDocumentVersion = async (file, documentId, recipientKeys) => {
    const aesKey = await generateAESKey();
    const fileBuffer = await file.arrayBuffer();
    const { ciphertext, iv } = await encryptFile(fileBuffer, aesKey);

    const enc = new TextEncoder();
    const nameBuffer = enc.encode(file.name);
    const { ciphertext: encNameBuffer, iv: nameIv } = await encryptFile(nameBuffer, aesKey);
    const encryptedFilename = `${nameIv}:${arrayBufferToBase64(encNameBuffer)}`;

    const wrappedKeys = [];
    for (const keyInfo of recipientKeys) {
        const pubKey = await importPublicKey(keyInfo.rsa_public_key);
        const encryptedAESKey = await encryptAESKeyWithRSA(aesKey, pubKey);
        wrappedKeys.push({
            key_type: 'RSA',
            recipient_id: keyInfo.recipient_id,
            encrypted_key: encryptedAESKey,
            permissions: keyInfo.permissions
        });
    }

    const formData = new FormData();
    const encryptedBlob = new Blob([ciphertext], { type: 'application/octet-stream' });
    formData.append('file', encryptedBlob, 'encrypted.bin');
    formData.append('encrypted_filename', encryptedFilename);
    formData.append('iv', iv);
    formData.append('keys', JSON.stringify(wrappedKeys));
    formData.append('document_id', documentId);

    const res = await axios.post(`${API_BASE}/documents/`, formData, {
        headers: {
            ...getAuthHeaders(),
            'Content-Type': 'multipart/form-data'
        }
    });

    return res.data;
};
