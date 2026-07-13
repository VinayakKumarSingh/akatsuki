import React, { useState, useEffect } from 'react';
import { fetchPublicUsers, uploadEncryptedDocument, uploadDocumentVersion, createAuditLog, fetchMyKeys } from '../api/documents';
import axios from 'axios';
import { 
  decryptGroupKeyWithRSA, 
  encryptAESKeyWithGroupKey,
  generateAESKey,
  encryptFile,
  arrayBufferToBase64,
  importPublicKey,
  encryptAESKeyWithRSA
} from '../utils/crypto';

export default function UploadModal({ onClose, onUploadSuccess, documentToVersion, unlockedPrivateKey }) {
  const [users, setUsers] = useState([]);
  const [groups, setGroups] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [selectedGroup, setSelectedGroup] = useState(null);
  const [shareType, setShareType] = useState('USER'); // 'USER' or 'GROUP'
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const [permissions, setPermissions] = useState('DOWNLOAD');

  // Vault unlocking state
  const [password, setPassword] = useState('');
  const [localPrivateKey, setLocalPrivateKey] = useState(unlockedPrivateKey);

  const isVersionMode = !!documentToVersion;
  const token = localStorage.getItem('access_token');
  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => {
    if (!isVersionMode) {
      loadUsers();
      loadGroups();
    }
  }, [isVersionMode]);

  const loadUsers = async () => {
    try {
      const data = await fetchPublicUsers();
      setUsers(data);
    } catch (err) {
      setError('Failed to load user directory.');
    }
  };

  const loadGroups = async () => {
    try {
      const res = await axios.get('/api/groups/', { headers });
      setGroups(res.data);
    } catch (err) {
      setError('Failed to load groups list.');
    }
  };

  const handleUnlock = async (e) => {
    e.preventDefault();
    if (!password) return;
    setLoading(true);
    setError('');
    try {
      const myKeys = await fetchMyKeys();
      const saltBuffer = new Uint8Array(
        window.atob(myKeys.salt).split('').map(c => c.charCodeAt(0))
      ).buffer;
      
      const { deriveKeyFromPassword, unwrapPrivateKey } = await import('../utils/crypto');
      const derivedKey = await deriveKeyFromPassword(password, saltBuffer);
      const [privIvBase64, privEncBase64] = myKeys.encrypted_rsa_private_key.split(':');
      const rsaPrivateKey = await unwrapPrivateKey(privEncBase64, privIvBase64, derivedKey);
      
      setLocalPrivateKey(rsaPrivateKey);
      setPassword('');
    } catch (err) {
      setError('Incorrect Master Password.');
    } finally {
      setLoading(false);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files) {
      const droppedFiles = Array.from(e.dataTransfer.files);
      if (isVersionMode) {
        setFiles([droppedFiles[0]]);
      } else {
        setFiles(prev => [...prev, ...droppedFiles]);
      }
    }
  };

  const handleFileSelect = (e) => {
    if (e.target.files) {
      const selectedFiles = Array.from(e.target.files);
      if (isVersionMode) {
        setFiles([selectedFiles[0]]);
      } else {
        setFiles(prev => [...prev, ...selectedFiles]);
      }
    }
  };

  const removeFile = (indexToRemove) => {
    setFiles(prev => prev.filter((_, idx) => idx !== indexToRemove));
  };

  const handleUpload = async (e) => {
    e.preventDefault();
    if (files.length === 0) {
      setError('Please select at least one file.');
      return;
    }

    if (!isVersionMode) {
      if (shareType === 'USER' && !selectedUser) {
        setError('Please select a recipient user.');
        return;
      }
      if (shareType === 'GROUP' && !selectedGroup) {
        setError('Please select a recipient group.');
        return;
      }
      if (shareType === 'GROUP' && !localPrivateKey) {
        setError('Please unlock your private key first to encrypt for groups.');
        return;
      }
    }

    setLoading(true);
    setError('');
    try {
      if (isVersionMode) {
        // Upload Version Mode (always RSA/GRP inheritance)
        const versions = documentToVersion.versions || [];
        const latestVersion = versions.length > 0
          ? [...versions].sort((a, b) => b.version_number - a.version_number)[0]
          : null;
        
        if (!latestVersion) {
          throw new Error("No active version found on this document.");
        }

        // Fetch recipients (owner + users)
        const recipientIds = (latestVersion.access_keys || [])
          .map(k => k.recipient)
          .filter(Boolean);
        recipientIds.push(documentToVersion.owner);

        const resKeys = await axios.get(`/api/keys/public/?user_ids=${recipientIds.join(',')}`, { headers });
        const newWrappedKeys = [];
        const aesKey = await generateAESKey();

        // Encrypt file & filename
        const fileBuffer = await files[0].arrayBuffer();
        const { ciphertext, iv } = await encryptFile(fileBuffer, aesKey);

        const enc = new TextEncoder();
        const nameBuffer = enc.encode(files[0].name);
        const { ciphertext: encNameBuffer, iv: nameIv } = await encryptFile(nameBuffer, aesKey);
        const encryptedFilename = `${nameIv}:${arrayBufferToBase64(encNameBuffer)}`;

        // Wrap for users (RSA)
        for (const user of resKeys.data) {
          let perm = 'DOWNLOAD';
          if (user.id !== documentToVersion.owner) {
            const existingKey = latestVersion.access_keys.find(k => k.recipient === user.id);
            perm = existingKey ? existingKey.permissions : 'DOWNLOAD';
          }
          const pubKey = await importPublicKey(user.rsa_public_key);
          const wrapped = await encryptAESKeyWithRSA(aesKey, pubKey);
          newWrappedKeys.push({
            key_type: 'RSA',
            recipient_id: user.id,
            encrypted_key: wrapped,
            permissions: perm
          });
        }

        // Wrap for groups (GRP)
        const groupAccessKeys = (latestVersion.access_keys || []).filter(k => k.key_type === 'GRP' && k.group);
        for (const gk of groupAccessKeys) {
          const groupDetailRes = await axios.get(`/api/groups/${gk.group}/`, { headers });
          const myMembership = groupDetailRes.data.memberships.find(m => m.user === localStorage.getItem('user_id'));
          if (!myMembership) continue;
          
          const groupSymmetricKey = await decryptGroupKeyWithRSA(myMembership.encrypted_group_key, localPrivateKey);
          const wrapped = await encryptAESKeyWithGroupKey(aesKey, groupSymmetricKey);
          newWrappedKeys.push({
            key_type: 'GRP',
            group_id: gk.group,
            encrypted_key: wrapped,
            permissions: gk.permissions
          });
        }

        // Upload version
        const formData = new FormData();
        const encryptedBlob = new Blob([ciphertext], { type: 'application/octet-stream' });
        formData.append('file', encryptedBlob, 'encrypted.bin');
        formData.append('encrypted_filename', encryptedFilename);
        formData.append('iv', iv);
        formData.append('keys', JSON.stringify(newWrappedKeys));
        formData.append('document_id', documentToVersion.id);

        const resDoc = await axios.post('/api/documents/', formData, {
          headers: { ...headers, 'Content-Type': 'multipart/form-data' }
        });

        await createAuditLog("UPLOAD", resDoc.data.id, `Uploaded new version (v${latestVersion.version_number + 1})`);
      } else {
        // Regular Upload Mode
        const newWrappedKeys = [];
        const aesKey = await generateAESKey();

        // Encrypt file & filename
        const fileBuffer = await files[0].arrayBuffer();
        const { ciphertext, iv } = await encryptFile(fileBuffer, aesKey);

        const enc = new TextEncoder();
        const nameBuffer = enc.encode(files[0].name);
        const { ciphertext: encNameBuffer, iv: nameIv } = await encryptFile(nameBuffer, aesKey);
        const encryptedFilename = `${nameIv}:${arrayBufferToBase64(encNameBuffer)}`;

        // Wrap for Owner (myself)
        const myKeys = await fetchMyKeys();
        const myPubKey = await importPublicKey(myKeys.rsa_public_key);
        const ownerWrapped = await encryptAESKeyWithRSA(aesKey, myPubKey);
        newWrappedKeys.push({
          key_type: 'RSA',
          recipient_id: myKeys.user_id,
          encrypted_key: ownerWrapped,
          permissions: 'DOWNLOAD'
        });

        if (shareType === 'USER') {
          const recipientPubKey = await importPublicKey(selectedUser.rsa_public_key);
          const wrapped = await encryptAESKeyWithRSA(aesKey, recipientPubKey);
          newWrappedKeys.push({
            key_type: 'RSA',
            recipient_id: selectedUser.id,
            encrypted_key: wrapped,
            permissions: permissions
          });
        } else {
          // Find our membership in selected group
          const myMembership = selectedGroup.memberships.find(m => m.user === myKeys.user_id);
          if (!myMembership) {
            throw new Error("You are not a member of the selected group.");
          }
          const groupSymmetricKey = await decryptGroupKeyWithRSA(myMembership.encrypted_group_key, localPrivateKey);
          const wrapped = await encryptAESKeyWithGroupKey(aesKey, groupSymmetricKey);
          newWrappedKeys.push({
            key_type: 'GRP',
            group_id: selectedGroup.id,
            encrypted_key: wrapped,
            permissions: permissions
          });
        }

        // Upload
        const formData = new FormData();
        const encryptedBlob = new Blob([ciphertext], { type: 'application/octet-stream' });
        formData.append('file', encryptedBlob, 'encrypted.bin');
        formData.append('encrypted_filename', encryptedFilename);
        formData.append('iv', iv);
        formData.append('keys', JSON.stringify(newWrappedKeys));

        const resDoc = await axios.post('/api/documents/', formData, {
          headers: { ...headers, 'Content-Type': 'multipart/form-data' }
        });

        const shareName = shareType === 'USER' ? selectedUser.username : selectedGroup.name;
        await createAuditLog(
          "UPLOAD", 
          resDoc.data.id, 
          `Uploaded and shared document with ${shareType.toLowerCase()} "${shareName}"`
        );
      }

      onUploadSuccess();
    } catch (err) {
      setError(err.message || 'Encryption or Upload failed.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="glass-panel modal-content" style={{ padding: '30px', maxWidth: '550px', width: '100%', maxHeight: '90vh', overflowY: 'auto' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px' }}>
          <h3 className="gradient-text">{isVersionMode ? 'Upload New Version' : 'Upload Secure Files'}</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#fff', fontSize: '1.5rem', cursor: 'pointer' }}>&times;</button>
        </div>

        {error && <div className="error-text" style={{ marginBottom: '16px' }}>{error}</div>}

        {/* Vault Unlock (Only needed for Group share/inheritance if locked) */}
        {!isVersionMode && shareType === 'GROUP' && !localPrivateKey && (
          <form onSubmit={handleUnlock} className="glass-panel" style={{ padding: '16px', marginBottom: '20px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--glass-border)' }}>
            <p style={{ color: '#94a3b8', fontSize: '0.85rem', marginBottom: '12px' }}>
              Enter your Master Password to decrypt and wrap keys for the selected group:
            </p>
            <div style={{ display: 'flex', gap: '10px' }}>
              <input 
                type="password" 
                placeholder="Master Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                style={{
                  background: 'var(--input-bg)',
                  border: '1px solid var(--glass-border)',
                  borderRadius: '6px',
                  padding: '8px 12px',
                  color: '#fff',
                  fontSize: '0.875rem',
                  flex: 1
                }}
                required
              />
              <button type="submit" className="btn btn-primary" disabled={loading}>
                Unlock
              </button>
            </div>
          </form>
        )}

        <form onSubmit={handleUpload}>
          <div 
            style={{
              border: `2px dashed ${isDragging ? 'var(--accent-color)' : 'var(--glass-border)'}`,
              borderRadius: '12px',
              padding: '40px 20px',
              textAlign: 'center',
              background: isDragging ? 'rgba(99, 102, 241, 0.05)' : 'var(--input-bg)',
              cursor: 'pointer',
              marginBottom: '20px',
              transition: 'all 0.3s ease'
            }}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => document.getElementById('file-input').click()}
          >
            <div style={{ fontSize: '2.5rem', marginBottom: '12px' }}>📁</div>
            <p style={{ color: '#fff', fontWeight: '500', marginBottom: '4px' }}>Drag & drop {isVersionMode ? 'your file' : 'files'} here</p>
            <p style={{ color: '#64748b', fontSize: '0.85rem' }}>or click to browse from device</p>
            <input 
              id="file-input"
              type="file" 
              multiple={false} // Restrict to single upload for cleaner rekeying
              onChange={handleFileSelect}
              style={{ display: 'none' }}
            />
          </div>

          {files.length > 0 && (
            <div style={{ marginBottom: '24px', maxHeight: '150px', overflowY: 'auto', background: 'rgba(0,0,0,0.1)', borderRadius: '8px', padding: '10px' }}>
              <p style={{ fontSize: '0.85rem', color: '#94a3b8', marginBottom: '8px', fontWeight: '600' }}>Files to Encrypt ({files.length}):</p>
              {files.map((file, idx) => (
                <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 8px', borderBottom: '1px solid var(--glass-border)', fontSize: '0.875rem' }}>
                  <span style={{ color: '#fff', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '80%' }}>📄 {file.name}</span>
                  <button 
                    type="button" 
                    onClick={(e) => { e.stopPropagation(); removeFile(idx); }}
                    style={{ background: 'none', border: 'none', color: 'var(--danger-color)', cursor: 'pointer', fontSize: '1.1rem' }}
                  >
                    &times;
                  </button>
                </div>
              ))}
            </div>
          )}

          {!isVersionMode && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '15px', marginBottom: '32px' }}>
              <div style={{ display: 'flex', gap: '10px' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#fff', fontSize: '0.85rem', cursor: 'pointer' }}>
                  <input type="radio" checked={shareType === 'USER'} onChange={() => setShareType('USER')} /> Share with User
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#fff', fontSize: '0.85rem', cursor: 'pointer' }}>
                  <input type="radio" checked={shareType === 'GROUP'} onChange={() => setShareType('GROUP')} /> Share with Group
                </label>
              </div>

              <div style={{ display: 'flex', gap: '15px' }}>
                <div className="input-group" style={{ flex: 1, marginBottom: 0 }}>
                  <label>Recipient {shareType === 'USER' ? 'User' : 'Group'}</label>
                  {shareType === 'USER' ? (
                    <select 
                      className="select-input"
                      style={{ width: '100%' }}
                      value={selectedUser ? selectedUser.id : ''} 
                      onChange={(e) => {
                        const u = users.find(user => user.id === e.target.value);
                        setSelectedUser(u);
                      }}
                      required
                    >
                      <option value="" disabled>-- Select Recipient User --</option>
                      {users.map(u => (
                        <option key={u.id} value={u.id}>{u.username}</option>
                      ))}
                    </select>
                  ) : (
                    <select 
                      className="select-input"
                      style={{ width: '100%' }}
                      value={selectedGroup ? selectedGroup.id : ''} 
                      onChange={(e) => {
                        const g = groups.find(group => group.id === e.target.value);
                        setSelectedGroup(g);
                      }}
                      required
                    >
                      <option value="" disabled>-- Select Recipient Group --</option>
                      {groups.map(g => (
                        <option key={g.id} value={g.id}>{g.name}</option>
                      ))}
                    </select>
                  )}
                </div>

                <div className="input-group" style={{ width: '160px', marginBottom: 0 }}>
                  <label>Permissions</label>
                  <select 
                    className="select-input"
                    style={{ width: '100%' }}
                    value={permissions}
                    onChange={(e) => setPermissions(e.target.value)}
                    required
                  >
                    <option value="VIEW_ONLY">View Only</option>
                    <option value="DOWNLOAD">Download</option>
                    <option value="SHARE">Share</option>
                  </select>
                </div>
              </div>
            </div>
          )}

          <div style={{ display: 'flex', gap: '10px' }}>
            <button type="button" className="btn" style={{ flex: 1, background: 'rgba(255,255,255,0.1)', color: 'white' }} onClick={onClose}>
              Cancel
            </button>
            <button 
              type="submit" 
              className="btn btn-primary" 
              style={{ flex: 1 }} 
              disabled={loading || files.length === 0 || (!isVersionMode && shareType === 'USER' && !selectedUser) || (!isVersionMode && shareType === 'GROUP' && !selectedGroup) || (!isVersionMode && shareType === 'GROUP' && !localPrivateKey)}
            >
              {loading ? 'Encrypting & Uploading...' : isVersionMode ? 'Upload Version' : 'Encrypt & Upload'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
