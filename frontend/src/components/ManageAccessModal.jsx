import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  decryptAESKeyWithRSA, 
  decryptFile, 
  decryptString,
  generateAESKey,
  encryptFile,
  arrayBufferToBase64,
  importPublicKey,
  encryptAESKeyWithRSA,
  decryptGroupKeyWithRSA,
  encryptAESKeyWithGroupKey
} from '../utils/crypto';
import { downloadCiphertext, fetchMyKeys, createAuditLog } from '../api/documents';

export default function ManageAccessModal({ document, unlockedPrivateKey, onClose, onAccessUpdated }) {
  const [users, setUsers] = useState([]);
  const [groups, setGroups] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [selectedGroup, setSelectedGroup] = useState(null);
  const [shareType, setShareType] = useState('USER'); // 'USER' or 'GROUP'
  const [permissions, setPermissions] = useState('DOWNLOAD');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [password, setPassword] = useState('');
  const [localPrivateKey, setLocalPrivateKey] = useState(unlockedPrivateKey);

  const token = localStorage.getItem('access_token');
  const headers = { Authorization: `Bearer ${token}` };

  const versions = document.versions || [];
  const latestVersion = versions.length > 0
    ? [...versions].sort((a, b) => b.version_number - a.version_number)[0]
    : null;

  useEffect(() => {
    loadPublicUsers();
    loadGroups();
  }, []);

  const loadPublicUsers = async () => {
    try {
      const res = await axios.get('/api/keys/public/', { headers });
      setUsers(res.data);
    } catch (err) {
      setError('Failed to fetch public user directory.');
    }
  };

  const loadGroups = async () => {
    try {
      const res = await axios.get('/api/groups/', { headers });
      setGroups(res.data);
    } catch (err) {
      setError('Failed to fetch groups directory.');
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

  const handleGrantAccess = async (e) => {
    e.preventDefault();
    if (!latestVersion) return;
    if (!localPrivateKey) {
      setError('Unlock your private key first.');
      return;
    }

    if (shareType === 'USER' && !selectedUser) {
      setError('Please select a user to share with.');
      return;
    }
    if (shareType === 'GROUP' && !selectedGroup) {
      setError('Please select a group to share with.');
      return;
    }

    setLoading(true);
    setError('');
    setSuccess('');

    try {
      // 1. Locate current AES key by decrypting the owner's wrapped key in latest version
      const ownerKey = latestVersion.access_keys.find(k => k.recipient === document.owner);
      if (!ownerKey) {
        throw new Error("Could not find owner's key mapping in latest version.");
      }
      const currentAesKey = await decryptAESKeyWithRSA(ownerKey.encrypted_key, localPrivateKey);

      let encryptedAESKey = '';
      const payload = { permissions };

      if (shareType === 'USER') {
        const pubKey = await importPublicKey(selectedUser.rsa_public_key);
        encryptedAESKey = await encryptAESKeyWithRSA(currentAesKey, pubKey);
        payload.recipient_id = selectedUser.id;
      } else {
        // Find our membership in group
        const myKeys = await fetchMyKeys();
        const myMembership = selectedGroup.memberships.find(m => m.user === myKeys.user_id);
        if (!myMembership) {
          throw new Error("You are not a member of the selected group.");
        }
        const groupSymmetricKey = await decryptGroupKeyWithRSA(myMembership.encrypted_group_key, localPrivateKey);
        encryptedAESKey = await encryptAESKeyWithGroupKey(currentAesKey, groupSymmetricKey);
        payload.group_id = selectedGroup.id;
      }

      payload.encrypted_key = encryptedAESKey;

      // POST to grant access
      await axios.post(`/api/documents/${document.id}/grant_access/`, payload, { headers });

      const nameStr = shareType === 'USER' ? selectedUser.username : selectedGroup.name;
      setSuccess(`Access granted successfully to ${nameStr}!`);
      
      // Log audit trail event
      await createAuditLog(
        "SHARE", 
        document.id, 
        `Granted ${permissions} access to ${shareType.toLowerCase()} "${nameStr}"`
      );

      setSelectedUser(null);
      setSelectedGroup(null);
      
      setTimeout(() => {
        onAccessUpdated();
        onClose();
      }, 2000);

    } catch (err) {
      console.error(err);
      setError(err.message || 'Failed to grant access.');
    } finally {
      setLoading(false);
    }
  };

  const handleRevoke = async (accessKey) => {
    if (!latestVersion) return;
    if (!localPrivateKey) {
      setError('Please unlock your private key first.');
      return;
    }
    const targetName = accessKey.recipient
      ? (users.find(u => u.id === accessKey.recipient)?.username || accessKey.recipient)
      : (groups.find(g => g.id === accessKey.group)?.name || `Group ID ${accessKey.group}`);
    
    if (!window.confirm(`Are you sure you want to revoke access for "${targetName}"? This will download, decrypt, generate a new key/IV, re-encrypt the file in-memory, and upload it as a new version.`)) {
      return;
    }

    setLoading(true);
    setError('');
    setSuccess('');

    try {
      // 1. Locate current AES key by decrypting the owner's wrapped key in latest version
      let currentAesKey = null;
      const ownerKey = latestVersion.access_keys.find(k => k.recipient === document.owner);
      if (!ownerKey) {
        throw new Error("Could not find owner's key mapping in latest version.");
      }
      currentAesKey = await decryptAESKeyWithRSA(ownerKey.encrypted_key, localPrivateKey);

      // 2. Download current ciphertext
      const ciphertextBuffer = await downloadCiphertext(document.id, latestVersion.id);

      // 3. Decrypt document content
      const decryptedBuffer = await decryptFile(ciphertextBuffer, latestVersion.iv, currentAesKey);

      // 4. Decrypt original filename
      let originalFilename = "decrypted_file.bin";
      if (document.encrypted_filename && document.encrypted_filename.includes(':')) {
        const [nameIv, nameEnc] = document.encrypted_filename.split(':');
        originalFilename = await decryptString(nameEnc, nameIv, currentAesKey);
      }

      // 5. Generate BRAND NEW AES key & IV for re-encryption
      const newAesKey = await generateAESKey();
      const { ciphertext: newCiphertext, iv: newIv } = await encryptFile(decryptedBuffer, newAesKey);

      // 6. Encrypt filename with the new AES key
      const enc = new TextEncoder();
      const nameBuffer = enc.encode(originalFilename);
      const { ciphertext: encNameBuffer, iv: nameIv } = await encryptFile(nameBuffer, newAesKey);
      const newEncryptedFilename = `${nameIv}:${arrayBufferToBase64(encNameBuffer)}`;

      // 7. Re-wrap the NEW AES key for the remaining recipients
      const remainingAccessKeys = latestVersion.access_keys.filter(k => k.id !== accessKey.id);
      const newWrappedKeys = [];

      for (const k of remainingAccessKeys) {
        if (k.key_type === 'RSA' && k.recipient) {
          const recipientKeysRes = await axios.get(`/api/keys/public/?user_ids=${k.recipient}`, { headers });
          if (recipientKeysRes.data.length === 0) continue;
          const pubKeyJwkStr = recipientKeysRes.data[0].rsa_public_key;
          const pubKey = await importPublicKey(pubKeyJwkStr);
          
          const wrapped = await encryptAESKeyWithRSA(newAesKey, pubKey);
          newWrappedKeys.push({
            key_type: 'RSA',
            recipient_id: k.recipient,
            encrypted_key: wrapped,
            permissions: k.permissions
          });
        } else if (k.key_type === 'GRP' && k.group) {
          const groupDetailRes = await axios.get(`/api/groups/${k.group}/`, { headers });
          const myKeys = await fetchMyKeys();
          const myMembership = groupDetailRes.data.memberships.find(m => m.user === myKeys.user_id);
          if (!myMembership) continue;
          
          const groupSymmetricKey = await decryptGroupKeyWithRSA(myMembership.encrypted_group_key, localPrivateKey);
          const wrapped = await encryptAESKeyWithGroupKey(newAesKey, groupSymmetricKey);
          newWrappedKeys.push({
            key_type: 'GRP',
            group_id: k.group,
            encrypted_key: wrapped,
            permissions: k.permissions
          });
        }
      }

      // 8. Upload the new ciphertext and keys to the /rekey/ view endpoint
      const formData = new FormData();
      const encryptedBlob = new Blob([newCiphertext], { type: 'application/octet-stream' });
      formData.append('file', encryptedBlob, 'encrypted.bin');
      formData.append('encrypted_filename', newEncryptedFilename);
      formData.append('iv', newIv);
      formData.append('keys', JSON.stringify(newWrappedKeys));
      
      if (accessKey.recipient) {
        formData.append('revoked_user_id', accessKey.recipient);
      } else if (accessKey.group) {
        formData.append('revoked_group_id', accessKey.group);
      }

      await axios.post(`/api/documents/${document.id}/rekey/`, formData, {
        headers: {
          ...headers,
          'Content-Type': 'multipart/form-data'
        }
      });

      await createAuditLog(
        "SHARE", 
        document.id, 
        `Revoked access for ${targetName}. Re-encrypted document and generated new AES key/IV client-side.`
      );

      setSuccess(`Successfully revoked access for ${targetName} and re-encrypted the document content.`);
      setTimeout(() => {
        onAccessUpdated();
        onClose();
      }, 2500);

    } catch (err) {
      console.error(err);
      setError(err.message || 'Revocation re-encryption workflow failed.');
    } finally {
      setLoading(false);
    }
  };

  // Find user list excluding document owner
  const shareableUsers = users.filter(u => u.id !== document.owner);

  return (
    <div className="modal-overlay" style={{ zIndex: 1000 }}>
      <div className="glass-panel modal-content" style={{ padding: '30px', maxWidth: '550px', width: '100%', maxHeight: '85vh', overflowY: 'auto' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px', alignItems: 'center' }}>
          <h3 className="gradient-text">🔑 Manage Document Access</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#fff', fontSize: '1.5rem', cursor: 'pointer' }}>&times;</button>
        </div>

        {error && <div className="error-text" style={{ marginBottom: '16px' }}>{error}</div>}
        {success && <div style={{ color: 'var(--success-color)', marginBottom: '16px', fontSize: '0.875rem' }}>{success}</div>}

        {!localPrivateKey && (
          <form onSubmit={handleUnlock} className="glass-panel" style={{ padding: '16px', marginBottom: '20px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--glass-border)' }}>
            <p style={{ color: '#94a3b8', fontSize: '0.85rem', marginBottom: '12px' }}>
              Enter your Master Password to decrypt and re-wrap key mappings:
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

        {/* Share Section */}
        {localPrivateKey && (
          <div style={{ background: 'rgba(0,0,0,0.15)', padding: '20px', borderRadius: '10px', border: '1px solid var(--glass-border)', marginBottom: '24px' }}>
            <h5 style={{ color: '#fff', marginBottom: '12px' }}>Grant New Access</h5>
            <form onSubmit={handleGrantAccess} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'flex', gap: '10px' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#fff', fontSize: '0.85rem', cursor: 'pointer' }}>
                  <input type="radio" checked={shareType === 'USER'} onChange={() => setShareType('USER')} /> User
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#fff', fontSize: '0.85rem', cursor: 'pointer' }}>
                  <input type="radio" checked={shareType === 'GROUP'} onChange={() => setShareType('GROUP')} /> Group
                </label>
              </div>

              <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                {shareType === 'USER' ? (
                  <select 
                    className="select-input" 
                    value={selectedUser ? selectedUser.id : ''} 
                    onChange={(e) => {
                      const u = shareableUsers.find(user => user.id === e.target.value);
                      setSelectedUser(u);
                    }}
                    required
                    style={{ flex: 1, minWidth: '150px' }}
                  >
                    <option value="" disabled>-- Select Recipient User --</option>
                    {shareableUsers.map(u => (
                      <option key={u.id} value={u.id}>{u.username}</option>
                    ))}
                  </select>
                ) : (
                  <select 
                    className="select-input" 
                    value={selectedGroup ? selectedGroup.id : ''} 
                    onChange={(e) => {
                      const g = groups.find(group => group.id === e.target.value);
                      setSelectedGroup(g);
                    }}
                    required
                    style={{ flex: 1, minWidth: '150px' }}
                  >
                    <option value="" disabled>-- Select Recipient Group --</option>
                    {groups.map(g => (
                      <option key={g.id} value={g.id}>{g.name}</option>
                    ))}
                  </select>
                )}

                <select 
                  className="select-input" 
                  value={permissions} 
                  onChange={(e) => setPermissions(e.target.value)}
                  style={{ width: '130px' }}
                >
                  <option value="VIEW_ONLY">View Only</option>
                  <option value="DOWNLOAD">Download</option>
                  <option value="SHARE">Share</option>
                </select>

                <button type="submit" className="btn btn-primary" disabled={loading}>
                  Grant
                </button>
              </div>
            </form>
          </div>
        )}

        <h4 style={{ color: '#fff', marginBottom: '12px' }}>Authorized Recipients</h4>
        {!latestVersion ? (
          <p style={{ color: '#64748b' }}>No version history found.</p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {latestVersion.access_keys.map(k => {
              const isOwner = k.recipient === document.owner;
              const displayName = k.recipient
                ? (users.find(u => u.id === k.recipient)?.username || `User ID: ${k.recipient}`)
                : (groups.find(g => g.id === k.group)?.name || `Group: ${k.group}`);

              return (
                <div 
                  key={k.id} 
                  style={{
                    padding: '14px 16px',
                    background: 'rgba(0,0,0,0.15)',
                    borderRadius: '8px',
                    border: '1px solid var(--glass-border)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center'
                  }}
                >
                  <div>
                    <div style={{ color: '#fff', fontWeight: '600' }}>
                      {displayName} {isOwner && <span style={{ color: 'var(--accent-color)', fontSize: '0.75rem', background: 'rgba(99, 102, 241, 0.1)', padding: '2px 6px', borderRadius: '4px', marginLeft: '6px' }}>Owner</span>}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: '4px' }}>
                      Key: <span style={{ color: 'var(--accent-color)' }}>{k.key_type}</span> | Permission: <span>{k.permissions}</span>
                    </div>
                  </div>

                  {!isOwner && (
                    <button 
                      className="btn" 
                      style={{ padding: '6px 12px', fontSize: '0.8rem', background: 'rgba(239, 68, 68, 0.15)', color: 'var(--danger-color)' }}
                      onClick={() => handleRevoke(k)}
                      disabled={loading || !localPrivateKey}
                    >
                      Revoke
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
