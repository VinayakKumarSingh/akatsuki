import React, { useState } from 'react';
import axios from 'axios';
import { fetchMyKeys, downloadCiphertext, createAuditLog } from '../api/documents';
import {
  deriveKeyFromPassword,
  unwrapPrivateKey,
  decryptAESKeyWithRSA,
  decryptFile,
  decryptString,
  decryptGroupKeyWithRSA,
  decryptAESKeyWithGroupKey
} from '../utils/crypto';
export default function VersionHistoryModal({ document, cachedPrivateKey, currentUserId, myGroups = [], onClose, onUploadNewVersion }) {
  const [password, setPassword] = useState('');
  const [unlockedKey, setUnlockedKey] = useState(cachedPrivateKey);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const isOwner = document.owner === currentUserId;

  const getDecryptedAESKey = async (version, rsaPrivateKey) => {
    let aesKey = null;
    const currentUserId = localStorage.getItem('user_id');
    for (const keyObj of (version.access_keys || [])) {
      if (keyObj.key_type === 'RSA' && keyObj.recipient === currentUserId) {
        try {
          aesKey = await decryptAESKeyWithRSA(keyObj.encrypted_key, rsaPrivateKey);
          break;
        } catch (err) {
          console.error("Key decryption failed:", err);
        }
      } else if (keyObj.key_type === 'GRP' && keyObj.group) {
        try {
          const token = localStorage.getItem('access_token');
          const res = await axios.get(`/api/groups/${keyObj.group}/`, {
            headers: { Authorization: `Bearer ${token}` }
          });
          const myMembership = res.data.memberships.find(m => m.user === currentUserId);
          if (myMembership) {
            const groupSymmetricKey = await decryptGroupKeyWithRSA(myMembership.encrypted_group_key, rsaPrivateKey);
            aesKey = await decryptAESKeyWithGroupKey(keyObj.encrypted_key, groupSymmetricKey);
            break;
          }
        } catch (err) {
          console.error("Group key decryption failed:", err);
        }
      }
    }
    return aesKey;
  };

  const unlockPrivateKey = async () => {
    if (unlockedKey) return unlockedKey;
    if (!password) {
      setError("Master Password is required to unlock your key.");
      return null;
    }
    try {
      const myKeys = await fetchMyKeys();
      const saltBuffer = new Uint8Array(
        window.atob(myKeys.salt).split('').map(c => c.charCodeAt(0))
      ).buffer;
      const derivedKey = await deriveKeyFromPassword(password, saltBuffer);
      const [privIvBase64, privEncBase64] = myKeys.encrypted_rsa_private_key.split(':');
      const rsaPrivateKey = await unwrapPrivateKey(privEncBase64, privIvBase64, derivedKey);
      setUnlockedKey(rsaPrivateKey);
      setPassword('');
      return rsaPrivateKey;
    } catch (err) {
      setError("Incorrect Master Password.");
      return null;
    }
  };

  const handleAction = async (version, actionType) => {
    setLoading(true);
    setError('');
    try {
      // 1. Ensure private key is unlocked
      const rsaPrivateKey = await unlockPrivateKey();
      if (!rsaPrivateKey) return;

      // 2. Find AES key for this version
      const aesKey = await getDecryptedAESKey(version, rsaPrivateKey);
      if (!aesKey) {
        throw new Error("Could not decrypt the AES key for this version. Access denied.");
      }

      // 3. Download encrypted bytes
      const ciphertextBuffer = await downloadCiphertext(document.id, version.id);

      // 4. Decrypt file
      const decryptedBuffer = await decryptFile(ciphertextBuffer, version.iv, aesKey);

      // 5. Decrypt filename
      let originalFilename = "decrypted_file.bin";
      if (document.encrypted_filename && document.encrypted_filename.includes(':')) {
        const [nameIv, nameEnc] = document.encrypted_filename.split(':');
        originalFilename = await decryptString(nameEnc, nameIv, aesKey);
      }

      if (actionType === 'DOWNLOAD') {
        // Trigger browser download
        const blob = new Blob([decryptedBuffer], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = window.document.createElement('a');
        a.href = url;
        a.download = originalFilename;
        window.document.body.appendChild(a);
        a.click();
        window.document.body.removeChild(a);
        URL.revokeObjectURL(url);

        await createAuditLog("DOWNLOAD", document.id, `Decrypted and downloaded version v${version.version_number}: ${originalFilename}`);
      } else if (actionType === 'PREVIEW') {
        const extension = originalFilename.split('.').pop().toLowerCase();
        let mimeType = 'application/octet-stream';
        if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'].includes(extension)) {
          mimeType = `image/${extension === 'jpg' ? 'jpeg' : extension === 'svg' ? 'svg+xml' : extension}`;
        } else if (extension === 'pdf') {
          mimeType = 'application/pdf';
        } else if (['txt', 'log', 'json', 'js', 'py', 'md', 'html', 'css'].includes(extension)) {
          mimeType = 'text/plain';
        }

        const blob = new Blob([decryptedBuffer], { type: mimeType });
        const url = URL.createObjectURL(blob);
        
        // Open the blob URL in a new browser tab for native previewing
        const newTab = window.open(url, '_blank');
        if (newTab) {
          newTab.focus();
        } else {
          alert('Popup blocker prevented opening the preview in a new tab. Please allow popups for this site.');
        }

        // Revoke the object URL after 10 seconds to allow the browser to load it
        setTimeout(() => {
          URL.revokeObjectURL(url);
        }, 10000);

        await createAuditLog("PREVIEW", document.id, `Previewed version v${version.version_number} in a new tab: ${originalFilename}`);
      }
    } catch (err) {
      console.error(err);
      setError(err.message || "Action failed.");
    } finally {
      setLoading(false);
    }
  };

  const getVersionPermission = (version) => {
    if (isOwner) return 'OWNER';
    
    // Find all access keys that apply to the current user
    const applicableKeys = (version.access_keys || []).filter(k => {
      if (k.recipient === currentUserId) return true;
      if (k.key_type === 'GRP' && k.group && myGroups.some(g => g.id === k.group)) return true;
      return false;
    });

    if (applicableKeys.length === 0) return 'NONE';

    // Order of priority: SHARE > DOWNLOAD > VIEW_ONLY
    const perms = applicableKeys.map(k => k.permissions);
    if (perms.includes('SHARE')) return 'SHARE';
    if (perms.includes('DOWNLOAD')) return 'DOWNLOAD';
    if (perms.includes('VIEW_ONLY')) return 'VIEW_ONLY';
    return 'NONE';
  };

  const sortedVersions = [...(document.versions || [])].sort((a, b) => b.version_number - a.version_number);

  return (
    <div className="modal-overlay" style={{ zIndex: 1000 }}>
      <div className="glass-panel modal-content" style={{ padding: '30px', maxWidth: '600px', width: '100%', maxHeight: '85vh', overflowY: 'auto' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px', alignItems: 'center' }}>
          <h3 className="gradient-text">📜 Document Version History</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#fff', fontSize: '1.5rem', cursor: 'pointer' }}>&times;</button>
        </div>

        {error && <div className="error-text">{error}</div>}

        {isOwner && (
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '20px' }}>
            <button className="btn btn-primary" onClick={() => { onClose(); onUploadNewVersion(document); }}>
              + Upload New Version
            </button>
          </div>
        )}

        {!unlockedKey && (
          <div className="glass-panel" style={{ padding: '16px', marginBottom: '20px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--glass-border)' }}>
            <p style={{ color: '#94a3b8', fontSize: '0.85rem', marginBottom: '12px' }}>
              Enter your Master Password to unlock decryption keys:
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
                  padding: '6px 12px',
                  color: '#fff',
                  fontSize: '0.875rem',
                  flex: 1
                }}
              />
              <button className="btn btn-primary" style={{ padding: '6px 16px' }} onClick={unlockPrivateKey} disabled={loading}>
                Unlock
              </button>
            </div>
          </div>
        )}

        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {sortedVersions.map((version, index) => {
            const perm = getVersionPermission(version);
            const isDownloadable = perm === 'OWNER' || perm === 'DOWNLOAD' || perm === 'SHARE';
            const isPreviewable = perm === 'OWNER' || perm === 'DOWNLOAD' || perm === 'SHARE' || perm === 'VIEW_ONLY';
            const hasAccess = perm !== 'NONE';

            return (
              <div key={version.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px', background: 'rgba(0,0,0,0.2)', borderRadius: '8px', border: '1px solid var(--glass-border)' }}>
                <div>
                  <div style={{ fontWeight: '600', color: '#fff' }}>
                    Version {version.version_number} {index === 0 && <span style={{ color: 'var(--accent-color)', fontSize: '0.75rem', marginLeft: '6px', background: 'rgba(99, 102, 241, 0.1)', padding: '2px 6px', borderRadius: '4px' }}>Latest</span>}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: '4px' }}>
                    Uploaded: {new Date(version.created_at).toLocaleString()}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '2px' }}>
                    Permission: <span style={{ color: hasAccess ? 'var(--success-color)' : 'var(--danger-color)' }}>{perm}</span>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '8px' }}>
                  <button 
                    className="btn" 
                    style={{ padding: '6px 12px', fontSize: '0.8rem', background: isPreviewable ? 'rgba(255,255,255,0.1)' : 'rgba(255,255,255,0.02)', color: isPreviewable ? '#fff' : '#64748b' }}
                    onClick={() => handleAction(version, 'PREVIEW')}
                    disabled={loading || !isPreviewable}
                  >
                    👁️ Preview
                  </button>
                  <button 
                    className="btn" 
                    style={{ padding: '6px 12px', fontSize: '0.8rem', background: isDownloadable ? 'rgba(99, 102, 241, 0.2)' : 'rgba(255,255,255,0.02)', color: isDownloadable ? '#fff' : '#64748b' }}
                    onClick={() => handleAction(version, 'DOWNLOAD')}
                    disabled={loading || !isDownloadable}
                  >
                    Decrypt & Download
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
