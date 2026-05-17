import React, { useState } from 'react';
import { fetchMyKeys } from '../api/documents';
import {
  deriveKeyFromPassword,
  unwrapPrivateKey,
  decryptAESKeyWithRSA,
  decryptString
} from '../utils/crypto';

export default function UnlockVaultModal({ documents, onClose, onUnlocked }) {
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleUnlock = async (e) => {
    e.preventDefault();
    if (!password) return;

    setLoading(true);
    setError('');

    try {
      // 1. Fetch User's Encrypted Private Key & Salt
      const myKeys = await fetchMyKeys();
      
      const saltBuffer = new Uint8Array(
        window.atob(myKeys.salt).split('').map(c => c.charCodeAt(0))
      ).buffer;
      const derivedKey = await deriveKeyFromPassword(password, saltBuffer);

      // 2. Unwrap RSA Private Key
      const [privIvBase64, privEncBase64] = myKeys.encrypted_rsa_private_key.split(':');
      const rsaPrivateKey = await unwrapPrivateKey(privEncBase64, privIvBase64, derivedKey);

      // 3. Decrypt all filenames
      const unlockedNames = {};
      
      for (const doc of documents) {
        if (!doc.encrypted_filename || !doc.encrypted_filename.includes(':')) continue;

        // Find the right access key
        let aesKey = null;
        for (const keyObj of doc.access_keys) {
          if (keyObj.key_type === 'RSA') {
            try {
              aesKey = await decryptAESKeyWithRSA(keyObj.encrypted_key, rsaPrivateKey);
              break;
            } catch (err) {
              // Ignore wrong keys
            }
          }
        }

        if (aesKey) {
          try {
            const [nameIv, nameEnc] = doc.encrypted_filename.split(':');
            const realName = await decryptString(nameEnc, nameIv, aesKey);
            unlockedNames[doc.id] = realName;
          } catch (e) {
            console.error("Filename decryption failed for doc", doc.id);
          }
        }
      }

      // Return the unlocked names and the private key (so we don't need password again to download)
      onUnlocked(unlockedNames, rsaPrivateKey);
      
    } catch (err) {
      console.error(err);
      setError(err.message || 'Unlock failed. Incorrect Master Password?');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="glass-panel modal-content" style={{ padding: '30px', maxWidth: '400px', width: '100%' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px' }}>
          <h3 className="gradient-text">Unlock Vault</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#fff', fontSize: '1.5rem', cursor: 'pointer' }}>&times;</button>
        </div>

        <p style={{ color: '#94a3b8', marginBottom: '20px', fontSize: '0.9rem' }}>
          Enter your Master Password to decrypt file metadata and reveal original filenames.
        </p>

        {error && <div className="error-text">{error}</div>}

        <form onSubmit={handleUnlock}>
          <div className="input-group" style={{ marginBottom: '32px' }}>
            <label>Master Password</label>
            <input 
              type="password" 
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required 
            />
          </div>

          <div style={{ display: 'flex', gap: '10px' }}>
            <button type="button" className="btn" style={{ flex: 1, background: 'rgba(255,255,255,0.1)', color: 'white' }} onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" style={{ flex: 1 }} disabled={loading || !password}>
              {loading ? 'Decrypting Vault...' : 'Unlock Vault'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
