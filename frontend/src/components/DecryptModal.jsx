import React, { useState } from 'react';
import { fetchMyKeys, downloadCiphertext } from '../api/documents';
import {
  deriveKeyFromPassword,
  unwrapPrivateKey,
  decryptAESKeyWithRSA,
  decryptFile,
  decryptString
} from '../utils/crypto';

export default function DecryptModal({ document, onClose }) {
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  const handleDecrypt = async (e) => {
    e.preventDefault();
    if (!password) {
      setError('Password is required to unlock your private key.');
      return;
    }

    setLoading(true);
    setError('');
    setSuccessMsg('');

    try {
      // 1. Fetch User's Encrypted Private Key & Salt
      const myKeys = await fetchMyKeys();
      if (!myKeys || !myKeys.encrypted_rsa_private_key) {
        throw new Error("No private key found on server. Did you register properly?");
      }

      // 2. Derive Password Key
      const saltBuffer = new Uint8Array(
        window.atob(myKeys.salt).split('').map(c => c.charCodeAt(0))
      ).buffer;
      const derivedKey = await deriveKeyFromPassword(password, saltBuffer);

      // 3. Unwrap RSA Private Key
      const [privIvBase64, privEncBase64] = myKeys.encrypted_rsa_private_key.split(':');
      const rsaPrivateKey = await unwrapPrivateKey(privEncBase64, privIvBase64, derivedKey);

      // 4. Find the correct Access Key for this document
      let aesKey = null;
      for (const keyObj of document.access_keys) {
        if (keyObj.key_type === 'RSA') {
          try {
            aesKey = await decryptAESKeyWithRSA(keyObj.encrypted_key, rsaPrivateKey);
            break; // Found the right key!
          } catch (e) {
            console.error("Decryption failed for a key:", e);
            // Not for us or corrupted
          }
        }
      }

      if (!aesKey) {
        throw new Error("Could not decrypt the AES key. Are you sure you are the recipient? Detailed error logged to console.");
      }

      // 5. Download Ciphertext
      const ciphertextBuffer = await downloadCiphertext(document.file_path);

      // 6. Decrypt File
      const decryptedBuffer = await decryptFile(ciphertextBuffer, document.iv, aesKey);

      // 7. Decrypt Filename
      let originalFilename = "decrypted_file.bin";
      if (document.encrypted_filename && document.encrypted_filename.includes(':')) {
        const [nameIv, nameEnc] = document.encrypted_filename.split(':');
        originalFilename = await decryptString(nameEnc, nameIv, aesKey);
      }

      // 8. Trigger Browser Download
      const blob = new Blob([decryptedBuffer], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = window.document.createElement('a');
      a.href = url;
      a.download = originalFilename;
      window.document.body.appendChild(a);
      a.click();
      window.document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setSuccessMsg('Decryption successful! File is downloading.');
      setTimeout(onClose, 2000);
      
    } catch (err) {
      console.error(err);
      setError(err.message || 'Decryption failed. Incorrect password?');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="glass-panel modal-content" style={{ padding: '30px', maxWidth: '400px', width: '100%' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px' }}>
          <h3 className="gradient-text">Unlock Document</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#fff', fontSize: '1.5rem', cursor: 'pointer' }}>&times;</button>
        </div>

        <p style={{ color: '#94a3b8', marginBottom: '20px', fontSize: '0.9rem' }}>
          Please enter your Master Password to locally unlock your Private Key and decrypt this file.
        </p>

        {error && <div className="error-text">{error}</div>}
        {successMsg && <div style={{ color: 'var(--success-color)', marginBottom: '16px', fontSize: '0.875rem' }}>{successMsg}</div>}

        <form onSubmit={handleDecrypt}>
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
              {loading ? 'Decrypting...' : 'Decrypt & Download'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
