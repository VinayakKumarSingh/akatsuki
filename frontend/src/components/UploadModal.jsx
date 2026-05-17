import React, { useState, useEffect } from 'react';
import { fetchPublicUsers, uploadEncryptedDocument } from '../api/documents';

export default function UploadModal({ onClose, onUploadSuccess }) {
  const [users, setUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    const loadUsers = async () => {
      try {
        const data = await fetchPublicUsers();
        setUsers(data);
      } catch (err) {
        setError('Failed to load users.');
      }
    };
    loadUsers();
  }, []);

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!file || !selectedUser) {
      setError('Please select a file and a recipient.');
      return;
    }

    setLoading(true);
    setError('');
    try {
      await uploadEncryptedDocument(file, selectedUser.id, selectedUser.rsa_public_key);
      onUploadSuccess();
    } catch (err) {
      setError('Encryption or Upload failed.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="glass-panel modal-content" style={{ padding: '30px', maxWidth: '500px', width: '100%' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px' }}>
          <h3 className="gradient-text">Upload Secure File</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#fff', fontSize: '1.5rem', cursor: 'pointer' }}>&times;</button>
        </div>

        {error && <div className="error-text">{error}</div>}

        <form onSubmit={handleUpload}>
          <div className="input-group">
            <label>Select File</label>
            <input 
              type="file" 
              onChange={(e) => setFile(e.target.files[0])}
              required 
            />
          </div>

          <div className="input-group" style={{ marginBottom: '32px' }}>
            <label>Recipient (End-to-End Encrypted)</label>
            <select 
              className="select-input"
              value={selectedUser ? selectedUser.id : ''} 
              onChange={(e) => {
                const u = users.find(user => user.id === e.target.value);
                setSelectedUser(u);
              }}
              required
            >
              <option value="" disabled>-- Choose Recipient --</option>
              {users.map(u => (
                <option key={u.id} value={u.id}>{u.username}</option>
              ))}
            </select>
          </div>

          <div style={{ display: 'flex', gap: '10px' }}>
            <button type="button" className="btn" style={{ flex: 1, background: 'rgba(255,255,255,0.1)', color: 'white' }} onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" style={{ flex: 1 }} disabled={loading || !file || !selectedUser}>
              {loading ? 'Encrypting...' : 'Encrypt & Upload'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
