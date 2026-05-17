import React, { useState } from 'react';
import { changePassword } from '../api/auth';
import { fetchMyKeys } from '../api/documents';

export default function ProfileModal({ onClose }) {
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  const handleChangePassword = async (e) => {
    e.preventDefault();
    if (newPassword.length < 8) {
      setError('New password must be at least 8 characters long.');
      return;
    }

    setLoading(true);
    setError('');
    setSuccessMsg('');

    try {
      // Fetch user's current keys so we can unwrap and re-wrap
      const myKeys = await fetchMyKeys();
      
      await changePassword(oldPassword, newPassword, myKeys);
      
      setSuccessMsg('Master Password updated successfully! Your RSA keys have been re-wrapped.');
      setOldPassword('');
      setNewPassword('');
      
      setTimeout(onClose, 3000);
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.error || 'Failed to update password. Incorrect old password?');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="glass-panel modal-content" style={{ padding: '30px', maxWidth: '400px', width: '100%' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px' }}>
          <h3 className="gradient-text">Change Master Password</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#fff', fontSize: '1.5rem', cursor: 'pointer' }}>&times;</button>
        </div>

        <p style={{ color: '#94a3b8', marginBottom: '20px', fontSize: '0.9rem' }}>
          Changing your Master Password requires locally unwrapping your Private Key and securely re-wrapping it with your new password.
        </p>

        {error && <div className="error-text">{error}</div>}
        {successMsg && <div style={{ color: 'var(--success-color)', marginBottom: '16px', fontSize: '0.875rem' }}>{successMsg}</div>}

        <form onSubmit={handleChangePassword}>
          <div className="input-group">
            <label>Current Password</label>
            <input 
              type="password" 
              placeholder="••••••••"
              value={oldPassword}
              onChange={(e) => setOldPassword(e.target.value)}
              required 
            />
          </div>

          <div className="input-group" style={{ marginBottom: '32px' }}>
            <label>New Password</label>
            <input 
              type="password" 
              placeholder="••••••••"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required 
              minLength={8}
            />
          </div>

          <div style={{ display: 'flex', gap: '10px' }}>
            <button type="button" className="btn" style={{ flex: 1, background: 'rgba(255,255,255,0.1)', color: 'white' }} onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" style={{ flex: 1 }} disabled={loading || !oldPassword || !newPassword}>
              {loading ? 'Re-wrapping Keys...' : 'Change Password'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
