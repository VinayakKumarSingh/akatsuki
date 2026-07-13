import React, { useState, useEffect } from 'react';
import { changePassword } from '../api/auth';
import { fetchMyKeys } from '../api/documents';
import axios from 'axios';

export default function ProfileModal({ onClose }) {
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');
  const [exporting, setExporting] = useState(false);

  // 2FA States
  const [otpEnabled, setOtpEnabled] = useState(false);
  const [otpSecret, setOtpSecret] = useState('');
  const [otpSetupUrl, setOtpSetupUrl] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  const [setupActive, setSetupActive] = useState(false);
  const [verifying, setVerifying] = useState(false);

  useEffect(() => {
    const check2FA = async () => {
      try {
        const keys = await fetchMyKeys();
        setOtpEnabled(keys.otp_enabled);
      } catch (err) {}
    };
    check2FA();
  }, []);

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

  const handleExportSecurityKit = async () => {
    setExporting(true);
    setError('');
    setSuccessMsg('');
    try {
      const myKeys = await fetchMyKeys();
      const backupData = {
        username: myKeys.username,
        salt: myKeys.salt,
        rsa_public_key: myKeys.rsa_public_key,
        encrypted_rsa_private_key: myKeys.encrypted_rsa_private_key,
        exported_at: new Date().toISOString()
      };

      const blob = new Blob([JSON.stringify(backupData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `akatsuki_security_kit_${myKeys.username || 'user'}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setSuccessMsg('Security Kit exported successfully!');
    } catch (err) {
      console.error(err);
      setError('Failed to export security kit.');
    } finally {
      setExporting(false);
    }
  };

  const handleSetup2FA = async () => {
    setLoading(true);
    setError('');
    try {
      const token = localStorage.getItem('access_token');
      const res = await axios.post('/api/auth/2fa/setup/', {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setOtpSecret(res.data.secret);
      setOtpSetupUrl(res.data.otpauth_url);
      setSetupActive(true);
    } catch (err) {
      setError('Failed to setup 2FA.');
    } finally {
      setLoading(false);
    }
  };

  const handleVerify2FA = async (e) => {
    e.preventDefault();
    setVerifying(true);
    setError('');
    try {
      const token = localStorage.getItem('access_token');
      await axios.post('/api/auth/2fa/verify/', { code: verificationCode }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setOtpEnabled(true);
      setSetupActive(false);
      setSuccessMsg('2FA has been enabled successfully!');
      setVerificationCode('');
    } catch (err) {
      setError(err.response?.data?.error || 'Invalid OTP verification code.');
    } finally {
      setVerifying(false);
    }
  };

  const handleDisable2FA = async () => {
    const code = window.prompt("Enter your 2FA OTP code to confirm disabling:");
    if (!code) return;
    setLoading(true);
    setError('');
    try {
      const token = localStorage.getItem('access_token');
      await axios.post('/api/auth/2fa/disable/', { code }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setOtpEnabled(false);
      setOtpSecret('');
      setOtpSetupUrl('');
      setSuccessMsg('2FA has been disabled.');
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to disable 2FA. Invalid OTP code.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="glass-panel modal-content" style={{ padding: '30px', maxWidth: '450px', width: '100%', maxHeight: '90vh', overflowY: 'auto' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px' }}>
          <h3 className="gradient-text">Profile & Security</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#fff', fontSize: '1.5rem', cursor: 'pointer' }}>&times;</button>
        </div>

        {error && <div className="error-text">{error}</div>}
        {successMsg && <div style={{ color: 'var(--success-color)', marginBottom: '16px', fontSize: '0.875rem' }}>{successMsg}</div>}

        {/* 1. Security Kit Export */}
        <div style={{ borderBottom: '1px solid var(--glass-border)', paddingBottom: '20px', marginBottom: '20px' }}>
          <h4 style={{ color: '#fff', marginBottom: '8px' }}>Backup Security Kit</h4>
          <p style={{ color: '#94a3b8', fontSize: '0.85rem', marginBottom: '16px' }}>
            Download your local cryptographic keys and password salt to a secure file. This kit can be used to recover your document vault in case of data loss.
          </p>
          <button 
            type="button" 
            className="btn btn-primary" 
            style={{ width: '100%', background: 'rgba(16, 185, 129, 0.2)', color: 'var(--success-color)', boxShadow: 'none' }}
            onClick={handleExportSecurityKit}
            disabled={exporting}
          >
            {exporting ? 'Exporting...' : '⬇ Export Security Kit'}
          </button>
        </div>

        {/* 2. Two-Factor Authentication Section */}
        <div style={{ borderBottom: '1px solid var(--glass-border)', paddingBottom: '20px', marginBottom: '20px' }}>
          <h4 style={{ color: '#fff', marginBottom: '8px' }}>Two-Factor Authentication (2FA)</h4>
          {otpEnabled ? (
            <div>
              <p style={{ color: 'var(--success-color)', fontSize: '0.85rem', marginBottom: '16px', fontWeight: '500' }}>
                ✓ Two-Factor Authentication is currently ENABLED.
              </p>
              <button 
                type="button" 
                className="btn" 
                style={{ width: '100%', background: 'rgba(239, 68, 68, 0.2)', color: 'var(--danger-color)' }}
                onClick={handleDisable2FA}
                disabled={loading}
              >
                Disable 2FA
              </button>
            </div>
          ) : !setupActive ? (
            <div>
              <p style={{ color: '#94a3b8', fontSize: '0.85rem', marginBottom: '16px' }}>
                Add an extra layer of security to your account by enabling TOTP-based 2FA.
              </p>
              <button 
                type="button" 
                className="btn btn-primary" 
                style={{ width: '100%', background: 'rgba(99, 102, 241, 0.2)', color: 'var(--accent-color)', boxShadow: 'none' }}
                onClick={handleSetup2FA}
                disabled={loading}
              >
                Enable 2FA
              </button>
            </div>
          ) : (
            <div>
              <p style={{ color: '#94a3b8', fontSize: '0.85rem', marginBottom: '12px' }}>
                Scan the QR code below using your Authenticator app, or manually enter the Secret Key:
              </p>
              
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: '16px', gap: '12px' }}>
                <img 
                  src={`https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(otpSetupUrl)}`} 
                  alt="2FA QR Code" 
                  style={{ borderRadius: '8px', border: '4px solid white', background: 'white', width: '180px', height: '180px' }}
                />
                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '10px', borderRadius: '8px', width: '100%', wordBreak: 'break-all', fontSize: '0.85rem', border: '1px solid var(--glass-border)', textAlign: 'center' }}>
                  <strong style={{ color: '#fff' }}>Secret Key:</strong> <code style={{ color: 'var(--accent-color)' }}>{otpSecret}</code>
                </div>
              </div>
              <form onSubmit={handleVerify2FA}>
                <div className="input-group" style={{ marginBottom: '16px' }}>
                  <label>Verification Code</label>
                  <input 
                    type="text" 
                    placeholder="Enter 6-digit code"
                    value={verificationCode}
                    onChange={(e) => setVerificationCode(e.target.value)}
                    maxLength={6}
                    required 
                  />
                </div>
                <div style={{ display: 'flex', gap: '10px' }}>
                  <button type="button" className="btn" style={{ flex: 1, background: 'rgba(255,255,255,0.1)', color: 'white' }} onClick={() => setSetupActive(false)}>
                    Cancel
                  </button>
                  <button type="submit" className="btn btn-primary" style={{ flex: 1 }} disabled={verifying}>
                    {verifying ? 'Verifying...' : 'Verify & Enable'}
                  </button>
                </div>
              </form>
            </div>
          )}
        </div>

        {/* 3. Change Master Password */}
        <div>
          <h4 style={{ color: '#fff', marginBottom: '8px' }}>Change Master Password</h4>
          <p style={{ color: '#94a3b8', fontSize: '0.85rem', marginBottom: '16px' }}>
            Changing your Master Password requires locally unwrapping your Private Key and securely re-wrapping it with your new password.
          </p>

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
    </div>
  );
}
