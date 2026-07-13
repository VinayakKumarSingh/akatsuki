import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { 
  loginUser, 
  getSecurityQuestion, 
  verifySecurityAnswer, 
  resetPasswordWithRecovery 
} from '../api/auth';
import {
  deriveKeyFromPassword,
  unwrapPrivateKey,
  wrapPrivateKey,
  generateSalt
} from '../utils/crypto';

export default function Login() {
  const [view, setView] = useState('login'); // login, forgot_username, forgot_verify, forgot_success
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [requires2FA, setRequires2FA] = useState(false);
  const [securityAnswer, setSecurityAnswer] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [securityQuestion, setSecurityQuestion] = useState('');
  
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await loginUser(username, password, requires2FA ? otpCode : null);
      navigate('/');
    } catch (err) {
      const data = err.response?.data;
      if (data && (data.requires_2fa || (Array.isArray(data.requires_2fa) && data.requires_2fa[0]))) {
        setRequires2FA(true);
        setError('Two-factor authentication code required.');
      } else {
        setError(data?.error || data?.detail || 'Invalid credentials or network error.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleFetchQuestion = async (e) => {
    e.preventDefault();
    if (!username.trim()) {
      setError('Username is required.');
      return;
    }
    setError('');
    setLoading(true);
    try {
      const data = await getSecurityQuestion(username.trim());
      setSecurityQuestion(data.security_question);
      setView('forgot_verify');
    } catch (err) {
      setError(err.response?.data?.error || 'User or security question not found.');
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    setError('');

    if (newPassword.length < 8) {
      setError('New password must be at least 8 characters long.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }
    if (!securityAnswer.trim()) {
      setError('Security answer is required.');
      return;
    }

    setLoading(true);
    try {
      // 1. Verify answer and fetch recovery vault
      const data = await verifySecurityAnswer(username.trim(), securityAnswer.trim());
      const { recovery_salt, encrypted_rsa_private_key_recovery } = data;

      // 2. Perform local cryptographic recovery of private key
      const normalizedAnswer = securityAnswer.trim().toLowerCase().replace(/\s+/g, '');
      const saltBuffer = new Uint8Array(
        window.atob(recovery_salt).split('').map(c => c.charCodeAt(0))
      ).buffer;
      const recoveryDerivedKey = await deriveKeyFromPassword(normalizedAnswer, saltBuffer);

      const [privIvBase64, privEncBase64] = encrypted_rsa_private_key_recovery.split(':');
      let rsaPrivateKey;
      try {
        rsaPrivateKey = await unwrapPrivateKey(privEncBase64, privIvBase64, recoveryDerivedKey);
      } catch (decErr) {
        throw new Error('Incorrect security answer or recovery decryption failed.');
      }

      // 3. Re-wrap private key with the new password
      const newSaltStr = generateSalt();
      const newSaltBuffer = window.atob(newSaltStr).split('').map(c => c.charCodeAt(0));
      const newDerivedKey = await deriveKeyFromPassword(newPassword, new Uint8Array(newSaltBuffer).buffer);

      const { encryptedPrivateKey, iv } = await wrapPrivateKey(rsaPrivateKey, newDerivedKey);
      const newStoredPrivateKey = `${iv}:${encryptedPrivateKey}`;

      // 4. Update password on server
      await resetPasswordWithRecovery(
        username.trim(), 
        securityAnswer.trim(), 
        newPassword, 
        newSaltStr, 
        newStoredPrivateKey
      );

      setView('forgot_success');
      // Clear fields
      setPassword('');
      setSecurityAnswer('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err) {
      console.error(err);
      setError(err.message || err.response?.data?.error || 'Reset failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="glass-panel auth-card">
        {view === 'login' && (
          <>
            <h2 style={{ marginBottom: '8px' }} className="gradient-text">Welcome Back</h2>
            <p style={{ color: '#94a3b8', marginBottom: '32px', fontSize: '0.9rem' }}>
              Sign in to access your secure documents.
            </p>

            {error && <div className="error-text">{error}</div>}

            <form onSubmit={handleLogin}>
              {!requires2FA ? (
                <>
                  <div className="input-group">
                    <label>Username</label>
                    <input 
                      type="text" 
                      placeholder="Enter your username"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      required 
                    />
                  </div>
                  <div className="input-group" style={{ marginBottom: '16px' }}>
                    <label>Password</label>
                    <input 
                      type="password" 
                      placeholder="••••••••"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required 
                    />
                  </div>
                  <div style={{ textAlign: 'right', marginBottom: '24px' }}>
                    <button 
                      type="button" 
                      onClick={() => { setView('forgot_username'); setError(''); }}
                      style={{ background: 'none', border: 'none', color: 'var(--accent-color)', cursor: 'pointer', fontSize: '0.875rem' }}
                    >
                      Forgot Password?
                    </button>
                  </div>
                </>
              ) : (
                <div className="input-group" style={{ marginBottom: '32px' }}>
                  <label>Authenticator Code (OTP)</label>
                  <input 
                    type="text" 
                    placeholder="6-digit code"
                    value={otpCode}
                    onChange={(e) => setOtpCode(e.target.value)}
                    maxLength={6}
                    required 
                    autoFocus
                  />
                </div>
              )}

              <button 
                type="submit" 
                className="btn btn-primary" 
                style={{ width: '100%' }}
                disabled={loading}
              >
                {loading ? 'Authenticating...' : requires2FA ? 'Confirm OTP' : 'Sign In'}
              </button>
            </form>

            <p style={{ textAlign: 'center', marginTop: '24px', fontSize: '0.875rem', color: '#94a3b8' }}>
              Don't have an account? <Link to="/register" style={{ color: 'var(--accent-color)', textDecoration: 'none' }}>Register</Link>
            </p>
            <p style={{ textAlign: 'center', marginTop: '12px', fontSize: '0.875rem', color: '#94a3b8' }}>
              Key issues? <Link to="/recovery" style={{ color: 'var(--accent-color)', textDecoration: 'none' }}>Emergency Key Recovery</Link>
            </p>
          </>
        )}

        {view === 'forgot_username' && (
          <>
            <h2 style={{ marginBottom: '8px' }} className="gradient-text">Forgot Password</h2>
            <p style={{ color: '#94a3b8', marginBottom: '32px', fontSize: '0.9rem' }}>
              Enter your username to retrieve your security question.
            </p>

            {error && <div className="error-text">{error}</div>}

            <form onSubmit={handleFetchQuestion}>
              <div className="input-group" style={{ marginBottom: '32px' }}>
                <label>Username</label>
                <input 
                  type="text" 
                  placeholder="Enter your username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required 
                />
              </div>

              <div style={{ display: 'flex', gap: '10px' }}>
                <button 
                  type="button" 
                  className="btn" 
                  style={{ flex: 1, background: 'rgba(255,255,255,0.1)', color: 'white' }} 
                  onClick={() => { setView('login'); setError(''); }}
                >
                  Back
                </button>
                <button 
                  type="submit" 
                  className="btn btn-primary" 
                  style={{ flex: 1 }}
                  disabled={loading}
                >
                  {loading ? 'Fetching...' : 'Continue'}
                </button>
              </div>
            </form>
          </>
        )}

        {view === 'forgot_verify' && (
          <>
            <h2 style={{ marginBottom: '8px' }} className="gradient-text">Verify Identity</h2>
            <p style={{ color: '#94a3b8', marginBottom: '24px', fontSize: '0.9rem' }}>
              Answer your security question to reset your password.
            </p>

            {error && <div className="error-text">{error}</div>}

            <form onSubmit={handleResetPassword}>
              <div className="input-group" style={{ marginBottom: '16px' }}>
                <label>Security Question</label>
                <div style={{ 
                  background: 'rgba(255,255,255,0.05)', 
                  padding: '12px 16px', 
                  borderRadius: '8px', 
                  fontSize: '0.95rem',
                  border: '1px solid var(--glass-border)',
                  color: '#fff',
                  fontWeight: '500'
                }}>
                  {securityQuestion}
                </div>
              </div>

              <div className="input-group">
                <label>Security Answer</label>
                <input 
                  type="text" 
                  placeholder="Enter your answer"
                  value={securityAnswer}
                  onChange={(e) => setSecurityAnswer(e.target.value)}
                  required 
                />
              </div>

              <div className="input-group">
                <label>New Master Password</label>
                <input 
                  type="password" 
                  placeholder="At least 8 characters"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required 
                  minLength={8}
                />
              </div>

              <div className="input-group" style={{ marginBottom: '32px' }}>
                <label>Confirm New Password</label>
                <input 
                  type="password" 
                  placeholder="••••••••"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required 
                />
              </div>

              <div style={{ display: 'flex', gap: '10px' }}>
                <button 
                  type="button" 
                  className="btn" 
                  style={{ flex: 1, background: 'rgba(255,255,255,0.1)', color: 'white' }} 
                  onClick={() => { setView('forgot_username'); setError(''); }}
                  disabled={loading}
                >
                  Back
                </button>
                <button 
                  type="submit" 
                  className="btn btn-primary" 
                  style={{ flex: 1 }}
                  disabled={loading}
                >
                  {loading ? 'Resetting...' : 'Reset Password'}
                </button>
              </div>
            </form>
          </>
        )}

        {view === 'forgot_success' && (
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '3rem', color: 'var(--success-color)', marginBottom: '16px' }}>✓</div>
            <h2 style={{ marginBottom: '12px' }} className="gradient-text">Password Reset</h2>
            <p style={{ color: '#94a3b8', marginBottom: '32px', fontSize: '0.95rem', lineHeight: '1.6' }}>
              Your Master Password has been successfully updated and your cryptographic vault has been re-wrapped.
            </p>
            <button 
              type="button" 
              className="btn btn-primary" 
              style={{ width: '100%' }}
              onClick={() => { setView('login'); setError(''); }}
            >
              Sign In Now
            </button>
          </div>
        )}
>>>>>>> 5082a02eaffde27072971fbcdbf431bd6e1a82e7
      </div>
    </div>
  );
}
