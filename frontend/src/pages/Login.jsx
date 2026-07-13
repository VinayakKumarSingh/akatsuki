import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { loginUser } from '../api/auth';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [requires2FA, setRequires2FA] = useState(false);
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

  return (
    <div className="auth-container">
      <div className="glass-panel auth-card">
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
              <div className="input-group" style={{ marginBottom: '32px' }}>
                <label>Password</label>
                <input 
                  type="password" 
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required 
                />
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
      </div>
    </div>
  );
}
