import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import axios from 'axios';
import { loginUser } from '../api/auth';

export default function Recovery() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [backupFile, setBackupFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const navigate = useNavigate();

  const handleFileChange = (e) => {
    setBackupFile(e.target.files[0]);
  };

  const handleRestore = async (e) => {
    e.preventDefault();
    if (!username || !password || !backupFile) {
      setError('All fields are required.');
      return;
    }

    setLoading(true);
    setError('');
    setSuccess(false);

    // Read the file content
    const reader = new FileReader();
    reader.onload = async (event) => {
      try {
        const backupData = JSON.parse(event.target.result);
        
        if (!backupData.salt || !backupData.encrypted_rsa_private_key) {
          throw new Error('Invalid Security Kit file format. Key data is missing.');
        }

        // 1. Authenticate the user to get JWT tokens
        const loginData = await loginUser(username, password);
        if (!loginData || !loginData.access) {
          throw new Error('Authentication failed.');
        }

        // 2. Put the restored keys to the server
        const token = loginData.access;
        const payload = {
          salt: backupData.salt,
          rsa_public_key: backupData.rsa_public_key,
          encrypted_rsa_private_key: backupData.encrypted_rsa_private_key
        };

        await axios.put('/api/keys/me/', payload, {
          headers: {
            Authorization: `Bearer ${token}`
          }
        });

        setSuccess(true);
        setTimeout(() => {
          navigate('/dashboard');
        }, 3000);

      } catch (err) {
        console.error(err);
        setError(err.message || 'Recovery failed. Verify your password and backup file.');
        // Clean local storage if login was successful but restore failed
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
      } finally {
        setLoading(false);
      }
    };

    reader.onerror = () => {
      setError('Failed to read the backup file.');
      setLoading(false);
    };

    reader.readAsText(backupFile);
  };

  return (
    <div className="auth-container">
      <div className="glass-panel auth-card" style={{ maxWidth: '480px' }}>
        <h2 style={{ marginBottom: '8px' }} className="gradient-text">Emergency Recovery</h2>
        <p style={{ color: '#94a3b8', marginBottom: '32px', fontSize: '0.9rem' }}>
          Restore your local cryptographic keys from an exported Security Kit file.
        </p>

        {error && <div className="error-text">{error}</div>}
        {success && (
          <div style={{ color: 'var(--success-color)', marginBottom: '16px', fontSize: '0.9rem' }}>
            Keys restored successfully! Redirecting you to the dashboard...
          </div>
        )}

        <form onSubmit={handleRestore}>
          <div className="input-group">
            <label>Username</label>
            <input 
              type="text" 
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required 
              disabled={loading || success}
            />
          </div>
          <div className="input-group">
            <label>Password</label>
            <input 
              type="password" 
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required 
              disabled={loading || success}
            />
          </div>
          <div className="input-group" style={{ marginBottom: '32px' }}>
            <label>Select Security Kit JSON File</label>
            <input 
              type="file" 
              accept=".json"
              onChange={handleFileChange}
              required 
              disabled={loading || success}
            />
          </div>
          <button 
            type="submit" 
            className="btn btn-primary" 
            style={{ width: '100%' }}
            disabled={loading || success}
          >
            {loading ? 'Restoring Credentials...' : 'Restore & Log In'}
          </button>
        </form>

        <p style={{ textAlign: 'center', marginTop: '24px', fontSize: '0.875rem', color: '#94a3b8' }}>
          Remember your password? <Link to="/login" style={{ color: 'var(--accent-color)', textDecoration: 'none' }}>Sign In</Link>
        </p>
      </div>
    </div>
  );
}
