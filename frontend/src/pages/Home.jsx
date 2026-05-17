import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import encryptionGif from '../assets/encryption.gif';
import logo from '../assets/vite.svg';
import { fetchMyKeys } from '../api/documents';
import { logoutUser } from '../api/auth';
import ProfileModal from '../components/ProfileModal';

export default function Home() {
  const navigate = useNavigate();
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [username, setUsername] = useState('');
  const [showProfile, setShowProfile] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (token) {
      setIsLoggedIn(true);
      const fetchUser = async () => {
        try {
          const keys = await fetchMyKeys();
          setUsername(keys.username || 'User');
        } catch (err) {
          // Token might be expired, ignore or handle
        }
      };
      fetchUser();
    }
  }, []);

  const handleLogout = () => {
    logoutUser();
    setIsLoggedIn(false);
    setUsername('');
    navigate('/');
  };
  return (
    <div className="home-container">
      {/* Navigation */}
      <nav className="nav-bar home-nav">
        <Link to="/" style={{ textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <img src={logo} alt="Akatsuki Logo" style={{ width: '32px', height: '32px' }} />
          <h2 className="gradient-text" style={{ margin: 0 }}>Akatsuki 暁</h2>
        </Link>
        <div>
          {isLoggedIn ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
              <div style={{ color: '#94a3b8', fontSize: '0.9rem' }}>
                Welcome, <strong style={{ color: 'white' }}>{username}</strong>
              </div>
              <button className="btn" style={{ background: 'rgba(99, 102, 241, 0.1)', color: 'var(--accent-color)' }} onClick={() => setShowProfile(true)}>
                Profile & Security
              </button>
              <Link to="/dashboard" className="btn btn-primary">Go to Dashboard</Link>
              <button className="btn" style={{ background: 'rgba(255,255,255,0.1)', color: 'white' }} onClick={handleLogout}>
                Sign Out
              </button>
            </div>
          ) : (
            <div>
              <Link to="/login" className="btn" style={{ background: 'transparent', color: 'white', marginRight: '10px' }}>Sign In</Link>
              <Link to="/dashboard" className="btn btn-primary">Go to Dashboard</Link>
            </div>
          )}
        </div>
      </nav>

      {/* Hero Section */}
      <section className="hero-section">
        <div className="hero-content">
          <h1 className="hero-title">
            Akatsuki 暁
          </h1>
          <p className="hero-subtitle">
            The ultimate zero-knowledge, End-to-End Encrypted document sharing platform.
            Protect your sensitive data with military-grade cryptography right from your browser.
          </p>
          <div className="hero-actions">
            {isLoggedIn ? (
              <Link to="/dashboard" className="btn btn-primary" style={{ padding: '14px 28px', fontSize: '1.1rem' }}>Enter Your Vault</Link>
            ) : (
              <Link to="/register" className="btn btn-primary" style={{ padding: '14px 28px', fontSize: '1.1rem' }}>Get Started Securely</Link>
            )}
          </div>
        </div>
        <div className="hero-image-container">
          <img src={encryptionGif} alt="Secure Encryption" className="hero-image" />
          <div className="hero-glow"></div>
        </div>
      </section>

      {/* Features Section */}
      <section className="features-section">
        <h2 style={{ textAlign: 'center', marginBottom: '50px', fontSize: '2.5rem' }}>Why Choose Akatsuki?</h2>

        <div className="features-grid">
          <div className="glass-panel feature-card">
            <div className="feature-icon">🔒</div>
            <h3>True Zero-Knowledge</h3>
            <p>
              Your data is encrypted locally using AES-256-GCM before it ever leaves your device.
              The server only sees ciphertext and cannot access your files or your keys.
            </p>
          </div>

          <div className="glass-panel feature-card">
            <div className="feature-icon">🔑</div>
            <h3>Hybrid Cryptography</h3>
            <p>
              We utilize a powerful combination of AES for fast file encryption and RSA-OAEP for secure key exchange,
              ensuring perfect forward secrecy and secure sharing.
            </p>
          </div>

          <div className="glass-panel feature-card">
            <div className="feature-icon">🛡️</div>
            <h3>Metadata Protection</h3>
            <p>
              Unlike standard platforms, Akatsuki encrypts your filenames and metadata.
              Only you and your intended recipient can decrypt and view the original file details.
            </p>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer style={{ textAlign: 'center', padding: '40px 20px', color: '#64748b', marginTop: '60px', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
        <p>&copy; 2026 Akatsuki E2EE Platform. All rights reserved.</p>
      </footer>

      {showProfile && (
        <ProfileModal onClose={() => setShowProfile(false)} />
      )}
    </div>
  );
}
