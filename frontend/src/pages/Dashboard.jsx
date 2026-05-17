import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { logoutUser } from '../api/auth';
import axios from 'axios';
import UploadModal from '../components/UploadModal';
import DecryptModal from '../components/DecryptModal';
import ProfileModal from '../components/ProfileModal';
import { fetchMyKeys } from '../api/documents';

export default function Dashboard() {
  const navigate = useNavigate();
  const [documents, setDocuments] = useState([]);
  const [showUpload, setShowUpload] = useState(false);
  const [decryptDoc, setDecryptDoc] = useState(null);
  const [showProfile, setShowProfile] = useState(false);
  const [username, setUsername] = useState('');

  useEffect(() => {
    // Basic fetch just to ensure routing and API connection works
    const fetchDocs = async () => {
      try {
        const token = localStorage.getItem('access_token');
        const res = await axios.get('/api/documents/', {
          headers: { Authorization: `Bearer ${token}` }
        });
        setDocuments(res.data);
      } catch (err) {
        if (err.response?.status === 401) {
          handleLogout();
        }
      }
    };
    
    const fetchUser = async () => {
      try {
        const keys = await fetchMyKeys();
        setUsername(keys.username || 'User');
      } catch (err) {}
    };

    fetchDocs();
    fetchUser();
  }, []);

  const fetchDocs = async () => {
    try {
      const token = localStorage.getItem('access_token');
      const res = await axios.get('/api/documents/', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setDocuments(res.data);
    } catch (err) { }
  };

  const handleLogout = () => {
    logoutUser();
    navigate('/login');
  };

  return (
    <div className="dashboard-container">
      <div className="nav-bar">
        <h2 className="gradient-text">Akatsuki</h2>
        <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
          <div style={{ color: '#94a3b8', fontSize: '0.9rem' }}>
            Welcome, <strong style={{ color: 'white' }}>{username}</strong>
          </div>
          <button className="btn" style={{ background: 'rgba(99, 102, 241, 0.1)', color: 'var(--accent-color)' }} onClick={() => setShowProfile(true)}>
            Profile & Security
          </button>
          <button className="btn" style={{ background: 'rgba(255,255,255,0.1)', color: 'white' }} onClick={handleLogout}>
            Sign Out
          </button>
        </div>
      </div>

      <div className="glass-panel" style={{ padding: '30px', minHeight: '400px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
          <h3>My Documents</h3>
          <button className="btn btn-primary" onClick={() => setShowUpload(true)}>+ Upload Encrypted File</button>
        </div>

        {documents.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '60px 20px', color: '#94a3b8' }}>
            <div style={{ fontSize: '3rem', marginBottom: '16px' }}>🗄️</div>
            <p>Your vault is empty. Upload a file to see E2EE in action.</p>
          </div>
        ) : (
          <div>
            {documents.map(doc => (
              <div key={doc.id} style={{ padding: '16px', borderBottom: '1px solid var(--glass-border)', display: 'flex', justifyContent: 'space-between' }}>
                <span>{doc.encrypted_filename && doc.encrypted_filename.includes(':') ? 'Encrypted File' : (doc.encrypted_filename || 'Encrypted File')}</span>
                <button
                  className="btn"
                  style={{ padding: '6px 12px', fontSize: '0.875rem', background: 'rgba(99, 102, 241, 0.2)' }}
                  onClick={() => setDecryptDoc(doc)}
                >
                  Decrypt & Download
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {showUpload && (
        <UploadModal
          onClose={() => setShowUpload(false)}
          onUploadSuccess={() => {
            setShowUpload(false);
            fetchDocs();
          }}
        />
      )}

      {decryptDoc && (
        <DecryptModal
          document={decryptDoc}
          onClose={() => setDecryptDoc(null)}
        />
      )}

      {showProfile && (
        <ProfileModal onClose={() => setShowProfile(false)} />
      )}
    </div>
  );
}
