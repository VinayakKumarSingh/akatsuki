import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { logoutUser } from '../api/auth';
import axios from 'axios';
import logo from '../assets/vite.svg';
import UploadModal from '../components/UploadModal';
import DecryptModal from '../components/DecryptModal';
import ProfileModal from '../components/ProfileModal';
import UnlockVaultModal from '../components/UnlockVaultModal';
import { 
  fetchMyKeys, 
  downloadCiphertext, 
  fetchPendingRequests, 
  approveAccessRequest, 
  denyAccessRequest, 
  requestAccess,
  createAuditLog
} from '../api/documents';
import { decryptAESKeyWithRSA, decryptFile, decryptString, importPublicKey, encryptAESKeyWithRSA } from '../utils/crypto';
import AuditLogModal from '../components/AuditLogModal';
import VersionHistoryModal from '../components/VersionHistoryModal';
import GroupManagementModal from '../components/GroupManagementModal';
import ManageAccessModal from '../components/ManageAccessModal';

export default function Dashboard() {
  const navigate = useNavigate();
  const [documents, setDocuments] = useState([]);
  const [showUpload, setShowUpload] = useState(false);
  const [showVersions, setShowVersions] = useState(false);
  const [versionDoc, setVersionDoc] = useState(null);
  const [showGroups, setShowGroups] = useState(false);
  const [showManageAccess, setShowManageAccess] = useState(false);
  const [accessDoc, setAccessDoc] = useState(null);
  const [decryptDoc, setDecryptDoc] = useState(null);
  const [showProfile, setShowProfile] = useState(false);
  const [showUnlock, setShowUnlock] = useState(false);
  const [showAuditTrail, setShowAuditTrail] = useState(false);
  const [username, setUsername] = useState('');
  const [currentUserId, setCurrentUserId] = useState(null);
  const [myGroups, setMyGroups] = useState([]);
  const [unlockedNames, setUnlockedNames] = useState({});
  const [unlockedPrivateKey, setUnlockedPrivateKey] = useState(null);

  // Search, Selection, and Access Request States
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIds, setSelectedIds] = useState([]);
  const [batchLoading, setBatchLoading] = useState(false);
  const [pendingRequests, setPendingRequests] = useState([]);
  const [requestDocId, setRequestDocId] = useState('');
  const [requestLoading, setRequestLoading] = useState(false);

  useEffect(() => {
    fetchDocs();
    fetchUser();
    fetchRequests();
    fetchMyGroups();
  }, []);

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
      setCurrentUserId(keys.user_id);
      localStorage.setItem('user_id', keys.user_id);
    } catch (err) { }
  };

  const fetchMyGroups = async () => {
    try {
      const token = localStorage.getItem('access_token');
      const res = await axios.get('/api/groups/', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setMyGroups(res.data);
    } catch (err) { }
  };

  const fetchRequests = async () => {
    try {
      const data = await fetchPendingRequests();
      setPendingRequests(data);
    } catch (err) { }
  };

  const handleLogout = () => {
    logoutUser();
    navigate('/login');
  };

  // Helper to determine permission level for current user (checks direct and group access)
  const getUserPermission = (doc) => {
    if (doc.owner === currentUserId) return 'OWNER';
    const versions = doc.versions || [];
    const latestVersion = versions.length > 0
      ? [...versions].sort((a, b) => b.version_number - a.version_number)[0]
      : null;
    if (!latestVersion) return 'NONE';

    // Find all access keys that apply to the current user
    const applicableKeys = (latestVersion.access_keys || []).filter(k => {
      if (k.recipient === currentUserId) return true;
      if (k.key_type === 'GRP' && k.group && myGroups.some(g => g.id === k.group)) return true;
      return false;
    });

    if (applicableKeys.length === 0) return 'NONE';

    // Order of priority: SHARE > DOWNLOAD > VIEW_ONLY
    const perms = applicableKeys.map(k => k.permissions);
    if (perms.includes('SHARE')) return 'SHARE';
    if (perms.includes('DOWNLOAD')) return 'DOWNLOAD';
    if (perms.includes('VIEW_ONLY')) return 'VIEW_ONLY';
    return 'NONE';
  };

  // Helper to determine the display name of a document
  const getDocName = (doc) => {
    return unlockedNames[doc.id] || (doc.encrypted_filename && doc.encrypted_filename.includes(':') ? 'Encrypted File' : (doc.encrypted_filename || 'Encrypted File'));
  };

  // Filtered documents based on search query
  const filteredDocuments = documents.filter(doc => {
    const docName = getDocName(doc);
    return docName.toLowerCase().includes(searchQuery.toLowerCase());
  });

  const handleToggleSelect = (id) => {
    setSelectedIds(prev =>
      prev.includes(id) ? prev.filter(item => item !== id) : [...prev, id]
    );
  };

  const handleToggleSelectAll = () => {
    // Only select documents that the user has download/share access for
    const visibleDownloadableIds = filteredDocuments
      .filter(doc => {
        const perm = getUserPermission(doc);
        return perm === 'OWNER' || perm === 'DOWNLOAD' || perm === 'SHARE';
      })
      .map(doc => doc.id);

    const allVisibleSelected = visibleDownloadableIds.every(id => selectedIds.includes(id));
    
    if (allVisibleSelected) {
      setSelectedIds(prev => prev.filter(id => !visibleDownloadableIds.includes(id)));
    } else {
      setSelectedIds(prev => [...new Set([...prev, ...visibleDownloadableIds])]);
    }
  };

  const handleBatchDelete = async () => {
    if (!window.confirm(`Are you sure you want to delete ${selectedIds.length} files?`)) return;
    setBatchLoading(true);
    const token = localStorage.getItem('access_token');
    
    try {
      for (const id of selectedIds) {
        await axios.delete(`/api/documents/${id}/`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        await createAuditLog("DELETE", id, `Deleted file with document ID: ${id}`);
      }
      setSelectedIds([]);
      fetchDocs();
    } catch (err) {
      alert("An error occurred during batch deletion.");
      console.error(err);
    } finally {
      setBatchLoading(false);
    }
  };

  const handleBatchDownload = async () => {
    if (!unlockedPrivateKey) {
      alert("Please unlock your vault first to perform batch decrypt & downloads.");
      setShowUnlock(true);
      return;
    }

    // Check if any selected files are View Only
    const hasViewOnly = selectedIds.some(id => {
      const doc = documents.find(d => d.id === id);
      return doc && getUserPermission(doc) === 'VIEW_ONLY';
    });

    if (hasViewOnly) {
      alert("One or more selected documents are View-Only and cannot be downloaded.");
      return;
    }

    setBatchLoading(true);
    try {
      for (const id of selectedIds) {
        const doc = documents.find(d => d.id === id);
        if (!doc) continue;

        const versions = doc.versions || [];
        const latestVersion = versions.length > 0
          ? [...versions].sort((a, b) => b.version_number - a.version_number)[0]
          : null;
        if (!latestVersion) continue;

        // 1. Locate matching RSA key
        let aesKey = null;
        for (const keyObj of (latestVersion.access_keys || [])) {
          if (keyObj.key_type === 'RSA') {
            try {
              aesKey = await decryptAESKeyWithRSA(keyObj.encrypted_key, unlockedPrivateKey);
              break;
            } catch (err) { }
          }
        }

        if (!aesKey) continue;

        // 2. Download encrypted bytes using document ID and version ID
        const ciphertextBuffer = await downloadCiphertext(doc.id, latestVersion.id);

        // 3. Decrypt document
        const decryptedBuffer = await decryptFile(ciphertextBuffer, latestVersion.iv, aesKey);

        // 4. Decrypt original filename
        let originalFilename = "decrypted_file.bin";
        if (doc.encrypted_filename && doc.encrypted_filename.includes(':')) {
          const [nameIv, nameEnc] = doc.encrypted_filename.split(':');
          originalFilename = await decryptString(nameEnc, nameIv, aesKey);
        }

        // 5. Trigger download
        const blob = new Blob([decryptedBuffer], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = window.document.createElement('a');
        a.href = url;
        a.download = originalFilename;
        window.document.body.appendChild(a);
        a.click();
        window.document.body.removeChild(a);
        URL.revokeObjectURL(url);

        await createAuditLog("DOWNLOAD", doc.id, `Batch decrypted and downloaded file: ${originalFilename}`);
      }
    } catch (err) {
      alert("Failed during batch decryption/downloads.");
      console.error(err);
    } finally {
      setBatchLoading(false);
    }
  };

  const handleRequestAccessSubmit = async (e) => {
    e.preventDefault();
    if (!requestDocId.trim()) return;

    setRequestLoading(true);
    try {
      await requestAccess(requestDocId.trim());
      alert("Access requested successfully! The document owner has been notified.");
      setRequestDocId('');
    } catch (err) {
      alert(err.response?.data?.error || "Failed to submit access request.");
    } finally {
      setRequestLoading(false);
    }
  };

  const handleApproveRequest = async (reqObj) => {
    if (!unlockedPrivateKey) {
      alert("Please unlock your vault first to approve access requests.");
      setShowUnlock(true);
      return;
    }

    const permissions = window.prompt("Enter permission level for recipient (VIEW_ONLY, DOWNLOAD):", "DOWNLOAD");
    if (!permissions || !['VIEW_ONLY', 'DOWNLOAD'].includes(permissions.toUpperCase())) {
      alert("Invalid permission level entered.");
      return;
    }

    try {
      // 1. Fetch requester's public key
      const token = localStorage.getItem('access_token');
      const res = await axios.get(`/api/keys/public/?user_ids=${reqObj.requester}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.data.length === 0) throw new Error("Could not find requester's public key.");
      const requesterPubKeyStr = res.data[0].rsa_public_key;

      // 2. Find document & decrypt its AES key using owner's private key
      const doc = documents.find(d => d.id === reqObj.document);
      if (!doc) throw new Error("Document not found.");

      const versions = doc.versions || [];
      const latestVersion = versions.length > 0
        ? [...versions].sort((a, b) => b.version_number - a.version_number)[0]
        : null;
      if (!latestVersion) throw new Error("No version exists for this document.");

      let aesKey = null;
      for (const keyObj of (latestVersion.access_keys || [])) {
        if (keyObj.key_type === 'RSA') {
          try {
            aesKey = await decryptAESKeyWithRSA(keyObj.encrypted_key, unlockedPrivateKey);
            break;
          } catch (err) {}
        }
      }

      if (!aesKey) throw new Error("Could not decrypt the file key. Please verify your vault is fully unlocked.");

      // 3. Encrypt the AES key with the requester's public key
      const requesterPubKey = await importPublicKey(requesterPubKeyStr);
      const encryptedAESKey = await encryptAESKeyWithRSA(aesKey, requesterPubKey);

      // 4. Send approval
      await approveAccessRequest(reqObj.id, encryptedAESKey, permissions.toUpperCase());
      
      // Log audit trail event
      await createAuditLog("SHARE", reqObj.document, `Approved sharing request from user ${reqObj.requester_username} with ${permissions.toUpperCase()} permission`);
      
      alert("Request approved successfully.");
      fetchRequests();
      fetchDocs();
    } catch (err) {
      console.error(err);
      alert(err.message || "Failed to approve request.");
    }
  };

  const handleDenyRequest = async (reqId) => {
    try {
      await denyAccessRequest(reqId);
      alert("Request denied.");
      fetchRequests();
    } catch (err) {
      alert("Failed to deny request.");
    }
  };

  const isAllVisibleSelected = filteredDocuments.length > 0 && 
    filteredDocuments
      .filter(doc => {
        const perm = getUserPermission(doc);
        return perm === 'OWNER' || perm === 'DOWNLOAD' || perm === 'SHARE';
      })
      .map(doc => doc.id)
      .every(id => selectedIds.includes(id));

  return (
    <div className="dashboard-container">
      <div className="nav-bar">
        <Link to="/" style={{ textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <img src={logo} alt="Akatsuki Logo" style={{ width: '32px', height: '32px' }} />
          <h2 className="gradient-text" style={{ margin: 0 }}>Akatsuki</h2>
        </Link>
        <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
          <div style={{ color: '#94a3b8', fontSize: '0.9rem' }}>
            Welcome, <strong style={{ color: 'white' }}>{username}</strong>
          </div>
          <button className="btn" style={{ background: 'rgba(99, 102, 241, 0.1)', color: 'var(--accent-color)' }} onClick={() => setShowAuditTrail(true)}>
            Audit Trail
          </button>
          <button className="btn" style={{ background: 'rgba(99, 102, 241, 0.1)', color: 'var(--accent-color)' }} onClick={() => setShowProfile(true)}>
            Profile & Security
          </button>
          <button className="btn" style={{ background: 'rgba(255,255,255,0.1)', color: 'white' }} onClick={handleLogout}>
            Sign Out
          </button>
        </div>
      </div>

      {/* Access Request Inbox notifications */}
      {pendingRequests.length > 0 && (
        <div className="glass-panel" style={{ padding: '20px', marginBottom: '24px', border: '1px solid rgba(234, 179, 8, 0.3)', background: 'rgba(234, 179, 8, 0.02)' }}>
          <h4 style={{ color: '#eab308', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            🔔 Pending Access Requests ({pendingRequests.length})
          </h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {pendingRequests.map(req => (
              <div key={req.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px', background: 'rgba(0,0,0,0.2)', borderRadius: '6px', fontSize: '0.9rem' }}>
                <span style={{ color: '#fff' }}>
                  User <strong>{req.requester_username}</strong> requested access to document <code>{req.document}</code>
                </span>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button className="btn" style={{ background: 'rgba(16, 185, 129, 0.2)', color: 'var(--success-color)', padding: '4px 10px', fontSize: '0.8rem' }} onClick={() => handleApproveRequest(req)}>
                    Approve
                  </button>
                  <button className="btn" style={{ background: 'rgba(239, 68, 68, 0.2)', color: 'var(--danger-color)', padding: '4px 10px', fontSize: '0.8rem' }} onClick={() => handleDenyRequest(req.id)}>
                    Deny
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="glass-panel" style={{ padding: '30px', minHeight: '400px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
            <h3>My Documents</h3>
            {!unlockedPrivateKey && documents.length > 0 && (
              <button className="btn" style={{ background: 'rgba(234, 179, 8, 0.1)', color: '#eab308', padding: '6px 12px', fontSize: '0.875rem' }} onClick={() => setShowUnlock(true)}>
                Unlock Vault to view filenames
              </button>
            )}
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <button className="btn" style={{ background: 'rgba(99, 102, 241, 0.15)', color: 'var(--accent-color)' }} onClick={() => setShowGroups(true)}>👥 Manage Groups</button>
            <button className="btn btn-primary" onClick={() => { setVersionDoc(null); setShowUpload(true); }}>+ Upload Encrypted File</button>
          </div>
        </div>

        {/* Search, Request Access & Batch Operations Toolbar */}
        {documents.length > 0 && (
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '16px', marginBottom: '20px', flexWrap: 'wrap', background: 'rgba(255,255,255,0.02)', padding: '12px 16px', borderRadius: '8px', border: '1px solid var(--glass-border)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1, minWidth: '200px' }}>
              <span style={{ fontSize: '1.2rem' }}>🔍</span>
              <input 
                type="text" 
                placeholder="Search decrypted filenames..." 
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  background: 'none',
                  border: 'none',
                  outline: 'none',
                  color: '#fff',
                  width: '100%',
                  fontSize: '0.95rem'
                }}
              />
            </div>

            {/* Request Access Form */}
            <form onSubmit={handleRequestAccessSubmit} style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <input 
                type="text" 
                placeholder="Request access (Doc ID)..." 
                value={requestDocId}
                onChange={(e) => setRequestDocId(e.target.value)}
                style={{
                  background: 'var(--input-bg)',
                  border: '1px solid var(--glass-border)',
                  borderRadius: '6px',
                  padding: '6px 12px',
                  color: '#fff',
                  fontSize: '0.875rem',
                  width: '200px'
                }}
              />
              <button type="submit" className="btn" style={{ padding: '6px 12px', fontSize: '0.85rem', background: 'rgba(255,255,255,0.1)' }} disabled={requestLoading}>
                Request Access
              </button>
            </form>

            {selectedIds.length > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span style={{ color: '#94a3b8', fontSize: '0.875rem' }}>{selectedIds.length} selected</span>
                <button 
                  className="btn" 
                  style={{ background: 'rgba(99, 102, 241, 0.2)', color: 'var(--accent-color)', padding: '6px 12px', fontSize: '0.85rem' }}
                  onClick={handleBatchDownload}
                  disabled={batchLoading}
                >
                  Decrypt & Download
                </button>
                <button 
                  className="btn" 
                  style={{ background: 'rgba(239, 68, 68, 0.2)', color: 'var(--danger-color)', padding: '6px 12px', fontSize: '0.85rem' }}
                  onClick={handleBatchDelete}
                  disabled={batchLoading}
                >
                  Delete
                </button>
              </div>
            )}
          </div>
        )}

        {documents.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '60px 20px', color: '#94a3b8' }}>
            <div style={{ fontSize: '3rem', marginBottom: '16px' }}>🗄️</div>
            <p>Your vault is empty. Upload a file to see E2EE in action.</p>
          </div>
        ) : filteredDocuments.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px 20px', color: '#94a3b8' }}>
            <p>No documents found matching "{searchQuery}"</p>
          </div>
        ) : (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', padding: '12px 16px', borderBottom: '2px solid var(--glass-border)', color: '#64748b', fontSize: '0.85rem', fontWeight: '600' }}>
              <input 
                type="checkbox" 
                checked={isAllVisibleSelected}
                onChange={handleToggleSelectAll}
                style={{ marginRight: '16px', cursor: 'pointer' }}
              />
              <span style={{ flex: 1 }}>Name</span>
              <span style={{ width: '120px' }}>Permission</span>
              <span style={{ width: '380px', textAlign: 'right' }}>Actions</span>
            </div>
            
            {filteredDocuments.map(doc => {
              const perm = getUserPermission(doc);
              const isDownloadable = perm === 'OWNER' || perm === 'DOWNLOAD' || perm === 'SHARE';
              const hasAccess = perm !== 'NONE';

              return (
                <div key={doc.id} style={{ padding: '16px', borderBottom: '1px solid var(--glass-border)', display: 'flex', alignItems: 'center' }}>
                  <input 
                    type="checkbox" 
                    checked={selectedIds.includes(doc.id)}
                    onChange={() => handleToggleSelect(doc.id)}
                    disabled={!isDownloadable}
                    style={{ marginRight: '16px', cursor: 'pointer' }}
                  />
                  
                  <div style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
                    <span style={{ fontWeight: '500', color: unlockedNames[doc.id] ? '#fff' : '#94a3b8' }}>
                      {getDocName(doc)}
                    </span>
                    <span style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '4px' }}>
                      {doc.owner === currentUserId ? 'Sent: ' : 'Received: '}
                      {new Date(doc.created_at).toLocaleString()} | ID: <code>{doc.id}</code>
                    </span>
                  </div>

                  <span style={{ width: '120px', fontSize: '0.85rem', color: perm === 'OWNER' ? 'var(--accent-color)' : perm === 'VIEW_ONLY' ? 'var(--danger-color)' : 'var(--success-color)' }}>
                    {perm}
                  </span>
                  
                  <div style={{ width: '380px', textAlign: 'right', display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                    <button
                      className="btn"
                      style={{ padding: '6px 12px', fontSize: '0.875rem', background: hasAccess ? 'rgba(255,255,255,0.08)' : 'rgba(255,255,255,0.02)', color: hasAccess ? '#fff' : '#64748b' }}
                      onClick={() => { setVersionDoc(doc); setShowVersions(true); }}
                      disabled={!hasAccess}
                    >
                      📜 Versions ({doc.versions?.length || 0})
                    </button>
                    {doc.owner === currentUserId && (
                      <button
                        className="btn"
                        style={{ padding: '6px 12px', fontSize: '0.875rem', background: 'rgba(16, 185, 129, 0.15)', color: 'var(--success-color)' }}
                        onClick={() => { setAccessDoc(doc); setShowManageAccess(true); }}
                      >
                        🔑 Access
                      </button>
                    )}
                    <button
                      className="btn"
                      style={{ padding: '6px 12px', fontSize: '0.875rem', background: isDownloadable ? 'rgba(99, 102, 241, 0.2)' : 'rgba(255,255,255,0.05)', color: isDownloadable ? '#fff' : '#64748b' }}
                      onClick={() => setDecryptDoc(doc)}
                      disabled={!isDownloadable}
                    >
                      {isDownloadable ? 'Decrypt & Download' : '🔒 View Only'}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {showUpload && (
        <UploadModal
          documentToVersion={versionDoc}
          unlockedPrivateKey={unlockedPrivateKey}
          onClose={() => {
            setShowUpload(false);
            setVersionDoc(null);
          }}
          onUploadSuccess={() => {
            setShowUpload(false);
            setVersionDoc(null);
            fetchDocs();
          }}
        />
      )}

      {showGroups && (
        <GroupManagementModal
          unlockedPrivateKey={unlockedPrivateKey}
          documents={documents}
          onClose={() => { setShowGroups(false); fetchMyGroups(); }}
        />
      )}

      {showManageAccess && (
        <ManageAccessModal
          document={accessDoc}
          unlockedPrivateKey={unlockedPrivateKey}
          onClose={() => {
            setShowManageAccess(false);
            setAccessDoc(null);
          }}
          onAccessUpdated={fetchDocs}
        />
      )}

      {showVersions && (
        <VersionHistoryModal 
          document={versionDoc}
          cachedPrivateKey={unlockedPrivateKey}
          currentUserId={currentUserId}
          myGroups={myGroups}
          onClose={() => {
            setShowVersions(false);
            setVersionDoc(null);
            fetchDocs();
          }}
          onUploadNewVersion={(doc) => {
            setVersionDoc(doc);
            setShowUpload(true);
          }}
        />
      )}

      {decryptDoc && (
        <DecryptModal
          document={decryptDoc}
          cachedPrivateKey={unlockedPrivateKey}
          onClose={() => setDecryptDoc(null)}
        />
      )}

      {showUnlock && (
        <UnlockVaultModal
          documents={documents}
          onClose={() => setShowUnlock(false)}
          onUnlocked={(names, privKey) => {
            setUnlockedNames(names);
            setUnlockedPrivateKey(privKey);
            setShowUnlock(false);
          }}
        />
      )}

      {showProfile && (
        <ProfileModal onClose={() => setShowProfile(false)} />
      )}

      {showAuditTrail && (
        <AuditLogModal 
          cachedPrivateKey={unlockedPrivateKey} 
          onClose={() => setShowAuditTrail(false)} 
          onUnlockRequest={() => setShowUnlock(true)}
        />
      )}
    </div>
  );
}
