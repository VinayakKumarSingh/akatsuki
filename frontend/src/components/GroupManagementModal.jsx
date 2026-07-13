import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  generateGroupKey, 
  encryptGroupKeyWithRSA, 
  decryptGroupKeyWithRSA, 
  importPublicKey 
} from '../utils/crypto';
import { fetchPublicUsers, fetchMyKeys } from '../api/documents';

export default function GroupManagementModal({ unlockedPrivateKey, onClose }) {
  const [groups, setGroups] = useState([]);
  const [selectedGroup, setSelectedGroup] = useState(null);
  const [groupName, setGroupName] = useState('');
  const [users, setUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [role, setRole] = useState('MEMBER');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const token = localStorage.getItem('access_token');
  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => {
    fetchGroups();
    loadUsers();
  }, []);

  const fetchGroups = async () => {
    try {
      const res = await axios.get('/api/groups/', { headers });
      setGroups(res.data);
      if (selectedGroup) {
        const updated = res.data.find(g => g.id === selectedGroup.id);
        setSelectedGroup(updated || null);
      }
    } catch (err) {
      setError('Failed to fetch groups.');
    }
  };

  const loadUsers = async () => {
    try {
      const data = await fetchPublicUsers();
      setUsers(data);
    } catch (err) {
      setError('Failed to load registered users.');
    }
  };

  const handleCreateGroup = async (e) => {
    e.preventDefault();
    if (!groupName) return;
    if (!unlockedPrivateKey) {
      setError('Unlock your vault first to generate group keys.');
      return;
    }

    setLoading(true);
    setError('');
    setSuccess('');
    try {
      // 1. Generate Group Symmetric Key
      const groupKey = await generateGroupKey();

      // 2. Fetch my own public key to encrypt the group key for myself
      const myKeys = await fetchMyKeys();
      const myPubKey = await importPublicKey(myKeys.rsa_public_key);

      // 3. Encrypt the group key
      const creatorWrappedKey = await encryptGroupKeyWithRSA(groupKey, myPubKey);

      // 4. Send creation request to server
      const res = await axios.post('/api/groups/', {
        name: groupName,
        creator_wrapped_key: creatorWrappedKey
      }, { headers });

      setGroupName('');
      setSuccess(`Group "${res.data.name}" created successfully!`);
      fetchGroups();
    } catch (err) {
      console.error(err);
      setError('Failed to create group.');
    } finally {
      setLoading(false);
    }
  };

  const handleAddMember = async (e) => {
    e.preventDefault();
    if (!selectedGroup || !selectedUser) return;
    if (!unlockedPrivateKey) {
      setError('Unlock your vault first to decrypt and share group keys.');
      return;
    }

    setLoading(true);
    setError('');
    setSuccess('');

    try {
      // 1. Find my membership in the group to get my encrypted group key
      const myKeys = await fetchMyKeys();
      const myMembership = selectedGroup.memberships.find(m => m.user === myKeys.user_id);
      if (!myMembership) {
        throw new Error("You are not a member of this group.");
      }

      // 2. Decrypt group key using my private key
      const groupKey = await decryptGroupKeyWithRSA(myMembership.encrypted_group_key, unlockedPrivateKey);

      // 3. Import public key of new member
      const memberPubKey = await importPublicKey(selectedUser.rsa_public_key);

      // 4. Encrypt the group key with new member's public key
      const encryptedGroupKey = await encryptGroupKeyWithRSA(groupKey, memberPubKey);

      // 5. POST to server
      await axios.post(`/api/groups/${selectedGroup.id}/add_member/`, {
        user_id: selectedUser.id,
        encrypted_group_key: encryptedGroupKey,
        role
      }, { headers });

      setSuccess(`User ${selectedUser.username} added successfully!`);
      setSelectedUser(null);
      fetchGroups();
    } catch (err) {
      console.error(err);
      setError(err.message || 'Failed to add group member.');
    } finally {
      setLoading(false);
    }
  };

  const handleRemoveMember = async (userId) => {
    if (!selectedGroup) return;
    if (!window.confirm("Are you sure you want to remove this member?")) return;

    setLoading(true);
    setError('');
    setSuccess('');

    try {
      await axios.post(`/api/groups/${selectedGroup.id}/remove_member/`, {
        user_id: userId
      }, { headers });

      setSuccess('Member removed successfully.');
      fetchGroups();
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.error || 'Failed to remove member.');
    } finally {
      setLoading(false);
    }
  };

  // Filter users who are not already members of the selected group
  const nonMembers = selectedGroup 
    ? users.filter(u => !selectedGroup.memberships.some(m => m.user === u.id))
    : [];

  return (
    <div className="modal-overlay" style={{ zIndex: 900 }}>
      <div className="glass-panel modal-content" style={{ padding: '30px', maxWidth: '650px', width: '100%', maxHeight: '85vh', overflowY: 'auto' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px', alignItems: 'center' }}>
          <h3 className="gradient-text">👥 Shared Team Vaults (Groups)</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#fff', fontSize: '1.5rem', cursor: 'pointer' }}>&times;</button>
        </div>

        {error && <div className="error-text" style={{ marginBottom: '16px' }}>{error}</div>}
        {success && <div style={{ color: 'var(--success-color)', marginBottom: '16px', fontSize: '0.875rem' }}>{success}</div>}

        {!selectedGroup ? (
          <div>
            {/* Create Group Form */}
            <form onSubmit={handleCreateGroup} style={{ display: 'flex', gap: '10px', marginBottom: '24px' }}>
              <input 
                type="text" 
                placeholder="Enter Group Name (e.g. Finance Team)"
                value={groupName}
                onChange={(e) => setGroupName(e.target.value)}
                required
                style={{
                  background: 'var(--input-bg)',
                  border: '1px solid var(--glass-border)',
                  borderRadius: '6px',
                  padding: '10px 14px',
                  color: '#fff',
                  fontSize: '0.875rem',
                  flex: 1
                }}
              />
              <button type="submit" className="btn btn-primary" disabled={loading || !unlockedPrivateKey}>
                {loading ? 'Creating...' : 'Create Group'}
              </button>
            </form>

            {!unlockedPrivateKey && (
              <div style={{ color: '#eab308', background: 'rgba(234, 179, 8, 0.1)', padding: '10px 14px', borderRadius: '8px', marginBottom: '20px', fontSize: '0.85rem' }}>
                ⚠️ Please unlock your vault first to create or manage groups.
              </div>
            )}

            {/* Groups List */}
            <h4 style={{ color: '#fff', marginBottom: '12px' }}>Your Groups</h4>
            {groups.length === 0 ? (
              <p style={{ color: '#64748b', fontSize: '0.9rem' }}>You do not belong to any groups yet.</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {groups.map(g => (
                  <div 
                    key={g.id} 
                    onClick={() => setSelectedGroup(g)}
                    style={{
                      padding: '16px',
                      background: 'rgba(255,255,255,0.02)',
                      border: '1px solid var(--glass-border)',
                      borderRadius: '8px',
                      cursor: 'pointer',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      transition: 'all 0.2s ease'
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.05)'}
                    onMouseLeave={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
                  >
                    <div>
                      <div style={{ color: '#fff', fontWeight: '600' }}>{g.name}</div>
                      <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: '4px' }}>
                        Created by: {g.created_by_username} | Members: {g.memberships?.length || 0}
                      </div>
                    </div>
                    <span style={{ color: 'var(--accent-color)', fontSize: '0.875rem' }}>View Members &rarr;</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : (
          <div>
            <button className="btn" style={{ padding: '6px 12px', fontSize: '0.8rem', background: 'rgba(255,255,255,0.1)', color: '#fff', marginBottom: '20px' }} onClick={() => setSelectedGroup(null)}>
              &larr; Back to Groups List
            </button>

            <h4 style={{ color: '#fff', marginBottom: '16px' }}>Group: {selectedGroup.name}</h4>

            {/* Add Member section */}
            <div style={{ background: 'rgba(0,0,0,0.15)', padding: '20px', borderRadius: '10px', border: '1px solid var(--glass-border)', marginBottom: '24px' }}>
              <h5 style={{ color: '#fff', marginBottom: '12px' }}>Add Group Member</h5>
              <form onSubmit={handleAddMember} style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                <select 
                  className="select-input" 
                  value={selectedUser ? selectedUser.id : ''} 
                  onChange={(e) => {
                    const u = nonMembers.find(user => user.id === e.target.value);
                    setSelectedUser(u);
                  }}
                  required
                  style={{ flex: 1, minWidth: '150px' }}
                >
                  <option value="" disabled>-- Select User --</option>
                  {nonMembers.map(u => (
                    <option key={u.id} value={u.id}>{u.username}</option>
                  ))}
                </select>

                <select 
                  className="select-input" 
                  value={role} 
                  onChange={(e) => setRole(e.target.value)}
                  style={{ width: '120px' }}
                >
                  <option value="MEMBER">Member</option>
                  <option value="ADMIN">Admin</option>
                </select>

                <button type="submit" className="btn btn-primary" disabled={loading || !selectedUser || !unlockedPrivateKey}>
                  Add Member
                </button>
              </form>
            </div>

            {/* Members List */}
            <h5 style={{ color: '#fff', marginBottom: '12px' }}>Members ({selectedGroup.memberships?.length || 0})</h5>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {selectedGroup.memberships.map(m => (
                <div 
                  key={m.id} 
                  style={{
                    padding: '12px 16px',
                    background: 'rgba(0,0,0,0.1)',
                    borderRadius: '8px',
                    border: '1px solid var(--glass-border)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center'
                  }}
                >
                  <div>
                    <span style={{ color: '#fff', fontWeight: '500' }}>{m.username}</span>
                    <span style={{
                      marginLeft: '10px',
                      fontSize: '0.7rem',
                      background: m.role === 'ADMIN' ? 'rgba(99, 102, 241, 0.2)' : 'rgba(255,255,255,0.05)',
                      color: m.role === 'ADMIN' ? 'var(--accent-color)' : '#94a3b8',
                      padding: '2px 6px',
                      borderRadius: '4px',
                      fontWeight: '600'
                    }}>
                      {m.role}
                    </span>
                  </div>

                  {selectedGroup.memberships.some(me => me.user === localStorage.getItem('user_id') && me.role === 'ADMIN') && m.user !== localStorage.getItem('user_id') && (
                    <button 
                      className="btn" 
                      style={{ padding: '4px 8px', fontSize: '0.75rem', background: 'rgba(239, 68, 68, 0.1)', color: 'var(--danger-color)' }}
                      onClick={() => handleRemoveMember(m.user)}
                      disabled={loading}
                    >
                      Remove
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
