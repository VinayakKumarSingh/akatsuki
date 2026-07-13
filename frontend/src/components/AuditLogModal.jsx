import React, { useEffect, useState } from 'react';
import { fetchAuditLogs } from '../api/documents';
import { decryptAuditLog } from '../utils/crypto';

export default function AuditLogModal({ cachedPrivateKey, onClose, onUnlockRequest }) {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const loadAndDecryptLogs = async () => {
      if (!cachedPrivateKey) {
        setLoading(false);
        return;
      }
      try {
        const rawLogs = await fetchAuditLogs();
        const decryptedLogsList = [];
        
        for (const logObj of rawLogs) {
          try {
            const decStr = await decryptAuditLog(logObj.encrypted_log, cachedPrivateKey);
            const decObj = JSON.parse(decStr);
            decryptedLogsList.push({
              id: logObj.id,
              created_at: logObj.created_at,
              ...decObj
            });
          } catch (e) {
            console.error("Failed to decrypt log entry", e);
            decryptedLogsList.push({
              id: logObj.id,
              created_at: logObj.created_at,
              action: "UNKNOWN",
              document_id: "N/A",
              details: "[Unreadable log entry - decryption key mismatch]"
            });
          }
        }
        setLogs(decryptedLogsList);
      } catch (err) {
        setError('Failed to load audit logs.');
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    loadAndDecryptLogs();
  }, [cachedPrivateKey]);

  return (
    <div className="modal-overlay">
      <div className="glass-panel modal-content" style={{ padding: '30px', maxWidth: '700px', width: '100%', maxHeight: '80vh', overflowY: 'auto' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px' }}>
          <h3 className="gradient-text">🔒 Encrypted Audit Trail</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#fff', fontSize: '1.5rem', cursor: 'pointer' }}>&times;</button>
        </div>

        {error && <div className="error-text">{error}</div>}

        {!cachedPrivateKey ? (
          <div style={{ textAlign: 'center', padding: '30px 10px' }}>
            <p style={{ color: '#94a3b8', marginBottom: '20px' }}>
              Audit logs are hybrid-encrypted client-side using your public key. You must unlock your vault first to load and decrypt them.
            </p>
            <button className="btn btn-primary" onClick={() => { onClose(); onUnlockRequest(); }}>
              Unlock Vault
            </button>
          </div>
        ) : loading ? (
          <div style={{ textAlign: 'center', padding: '40px', color: '#94a3b8' }}>
            Decrypting audit records in-browser...
          </div>
        ) : logs.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px', color: '#94a3b8' }}>
            No audit records found.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid var(--glass-border)', color: '#64748b', textAlign: 'left' }}>
                  <th style={{ padding: '10px' }}>Timestamp</th>
                  <th style={{ padding: '10px' }}>Action</th>
                  <th style={{ padding: '10px' }}>Document ID</th>
                  <th style={{ padding: '10px' }}>Details</th>
                </tr>
              </thead>
              <tbody>
                {logs.map(log => (
                  <tr key={log.id} style={{ borderBottom: '1px solid var(--glass-border)', color: '#fff' }}>
                    <td style={{ padding: '10px', whiteSpace: 'nowrap', color: '#94a3b8' }}>
                      {new Date(log.created_at || log.timestamp).toLocaleString()}
                    </td>
                    <td style={{ padding: '10px' }}>
                      <span style={{
                        padding: '2px 8px',
                        borderRadius: '4px',
                        fontWeight: '600',
                        fontSize: '0.75rem',
                        background: log.action === 'UPLOAD' ? 'rgba(16, 185, 129, 0.2)' :
                                    log.action === 'DOWNLOAD' ? 'rgba(99, 102, 241, 0.2)' :
                                    log.action === 'SHARE' ? 'rgba(234, 179, 8, 0.2)' :
                                    log.action === 'DELETE' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(255,255,255,0.1)',
                        color: log.action === 'UPLOAD' ? 'var(--success-color)' :
                               log.action === 'DOWNLOAD' ? 'var(--accent-color)' :
                               log.action === 'SHARE' ? '#eab308' :
                               log.action === 'DELETE' ? 'var(--danger-color)' : '#fff'
                      }}>
                        {log.action}
                      </span>
                    </td>
                    <td style={{ padding: '10px' }}>
                      <code style={{ fontSize: '0.75rem' }}>{log.document_id || 'N/A'}</code>
                    </td>
                    <td style={{ padding: '10px', color: '#cbd5e1' }}>
                      {log.details}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
