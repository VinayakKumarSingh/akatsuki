import React, { useEffect } from 'react';

export default function PreviewModal({ fileBlob, filename, onClose }) {
  const fileUrl = URL.createObjectURL(fileBlob);
  const extension = filename.split('.').pop().toLowerCase();
  
  const isImage = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'].includes(extension);
  const isPdf = extension === 'pdf';
  const isText = ['txt', 'log', 'json', 'js', 'py', 'md', 'html', 'css', 'go', 'sh', 'bat'].includes(extension);

  useEffect(() => {
    return () => {
      URL.revokeObjectURL(fileUrl);
    };
  }, [fileUrl]);

  return (
    <div className="modal-overlay" style={{ zIndex: 1100 }}>
      <div className="glass-panel modal-content" style={{ padding: '30px', maxWidth: '800px', width: '90%', height: '80vh', display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px', alignItems: 'center' }}>
          <h3 className="gradient-text">📄 File Preview: {filename}</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#fff', fontSize: '1.5rem', cursor: 'pointer' }}>&times;</button>
        </div>

        <div style={{ flex: 1, background: 'rgba(0,0,0,0.3)', borderRadius: '8px', overflow: 'hidden', display: 'flex', justifyContent: 'center', alignItems: 'center', border: '1px solid var(--glass-border)' }}>
          {isImage ? (
            <img src={fileUrl} alt={filename} style={{ maxWidth: '100%', maxHeight: '100%', objectFit: 'contain' }} />
          ) : isPdf ? (
            <iframe src={fileUrl} title={filename} style={{ width: '100%', height: '100%', border: 'none' }} />
          ) : isText ? (
            <iframe src={fileUrl} title={filename} style={{ width: '100%', height: '100%', border: 'none', background: '#0a0f1d' }} />
          ) : (
            <div style={{ textAlign: 'center', color: '#94a3b8', padding: '20px' }}>
              <div style={{ fontSize: '3rem', marginBottom: '16px' }}>👁️</div>
              <p>Preview not supported natively for <strong>.{extension}</strong> files.</p>
              <p style={{ fontSize: '0.85rem', color: '#64748b', marginTop: '8px' }}>Please use the Decrypt & Download option to view this file offline.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
