import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { registerUser } from '../api/auth';

const STANDARD_QUESTIONS = [
  "What was the name of your first pet?",
  "What is your mother's maiden name?",
  "What was the name of your first school?",
  "In what city were you born?",
  "What is your favorite book or movie?"
];

export default function Register() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [questionSelect, setQuestionSelect] = useState(STANDARD_QUESTIONS[0]);
  const [customQuestion, setCustomQuestion] = useState('');
  const [securityAnswer, setSecurityAnswer] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleRegister = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    const finalQuestion = questionSelect === 'custom' ? customQuestion.trim() : questionSelect;
    if (!finalQuestion) {
      setError('Please provide a security question.');
      setLoading(false);
      return;
    }
    if (!securityAnswer.trim()) {
      setError('Please provide a security answer.');
      setLoading(false);
      return;
    }

    try {
      // The crypto magic happens inside registerUser
      await registerUser(username, password, finalQuestion, securityAnswer.trim());
      navigate('/login');
    } catch (err) {
      setError('Registration failed. Username might be taken.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="glass-panel auth-card">
        <h2 style={{ marginBottom: '8px' }} className="gradient-text">Create Account</h2>
        <p style={{ color: '#94a3b8', marginBottom: '32px', fontSize: '0.9rem' }}>
          Your cryptographic keys will be generated locally.
        </p>

        {error && <div className="error-text">{error}</div>}

        <form onSubmit={handleRegister}>
          <div className="input-group">
            <label>Username</label>
            <input 
              type="text" 
              placeholder="Choose a username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required 
            />
          </div>
          <div className="input-group">
            <label>Master Password</label>
            <input 
              type="password" 
              placeholder="Must be strong"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required 
              minLength={8}
            />
          </div>

          <div className="input-group">
            <label>Security Question</label>
            <select
              className="select-input"
              value={questionSelect}
              onChange={(e) => setQuestionSelect(e.target.value)}
              style={{ width: '100%' }}
            >
              {STANDARD_QUESTIONS.map((q, idx) => (
                <option key={idx} value={q}>{q}</option>
              ))}
              <option value="custom">Write my own question...</option>
            </select>
          </div>

          {questionSelect === 'custom' && (
            <div className="input-group">
              <label>Custom Security Question</label>
              <input 
                type="text" 
                placeholder="Enter your custom question"
                value={customQuestion}
                onChange={(e) => setCustomQuestion(e.target.value)}
                required 
              />
            </div>
          )}

          <div className="input-group" style={{ marginBottom: '32px' }}>
            <label>Security Answer</label>
            <input 
              type="text" 
              placeholder="Enter your secret answer"
              value={securityAnswer}
              onChange={(e) => setSecurityAnswer(e.target.value)}
              required 
            />
          </div>

          <button 
            type="submit" 
            className="btn btn-primary" 
            style={{ width: '100%' }}
            disabled={loading}
          >
            {loading ? 'Generating Keys...' : 'Register Securely'}
          </button>
        </form>

        <p style={{ textAlign: 'center', marginTop: '24px', fontSize: '0.875rem', color: '#94a3b8' }}>
          Already have an account? <Link to="/login" style={{ color: 'var(--accent-color)', textDecoration: 'none' }}>Sign In</Link>
        </p>
      </div>
    </div>
  );
}
