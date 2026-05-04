import { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import { HiOutlineShieldCheck } from 'react-icons/hi';

export default function LoginPage() {
  const { login, register } = useAuth();
  const navigate = useNavigate();
  const [isRegister, setIsRegister] = useState(false);
  const [form, setForm] = useState({ username: '', password: '', email: '', full_name: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(''); setLoading(true);
    try {
      if (isRegister) {
        await register({ email: form.email, username: form.username, password: form.password, full_name: form.full_name });
        setIsRegister(false);
        setError('');
      } else {
        await login(form.username, form.password);
        navigate('/');
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Authentication failed');
    }
    setLoading(false);
  };

  return (
    <div className="login-page">
      <div style={{position:'absolute',inset:0,background:'radial-gradient(ellipse at 30% 20%,rgba(99,102,241,0.08) 0%,transparent 60%),radial-gradient(ellipse at 70% 80%,rgba(6,182,212,0.06) 0%,transparent 50%)',pointerEvents:'none'}} />
      <div className="card login-card fade-in" style={{position:'relative',zIndex:1}}>
        <div style={{textAlign:'center',marginBottom:8}}>
          <HiOutlineShieldCheck style={{fontSize:40,color:'var(--accent)'}} />
        </div>
        <h1 className="login-title">ShadowNet</h1>
        <p className="login-sub">{isRegister ? 'Create your analyst account' : 'OSINT Intelligence Platform'}</p>
        {error && <div style={{background:'rgba(239,68,68,0.1)',border:'1px solid rgba(239,68,68,0.3)',borderRadius:8,padding:'10px 14px',marginBottom:16,fontSize:13,color:'#ef4444'}}>{error}</div>}
        <form className="login-form" onSubmit={handleSubmit}>
          {isRegister && (
            <>
              <div className="input-group">
                <label>Full Name</label>
                <input className="input" value={form.full_name} onChange={e => setForm({...form, full_name: e.target.value})} placeholder="John Doe" />
              </div>
              <div className="input-group">
                <label>Email</label>
                <input className="input" type="email" value={form.email} onChange={e => setForm({...form, email: e.target.value})} placeholder="analyst@shadownet.io" required />
              </div>
            </>
          )}
          <div className="input-group">
            <label>Username</label>
            <input className="input" value={form.username} onChange={e => setForm({...form, username: e.target.value})} placeholder="analyst" required />
          </div>
          <div className="input-group">
            <label>Password</label>
            <input className="input" type="password" value={form.password} onChange={e => setForm({...form, password: e.target.value})} placeholder="••••••••" required />
          </div>
          <button className="btn btn-primary" type="submit" disabled={loading}>
            {loading ? 'Processing...' : isRegister ? 'Create Account' : 'Sign In'}
          </button>
        </form>
        <p style={{textAlign:'center',marginTop:20,fontSize:13,color:'var(--text-muted)'}}>
          {isRegister ? 'Already have an account?' : "Don't have an account?"}{' '}
          <span style={{color:'var(--accent)',cursor:'pointer',fontWeight:600}} onClick={() => {setIsRegister(!isRegister); setError('');}}>
            {isRegister ? 'Sign In' : 'Register'}
          </span>
        </p>
      </div>
    </div>
  );
}
