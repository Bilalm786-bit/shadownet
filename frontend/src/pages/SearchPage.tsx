import { useState } from 'react';
import { searchAPI } from '../api/client';
import { HiOutlineSearch } from 'react-icons/hi';

export default function SearchPage() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;
    setLoading(true); setSearched(true);
    try {
      const res = await searchAPI.search(query);
      setResults(res.data.results || []);
    } catch { setResults([]); }
    setLoading(false);
  };

  return (
    <div className="fade-in">
      <div className="section-header"><h2 className="section-title">Intel Search</h2></div>
      <div className="card" style={{ marginBottom: 24 }}>
        <form onSubmit={handleSearch} style={{ display: 'flex', gap: 12 }}>
          <div style={{ flex: 1, position: 'relative' }}>
            <HiOutlineSearch style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            <input className="input" style={{ paddingLeft: 40 }} value={query} onChange={e => setQuery(e.target.value)} placeholder="Search across all intelligence data..." />
          </div>
          <button className="btn btn-primary" type="submit" disabled={loading}>{loading ? 'Searching...' : 'Search'}</button>
        </form>
      </div>
      {loading && <div className="empty-state pulse">Searching Elasticsearch...</div>}
      {!loading && searched && results.length === 0 && <div className="card empty-state"><p>No results found for "{query}"</p></div>}
      {results.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <p style={{ fontSize: 13, color: 'var(--text-muted)' }}>{results.length} results</p>
          {results.map((r: any, i: number) => (
            <div className="card" key={i} style={{ padding: 16 }}>
              <div style={{ display: 'flex', gap: 8, marginBottom: 6 }}>
                {r.module && <span className="badge badge-info">{r.module}</span>}
                {r.severity && <span className={`badge badge-${r.severity}`}>{r.severity}</span>}
                {r.entity_type && <span className="badge badge-medium">{r.entity_type}</span>}
              </div>
              <p style={{ fontSize: 14, lineHeight: 1.5 }}>{r.content || JSON.stringify(r).slice(0, 200)}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
