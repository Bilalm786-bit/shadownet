import { NavLink, useLocation } from 'react-router-dom';
import { HiOutlineViewGrid, HiOutlineFolder, HiOutlineGlobe, HiOutlineBell,
  HiOutlineSearch, HiOutlineChartBar, HiOutlineShieldCheck, HiOutlineCog, HiOutlineLightningBolt } from 'react-icons/hi';

const navItems = [
  { to: '/', icon: <HiOutlineViewGrid />, label: 'Dashboard' },
  { to: '/cases', icon: <HiOutlineFolder />, label: 'Investigations' },
  { to: '/darkweb', icon: <HiOutlineGlobe />, label: 'Dark Web' },
  { to: '/feed', icon: <HiOutlineBell />, label: 'Live Intel Feed' },
];

const toolItems = [
  { to: '/search', icon: <HiOutlineSearch />, label: 'Intel Search' },
  { to: '/modules', icon: <HiOutlineChartBar />, label: 'OSINT Modules' },
  { to: '/cursor-agent', icon: <HiOutlineLightningBolt />, label: 'Cloud Agent' },
];

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-logo">⬡ ShadowNet</div>
      <nav className="sidebar-nav">
        <div className="nav-section">Operations</div>
        {navItems.map(item => (
          <NavLink key={item.to} to={item.to} end={item.to === '/'}
            className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            {item.icon}<span>{item.label}</span>
          </NavLink>
        ))}
        <div className="nav-section" style={{ marginTop: 16 }}>Tools</div>
        {toolItems.map(item => (
          <NavLink key={item.to} to={item.to}
            className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            {item.icon}<span>{item.label}</span>
          </NavLink>
        ))}
      </nav>
      <div style={{ padding: '16px 24px', borderTop: '1px solid var(--border-glass)', fontSize: 11, color: 'var(--text-muted)' }}>
        <HiOutlineShieldCheck style={{ marginRight: 6, verticalAlign: 'middle' }} />
        ShadowNet v1.0.0
      </div>
    </aside>
  );
}
