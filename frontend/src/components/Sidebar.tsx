import { NavLink } from 'react-router-dom';
import { HiOutlineViewGrid, HiOutlineFolder, HiOutlineGlobe, HiOutlineBell,
  HiOutlineSearch, HiOutlineChartBar, HiOutlineShieldCheck, HiOutlineLightningBolt,
  HiOutlineUser, HiOutlineGlobeAlt, HiOutlineCode, HiOutlineShieldExclamation,
  HiOutlineFire, HiOutlineDocumentReport } from 'react-icons/hi';

const investigateItems = [
  { to: '/investigate/person', icon: <HiOutlineUser />, label: 'Person Intel' },
  { to: '/investigate/network', icon: <HiOutlineGlobeAlt />, label: 'Network Intel' },
  { to: '/investigate/website', icon: <HiOutlineCode />, label: 'Website Intel' },
  { to: '/investigate/exploit', icon: <HiOutlineFire />, label: 'Exploit Surface' },
  { to: '/investigate/vuln-scan', icon: <HiOutlineDocumentReport />, label: 'Vuln Scanner' },
];

const navItems = [
  { to: '/', icon: <HiOutlineViewGrid />, label: 'Dashboard' },
  { to: '/investigate', icon: <HiOutlineShieldExclamation />, label: 'Auto-Investigate' },
  { to: '/threat-intel', icon: <HiOutlineShieldCheck />, label: 'Threat Intel' },
  { to: '/cases', icon: <HiOutlineFolder />, label: 'Cases' },
  { to: '/darkweb', icon: <HiOutlineGlobe />, label: 'Dark Web' },
  { to: '/feed', icon: <HiOutlineBell />, label: 'Live Feed' },
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
        <div className="nav-section">Investigations</div>
        {investigateItems.map(item => (
          <NavLink key={item.to} to={item.to}
            className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            {item.icon}<span>{item.label}</span>
          </NavLink>
        ))}

        <div className="nav-section">Operations</div>
        {navItems.map(item => (
          <NavLink key={item.to} to={item.to} end={item.to === '/'}
            className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            {item.icon}<span>{item.label}</span>
          </NavLink>
        ))}

        <div className="nav-section">Tools</div>
        {toolItems.map(item => (
          <NavLink key={item.to} to={item.to}
            className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            {item.icon}<span>{item.label}</span>
          </NavLink>
        ))}
      </nav>
      <div style={{ padding: '16px 24px', borderTop: '1px solid var(--border-glass)', fontSize: 11, color: 'var(--text-muted)' }}>
        <HiOutlineShieldCheck style={{ marginRight: 6, verticalAlign: 'middle' }} />
        ShadowNet v2.0.0
      </div>
    </aside>
  );
}
