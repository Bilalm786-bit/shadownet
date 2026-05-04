import { BrowserRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Sidebar from './components/Sidebar';
import TopBar from './components/TopBar';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import CasesPage from './pages/CasesPage';
import CaseDetailPage from './pages/CaseDetailPage';
import GraphPage from './pages/GraphPage';
import DarkWebPage from './pages/DarkWebPage';
import FeedPage from './pages/FeedPage';
import SearchPage from './pages/SearchPage';
import ModulesPage from './pages/ModulesPage';
import CursorAgentPage from './pages/CursorAgentPage';

function ProtectedLayout() {
  const { token, loading } = useAuth();
  if (loading) return <div style={{height:'100vh',display:'flex',alignItems:'center',justifyContent:'center',color:'var(--accent)',fontSize:18}} className="pulse">Loading ShadowNet...</div>;
  if (!token) return <Navigate to="/login" />;
  return (
    <div className="app-layout">
      <Sidebar />
      <div className="main-area">
        <TopBar title="ShadowNet" />
        <main className="page-content"><Outlet /></main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route element={<ProtectedLayout />}>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/cases" element={<CasesPage />} />
            <Route path="/cases/:caseId" element={<CaseDetailPage />} />
            <Route path="/graph/:caseId" element={<GraphPage />} />
            <Route path="/darkweb" element={<DarkWebPage />} />
            <Route path="/feed" element={<FeedPage />} />
            <Route path="/search" element={<SearchPage />} />
            <Route path="/modules" element={<ModulesPage />} />
            <Route path="/cursor-agent" element={<CursorAgentPage />} />
          </Route>
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
