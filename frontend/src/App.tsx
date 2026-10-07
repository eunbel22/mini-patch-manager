import { NavLink, Route, Routes } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import EndpointDetail from './pages/EndpointDetail'
import Endpoints from './pages/Endpoints'
import PolicyDetail from './pages/PolicyDetail'
import PolicyEdit from './pages/PolicyEdit'
import Policies from './pages/Policies'
import Search from './pages/Search'

function Placeholder({ title }: { title: string }) {
  return (
    <main className="page">
      <h1>{title}</h1>
      <div className="notice">이 화면은 아직 만들지 않았습니다.</div>
    </main>
  )
}

export default function App() {
  return (
    <>
      <header className="topbar">
        <span className="brand">mini-patch-manager</span>
        <nav className="nav" aria-label="주 메뉴">
          <NavLink to="/" end>
            대시보드
          </NavLink>
          <NavLink to="/search">검색</NavLink>
          <NavLink to="/endpoints">PC 목록</NavLink>
          <NavLink to="/policies">정책</NavLink>
        </nav>
      </header>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/search" element={<Search />} />
        <Route path="/endpoints" element={<Endpoints />} />
        <Route path="/endpoints/:id" element={<EndpointDetail />} />
        <Route path="/policies" element={<Policies />} />
        <Route path="/policies/new" element={<PolicyEdit />} />
        <Route path="/policies/:id" element={<PolicyDetail />} />
        <Route path="/policies/:id/edit" element={<PolicyEdit />} />
        <Route path="*" element={<Placeholder title="페이지를 찾을 수 없습니다" />} />
      </Routes>
    </>
  )
}
