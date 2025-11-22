import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { Layout } from './components/Layout'
import { LiveAttacksPage } from './pages/LiveAttacksPage'
import { RiskAnalysisPage } from './pages/RiskAnalysisPage'
import { AttackDetailsPage } from './pages/AttackDetailsPage'
import { SessionViewPage } from './pages/SessionViewPage'

function App() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<LiveAttacksPage />} />
          <Route path="/risk-analysis" element={<RiskAnalysisPage />} />
          <Route path="/attack/:attackId" element={<AttackDetailsPage />} />
          <Route path="/session/:sessionId" element={<SessionViewPage />} />
        </Routes>
      </Layout>
    </Router>
  )
}

export default App

