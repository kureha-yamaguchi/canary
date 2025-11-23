import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { Layout } from './components/Layout'
import { LiveAttacksPage } from './pages/LiveAttacksPage'
import { AttackDetailsPage } from './pages/AttackDetailsPage'
import { SessionViewPage } from './pages/SessionViewPage'
import { MatrixMapPage } from './pages/MatrixMapPage'
import { AgentTrajectoryPage } from './pages/AgentTrajectoryPage'
import { TTPPredictionPage } from './pages/TTPPredictionPage'

function App() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<LiveAttacksPage />} />
          <Route path="/matrix-map" element={<MatrixMapPage />} />
          <Route path="/agent-trajectory" element={<AgentTrajectoryPage />} />
          <Route path="/ttp-prediction" element={<TTPPredictionPage />} />
          <Route path="/attack/:attackId" element={<AttackDetailsPage />} />
          <Route path="/session/:sessionId" element={<SessionViewPage />} />
        </Routes>
      </Layout>
    </Router>
  )
}

export default App

