import { useState } from 'react'
import Anomalies from './Analysis.tsx'
import './App.css'
import FileUpload from './FileUpload.tsx'
import Login from './Login.tsx'

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [user, setUser] = useState('')
  const [token, setToken] = useState('')
  const [uploadSuccess, setUploadSuccess] = useState(false)
  const [fileId, setFileId] = useState('')

  const handleLogin = (loggedInUser: string, authToken: string) => {
    setUser(loggedInUser);
    setToken(authToken);
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    setUser('');
    setToken('');
    setIsAuthenticated(false);
    setUploadSuccess(false);
  };

  const handleUploadSuccess = (fileId: string) => {
    setFileId(fileId);
    setUploadSuccess(true);
  };

  const handleBackToUpload = () => {
    setUploadSuccess(false);
  };

  return (
    <>
      {isAuthenticated ? (
        uploadSuccess ? (
          <Anomalies onBack={handleBackToUpload} token={token} fileId={fileId} />
        ) : (
          <FileUpload onLogout={handleLogout} token={token} onUploadSuccess={handleUploadSuccess} user={user} />
        )
      ) : (
        <Login onLogin={handleLogin} />
      )}
    </>
  )
}

export default App
