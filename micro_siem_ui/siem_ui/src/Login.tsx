import { useEffect, useState } from 'react';
import './Login.css'; // We'll create this later

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000';

declare global {
  interface Window {
    google: {
      accounts: {
        id: {
          initialize: (config: { client_id: string; callback: (response: any) => void }) => void;
          renderButton: (element: HTMLElement | null, options: { theme: string; size: string }) => void;
        };
      };
    };
    handleCredentialResponse: (response: any) => void;
  }
}

interface LoginProps {
  onLogin: (user: string, token: string) => void;
}



function Login({ onLogin }: LoginProps) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    const initializeGoogleSignIn = () => {
      if (window.google && window.google.accounts) {
        window.google.accounts.id.initialize({
          client_id: import.meta.env.VITE_GOOGLE_CLIENT_ID,
          callback: handleCredentialResponse,
        });
        window.google.accounts.id.renderButton(
          document.getElementById('google-signin-btn'),
          { theme: 'outline', size: 'large' }
        );
      }
    };

    if (window.google) {
      initializeGoogleSignIn();
    } else {
      window.addEventListener('load', initializeGoogleSignIn);
    }

    return () => {
      window.removeEventListener('load', initializeGoogleSignIn);
    };
  }, []);

  const handleCredentialResponse = async (response: any) => {
    try {
      const res = await fetch(`${API_BASE_URL}/google_login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ token: response.credential }),
      });
      if (res.ok) {
        const data = await res.json();
        // Decode the JWT token to get user info for display
        const userObject = JSON.parse(atob(response.credential.split('.')[1]));
        onLogin(userObject.name || userObject.email, data.access_token);
      } else {
        setError('Google login failed');
      }
    } catch (err) {
      setError('Login failed');
    }
  };

  window.handleCredentialResponse = handleCredentialResponse;

  const handleUsernameLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (username && password) {
      try {
        const response = await fetch(`${API_BASE_URL}/login`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ username, password }),
        });
        if (response.ok) {
          const data = await response.json();
          onLogin(username, data.access_token);
        } else {
          setError('Invalid credentials');
        }
      } catch (err) {
        setError('Login failed');
      }
    } else {
      setError('Please enter both username and password');
    }
  };

  return (
    <div className="login-container">
      <div className="login-form">
        <h2>Login</h2>
        <form onSubmit={handleUsernameLogin}>
          <div className="form-group">
            <label htmlFor="username">Username:</label>
            <input
              type="text"
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="password">Password:</label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          {error && <p className="error">{error}</p>}
          <button type="submit" className="login-btn">Login</button>
        </form>
        <div className="divider">or</div>
        <div id="google-signin-btn"></div>
      </div>
    </div>
  );
}

export default Login;