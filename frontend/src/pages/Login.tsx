import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import {
  Box,
  Button,
  Container,
  CssBaseline,
  TextField,
  Typography,
  Alert,
  CircularProgress
} from '@mui/material'
import { completeMfaLogin, login } from '../services/api'
import { useAuthStore } from '../store'
import CyberBackground from '../components/auth/CyberBackground'

const Login: React.FC = () => {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [challengeToken, setChallengeToken] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  const [useRecoveryCode, setUseRecoveryCode] = useState(false)
  const navigate = useNavigate()
  const authLogin = useAuthStore((state) => state.login)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const response = challengeToken
        ? await completeMfaLogin({
            challenge_token: challengeToken,
            code: mfaCode,
            recovery_code: useRecoveryCode,
          })
        : await login({ email, password })
      if (response.mfa_required && response.challenge_token) {
        setChallengeToken(response.challenge_token)
        return
      }
      if (!response.access_token) throw new Error('Authentication did not return an access token')
      authLogin(response.access_token, response.refresh_token)
      navigate('/dashboard')
    } catch (err: any) {
      setError(
        err.response?.data?.message || err.response?.data?.detail?.message ||
        err.response?.data?.detail || 'Login failed. Please check your credentials.'
      )
    } finally {
      setLoading(false)
    }
  }

  return (
    <CyberBackground><Container component="main" maxWidth="xs">
      <CssBaseline />
      <Box
        sx={{
          marginTop: 8,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
        }}
      >
        <Typography component="h1" variant="h5">
          TriageOps Login
        </Typography>
        <Box component="form" onSubmit={handleSubmit} sx={{ mt: 1, width: '100%' }}>
          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}
          {!challengeToken && <><TextField
            margin="normal"
            required
            fullWidth
            id="email"
            label="Email Address"
            name="email"
            autoComplete="email"
            autoFocus
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <TextField
            margin="normal"
            required
            fullWidth
            name="password"
            label="Password"
            type="password"
            id="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          /></>}
          {challengeToken && (
            <>
              <Alert severity="info" sx={{ mt: 2 }}>
                Enter the code from your authenticator app, or use a recovery code.
              </Alert>
              <TextField
                margin="normal"
                required
                fullWidth
                label={useRecoveryCode ? 'Recovery code' : '6-digit authentication code'}
                value={mfaCode}
                onChange={(event) => setMfaCode(event.target.value)}
                inputProps={{ inputMode: useRecoveryCode ? 'text' : 'numeric', autoComplete: 'one-time-code' }}
                autoFocus
              />
              <Button type="button" onClick={() => setUseRecoveryCode((value) => !value)}>
                {useRecoveryCode ? 'Use authenticator code' : 'Use a recovery code'}
              </Button>
            </>
          )}
          <Button
            type="submit"
            fullWidth
            variant="contained"
            sx={{ mt: 3, mb: 2 }}
            disabled={loading}
          >
            {loading ? <CircularProgress size={24} /> : challengeToken ? 'Verify and sign in' : 'Sign In'}
          </Button>
          <Box sx={{ textAlign: 'center' }}>
            {!challengeToken && <><Link to="/forgot-password" style={{ textDecoration: 'none' }}>
              <Typography variant="body2" sx={{ mb: 1 }}>Forgot password?</Typography>
            </Link>
            <Link to="/register" style={{ textDecoration: 'none' }}>
              <Typography variant="body2">
                Don't have an account? Sign Up
              </Typography>
            </Link></>}
          </Box>
        </Box>
      </Box>
    </Container></CyberBackground>
  )
}

export default Login
