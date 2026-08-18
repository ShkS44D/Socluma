import { useEffect, useState } from 'react'
import { Alert, Box, Button, Container, Typography } from '@mui/material'
import { Link, useSearchParams } from 'react-router-dom'
import CyberBackground from '../components/auth/CyberBackground'
import { confirmEmailVerification } from '../services/api'

export default function VerifyEmail() {
  const [params] = useSearchParams()
  const [message, setMessage] = useState('Verifying your email…')
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    confirmEmailVerification(params.get('token') || '')
      .then(setMessage)
      .catch(() => { setFailed(true); setMessage('This verification link is invalid or expired.') })
  }, [params])
  return <CyberBackground><Container maxWidth="xs"><Box sx={{ pt: 12 }}>
    <Typography variant="h5" gutterBottom>Email verification</Typography>
    <Alert severity={failed ? 'error' : 'info'}>{message}</Alert>
    <Button component={Link} to="/login" fullWidth sx={{ mt: 2 }}>Continue to sign in</Button>
  </Box></Container></CyberBackground>
}
