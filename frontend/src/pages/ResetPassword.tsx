import { FormEvent, useState } from 'react'
import { Alert, Box, Button, Container, TextField, Typography } from '@mui/material'
import { Link, useSearchParams } from 'react-router-dom'
import CyberBackground from '../components/auth/CyberBackground'
import { completePasswordReset } from '../services/api'

export default function ResetPassword() {
  const [params] = useSearchParams()
  const [password, setPassword] = useState('')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const submit = async (event: FormEvent) => {
    event.preventDefault()
    try {
      setError('')
      setMessage(await completePasswordReset(params.get('token') || '', password))
    } catch (err: any) {
      setError(err.response?.data?.message || err.response?.data?.detail?.message || 'The reset link is invalid or expired.')
    }
  }
  return <CyberBackground><Container maxWidth="xs"><Box sx={{ pt: 12 }}>
    <Typography variant="h5">Choose a new password</Typography>
    <Typography color="text.secondary">Use a long, unique passphrase (12–128 characters).</Typography>
    {message && <Alert severity="success" sx={{ mt: 2 }}>{message}</Alert>}
    {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
    <Box component="form" onSubmit={submit}>
      <TextField required fullWidth type="password" label="New password" autoComplete="new-password"
        value={password} onChange={(e) => setPassword(e.target.value)} sx={{ my: 2 }} />
      <Button fullWidth type="submit" variant="contained">Reset password</Button>
    </Box>
    <Button component={Link} to="/login" fullWidth sx={{ mt: 1 }}>Back to sign in</Button>
  </Box></Container></CyberBackground>
}
