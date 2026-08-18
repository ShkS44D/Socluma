import { FormEvent, useState } from 'react'
import { Alert, Box, Button, Container, TextField, Typography } from '@mui/material'
import { Link } from 'react-router-dom'
import CyberBackground from '../components/auth/CyberBackground'
import { requestPasswordReset } from '../services/api'

export default function ForgotPassword() {
  const [email, setEmail] = useState('')
  const [message, setMessage] = useState('')
  const submit = async (event: FormEvent) => {
    event.preventDefault()
    setMessage(await requestPasswordReset(email))
  }
  return <CyberBackground><Container maxWidth="xs"><Box sx={{ pt: 12 }}>
    <Typography variant="h5" gutterBottom>Reset your password</Typography>
    <Typography color="text.secondary">Enter your email. The response is the same for every address.</Typography>
    {message && <Alert severity="success" sx={{ mt: 2 }}>{message}</Alert>}
    <Box component="form" onSubmit={submit}>
      <TextField required fullWidth type="email" label="Email address" autoComplete="email"
        value={email} onChange={(e) => setEmail(e.target.value)} sx={{ my: 2 }} />
      <Button fullWidth type="submit" variant="contained">Send reset link</Button>
    </Box>
    <Button component={Link} to="/login" fullWidth sx={{ mt: 1 }}>Back to sign in</Button>
  </Box></Container></CyberBackground>
}
