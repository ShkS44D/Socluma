import { useEffect, useState } from 'react'
import {
  Alert, Box, Button, Card, CardContent, Chip, Dialog, DialogActions, DialogContent,
  DialogTitle, Divider, Stack, TextField, Typography,
} from '@mui/material'
import {
  confirmMfa, disableMfa, getAccountSecurityStatus, getAuthSecurityEvents, getAuthSessions,
  logoutAll, regenerateRecoveryCodes, requestEmailVerification, revokeAuthSession, startMfa,
} from '../services/api'
import type { AccountSecurityStatus, AuthSecurityEvent, AuthSession } from '../services/api'
import { useAuthStore } from '../store'

type Enrollment = { qr_code_data_url: string; manual_key: string; provisioning_uri: string; expires_at: string }

export default function AccountSecurity() {
  const [status, setStatus] = useState<AccountSecurityStatus>()
  const [sessions, setSessions] = useState<AuthSession[]>([])
  const [events, setEvents] = useState<AuthSecurityEvent[]>([])
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [enrollment, setEnrollment] = useState<Enrollment>()
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([])
  const [error, setError] = useState('')
  const logout = useAuthStore((state) => state.logout)
  const user = useAuthStore((state) => state.user)

  const load = async () => {
    const [nextStatus, nextSessions, nextEvents] = await Promise.all([
      getAccountSecurityStatus(), getAuthSessions(), getAuthSecurityEvents(),
    ])
    setStatus(nextStatus); setSessions(nextSessions); setEvents(nextEvents)
  }
  useEffect(() => { load().catch(() => setError('Unable to load account-security data.')) }, [])
  const run = async (action: () => Promise<void>) => {
    try { setError(''); await action(); await load() }
    catch (err: any) { setError(err.response?.data?.message || err.response?.data?.detail?.message || 'Request failed.') }
  }
  const downloadCodes = () => {
    const url = URL.createObjectURL(new Blob([recoveryCodes.join('\n')], { type: 'text/plain' }))
    const link = document.createElement('a'); link.href = url; link.download = 'triageops-recovery-codes.txt'; link.click()
    URL.revokeObjectURL(url)
  }

  return <Box sx={{ p: 3, maxWidth: 1100, mx: 'auto' }}>
    <Typography variant="h4" gutterBottom>Account Security</Typography>
    <Typography color="text.secondary" sx={{ mb: 3 }}>Manage MFA, recovery codes, sessions, and recent security activity.</Typography>
    {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
    {events.some((event) => event.severity !== 'informational') &&
      <Alert severity="warning" sx={{ mb: 2 }}>Your history contains suspicious or critical authentication activity. Review it below.</Alert>}
    {status && !status.email_verified && <Alert severity="warning" sx={{ mb: 2 }} action={
      <Button color="inherit" onClick={() => run(async () => {
        if (user?.email) await requestEmailVerification(user.email)
      })}>Resend verification</Button>
    }>Verify your email address before normal interactive access is required.</Alert>}

    <Card variant="outlined"><CardContent>
      <Stack direction={{ xs: 'column', md: 'row' }} justifyContent="space-between" gap={2}>
        <Box><Typography variant="h6">Authenticator MFA</Typography>
          <Typography color="text.secondary">{status?.mfa_enabled ? `Enabled · ${status.recovery_codes_remaining} recovery codes remain` : 'Not enabled'}</Typography>
        </Box>
        {!status?.mfa_enabled
          ? <Button variant="contained" onClick={() => run(async () => setEnrollment(await startMfa(password)))}>Start setup</Button>
          : <Stack direction="row" gap={1}>
              <Button onClick={() => window.confirm('Invalidate all existing recovery codes?') &&
                run(async () => setRecoveryCodes(await regenerateRecoveryCodes(password, code)))}>Regenerate codes</Button>
              <Button color="error" onClick={() => window.confirm('Disable MFA for this account?') &&
                run(() => disableMfa(password, code))}>Disable MFA</Button>
            </Stack>}
      </Stack>
      <Stack direction={{ xs: 'column', sm: 'row' }} gap={2} sx={{ mt: 2 }}>
        <TextField type="password" label="Current password" value={password} onChange={(e) => setPassword(e.target.value)}
          inputProps={{ autoComplete: 'current-password' }} />
        {status?.mfa_enabled && <TextField label="6-digit code" value={code} onChange={(e) => setCode(e.target.value)}
          inputProps={{ inputMode: 'numeric', autoComplete: 'one-time-code', maxLength: 6 }} />}
      </Stack>
    </CardContent></Card>

    <Card variant="outlined" sx={{ mt: 3 }}><CardContent>
      <Stack direction="row" justifyContent="space-between"><Typography variant="h6">Sessions</Typography>
        <Button color="error" onClick={() => run(async () => { await logoutAll(); logout() })}>Log out all devices</Button></Stack>
      {sessions.map((session) => <Box key={session.id} sx={{ py: 1.5 }}>
        <Stack direction="row" justifyContent="space-between" alignItems="center">
          <Box><Typography>{session.device_label || 'Unknown device'} {session.current && <Chip size="small" label="Current" />}</Typography>
            <Typography variant="body2" color="text.secondary">{session.ip_address || 'Unknown IP'} · {new Date(session.created_at).toLocaleString()}</Typography></Box>
          {!session.revoked_at && <Button color="error" onClick={() => window.confirm('Revoke this session?') &&
            run(() => revokeAuthSession(session.id))}>Revoke</Button>}
        </Stack><Divider sx={{ mt: 1.5 }} />
      </Box>)}
    </CardContent></Card>

    <Card variant="outlined" sx={{ mt: 3 }}><CardContent><Typography variant="h6">Login and security history</Typography>
      {events.map((event) => <Box key={event.id} sx={{ py: 1.5 }}>
        <Stack direction="row" gap={1} alignItems="center"><Typography sx={{ flex: 1 }}>{event.event_type.replace(/_/g, ' ')}</Typography>
          <Chip size="small" color={event.severity === 'critical' ? 'error' : event.severity === 'suspicious' ? 'warning' : 'default'} label={event.severity} /></Stack>
        <Typography variant="body2" color="text.secondary">{new Date(event.created_at).toLocaleString()} · {event.device_label || 'Unknown device'} · {event.ip_address || 'Unknown IP'}{event.reason_code ? ` · ${event.reason_code}` : ''}</Typography>
      </Box>)}
    </CardContent></Card>

    <Dialog open={Boolean(enrollment)} onClose={() => setEnrollment(undefined)} maxWidth="sm" fullWidth>
      <DialogTitle>Set up authenticator MFA</DialogTitle><DialogContent>
        <Alert severity="info" sx={{ mb: 2 }}>Scan this QR code, then enter the current 6-digit code. MFA is not active until confirmed.</Alert>
        {enrollment && <Stack alignItems="center" gap={2}>
          <Box component="img" src={enrollment.qr_code_data_url} alt="Authenticator setup QR code" sx={{ width: 220 }} />
          <Typography sx={{ wordBreak: 'break-all' }}>Manual key: <strong>{enrollment.manual_key}</strong></Typography>
          <TextField fullWidth label="6-digit authentication code" value={code} onChange={(e) => setCode(e.target.value)}
            inputProps={{ inputMode: 'numeric', autoComplete: 'one-time-code', maxLength: 6 }} />
        </Stack>}
      </DialogContent><DialogActions><Button onClick={() => setEnrollment(undefined)}>Cancel</Button>
        <Button variant="contained" onClick={() => run(async () => { setRecoveryCodes(await confirmMfa(code)); setEnrollment(undefined) })}>Confirm MFA</Button>
      </DialogActions>
    </Dialog>

    <Dialog open={recoveryCodes.length > 0} onClose={() => setRecoveryCodes([])} maxWidth="sm" fullWidth>
      <DialogTitle>Save your recovery codes now</DialogTitle><DialogContent>
        <Alert severity="warning">These single-use codes are shown only once. Store them somewhere safe.</Alert>
        <Box component="pre" sx={{ p: 2, bgcolor: 'background.default', columns: 2 }}>{recoveryCodes.join('\n')}</Box>
      </DialogContent><DialogActions><Button onClick={downloadCodes}>Download</Button><Button variant="contained" onClick={() => setRecoveryCodes([])}>I saved them</Button></DialogActions>
    </Dialog>
  </Box>
}
