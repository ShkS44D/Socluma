import { Alert, Box, Button, Typography } from '@mui/material'
import { Link } from 'react-router-dom'

export default function Unauthorized() {
  return <Box sx={{ p: 4, maxWidth: 720, mx: 'auto' }}>
    <Typography variant="h4" gutterBottom>Access denied</Typography>
    <Alert severity="warning">Your active organization membership does not include permission for this page.</Alert>
    <Button component={Link} to="/dashboard" sx={{ mt: 2 }}>Return to dashboard</Button>
  </Box>
}
