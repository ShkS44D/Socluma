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
import { register, login } from '../services/api'
import { useAuthStore } from '../store'
import CyberBackground from '../components/auth/CyberBackground'

const Register: React.FC = () => {
    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')
    const [fullName, setFullName] = useState('')
    const [tenantName, setTenantName] = useState('')
    const [tenantSlug, setTenantSlug] = useState('')
    const [error, setError] = useState('')
    const [loading, setLoading] = useState(false)
    const navigate = useNavigate()
    const authLogin = useAuthStore((state) => state.login)

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault()
        setError('')
        setLoading(true)

        try {
            const requestData = {
                email,
                password,
                full_name: fullName,
                tenant_name: tenantName,
                tenant_slug: tenantSlug
            }
            await register(requestData)
            const loginResponse = await login({ email, password })
            if (loginResponse.access_token) {
                authLogin(loginResponse.access_token, loginResponse.refresh_token)
                navigate('/dashboard')
            } else {
                navigate('/login')
            }
        } catch (err: any) {
            const errorMessage =
                err.response?.data?.detail ||
                err.message ||
                'Registration failed. Please try again.'
            console.error('Registration error:', err)
            setError(errorMessage)
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
                    VigilantAI Register
                </Typography>
                <Box component="form" onSubmit={handleSubmit} sx={{ mt: 1, width: '100%' }}>
                    {error && (
                        <Alert severity="error" sx={{ mb: 2 }}>
                            {error}
                        </Alert>
                    )}
                    <TextField
                        margin="normal"
                        required
                        fullWidth
                        id="fullName"
                        label="Full Name"
                        name="fullName"
                        autoComplete="name"
                        autoFocus
                        value={fullName}
                        onChange={(e) => setFullName(e.target.value)}
                    />
                    <TextField
                        margin="normal"
                        required
                        fullWidth
                        id="email"
                        label="Email Address"
                        name="email"
                        autoComplete="email"
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
                        autoComplete="new-password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                    />
                    <TextField
                        margin="normal"
                        required
                        fullWidth
                        id="tenantName"
                        label="Company/Team Name"
                        name="tenantName"
                        value={tenantName}
                        onChange={(e) => setTenantName(e.target.value)}
                    />
                    <TextField
                        margin="normal"
                        required
                        fullWidth
                        id="tenantSlug"
                        label="Subdomain (e.g., 'myteam')"
                        name="tenantSlug"
                        value={tenantSlug}
                        onChange={(e) => setTenantSlug(e.target.value.toLowerCase())}
                    />
                    <Button
                        type="submit"
                        fullWidth
                        variant="contained"
                        sx={{ mt: 3, mb: 2 }}
                        disabled={loading}
                    >
                        {loading ? <CircularProgress size={24} /> : 'Sign Up'}
                    </Button>
                    <Box sx={{ textAlign: 'center' }}>
                        <Link to="/login" style={{ textDecoration: 'none' }}>
                            <Typography variant="body2">
                                Already have an account? Sign In
                            </Typography>
                        </Link>
                    </Box>
                </Box>
            </Box>
        </Container></CyberBackground>
    )
}

export default Register
