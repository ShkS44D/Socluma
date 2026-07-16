import React, { useState } from 'react'
import {
  Box,
  Button,
  FormControl,
  FormLabel,
  InputAdornment,
  InputLabel,
  OutlinedInput,
  Stack,
  TextField,
  Typography,
} from '@mui/material'
import { Key as KeyIcon, Person as PersonIcon, Palette as PaletteIcon } from '@mui/icons-material'
import { toast } from 'react-hot-toast'
import { PageHeader, SectionCard, StatusChip } from '../components/ui'
import { useAuthStore } from '../store'
import { changePassword } from '../services/api'
import {
  ThemePreference,
  getStoredThemePreference,
  saveThemePreference,
} from '../utils/themePreference'

const Settings: React.FC = () => {
  const user = useAuthStore((state) => state.user)
  const [themePreference, setThemePreference] = useState<ThemePreference>(() => getStoredThemePreference())
  const [isChangingPassword, setIsChangingPassword] = useState(false)
  const [oldPassword, setOldPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')

  const handleChangePassword = async () => {
    if (newPassword !== confirmPassword) {
      toast.error('New passwords do not match!')
      return
    }
    if (!oldPassword || !newPassword) {
      toast.error('Enter your current password and a new password.')
      return
    }
    setIsChangingPassword(true)
    try {
      await changePassword({
        current_password: oldPassword,
        new_password: newPassword,
      })
      toast.success('Password changed successfully!')
      setOldPassword('')
      setNewPassword('')
      setConfirmPassword('')
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to change password.')
    } finally {
      setIsChangingPassword(false)
    }
  }

  const handleThemeChange = (preference: ThemePreference) => {
    setThemePreference(preference)
    saveThemePreference(preference)
    toast.success(`Theme preference set to ${preference}.`)
  }

  return (
    <Stack spacing={4} sx={{ width: '100%', maxWidth: 1480, mx: 'auto' }}>
      <PageHeader
        title="Settings"
        description="Manage your profile and application preferences"
      />

      <Box
        sx={{
          display: 'grid',
          gridTemplateColumns: { xs: '1fr', xl: 'repeat(2, minmax(0, 1fr))' },
          gap: 4,
          alignItems: 'stretch',
          width: '100%',
        }}
      >
        <Box sx={{ minWidth: 0 }}>
          <SectionCard title="Profile" icon={<PersonIcon />} contentSx={{ minHeight: 360 }}>
            <Stack spacing={3} sx={{ height: '100%' }}>
              <Box>
                <TextField
                  fullWidth
                  label="Username"
                  value={user?.full_name || 'N/A'}
                  disabled
                />
              </Box>
              <Box>
                <TextField
                  fullWidth
                  label="Email"
                  value={user?.email || 'N/A'}
                  disabled
                />
              </Box>
              <Box>
                <FormLabel>Role</FormLabel>
                <Box sx={{ mt: 1 }}>
                  <StatusChip
                    label={user?.role?.toLowerCase() || 'N/A'}
                    color={
                      user?.role?.toLowerCase() === 'admin'
                        ? 'error'
                        : user?.role?.toLowerCase() === 'analyst'
                        ? 'warning'
                        : 'info'
                    }
                  />
                </Box>
              </Box>
            </Stack>
          </SectionCard>
        </Box>

        <Box sx={{ minWidth: 0 }}>
          <SectionCard title="Security" icon={<KeyIcon />} contentSx={{ minHeight: 360 }}>
            <Stack spacing={3}>
              <Typography variant="body2" color="text.secondary">
                Change your password to keep your account secure.
              </Typography>
              <Box>
                <FormControl fullWidth variant="outlined">
                  <InputLabel htmlFor="outlined-adornment-old">
                    Old Password
                  </InputLabel>
                  <OutlinedInput
                    id="outlined-adornment-old"
                    type="password"
                    value={oldPassword}
                    onChange={(e) => setOldPassword(e.target.value)}
                    endAdornment={
                      <InputAdornment position="end">
                        <KeyIcon fontSize="small" />
                      </InputAdornment>
                    }
                    label="Old Password"
                  />
                </FormControl>
              </Box>
              <Box>
                <FormControl fullWidth variant="outlined">
                  <InputLabel htmlFor="outlined-adornment-new">
                    New Password
                  </InputLabel>
                  <OutlinedInput
                    id="outlined-adornment-new"
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    endAdornment={
                      <InputAdornment position="end">
                        <KeyIcon fontSize="small" />
                      </InputAdornment>
                    }
                    label="New Password"
                  />
                </FormControl>
              </Box>
              <Box>
                <FormControl fullWidth variant="outlined">
                  <InputLabel htmlFor="outlined-adornment-confirm">
                    Confirm New Password
                  </InputLabel>
                  <OutlinedInput
                    id="outlined-adornment-confirm"
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    endAdornment={
                      <InputAdornment position="end">
                        <KeyIcon fontSize="small" />
                      </InputAdornment>
                    }
                    label="Confirm New Password"
                  />
                </FormControl>
              </Box>
              <Button
                variant="contained"
                onClick={handleChangePassword}
                disabled={isChangingPassword}
              >
                {isChangingPassword ? 'Changing Password...' : 'Change Password'}
              </Button>
            </Stack>
          </SectionCard>
        </Box>

        <Box sx={{ gridColumn: '1 / -1', minWidth: 0 }}>
          <SectionCard title="Application Preferences" icon={<PaletteIcon />}>
            <Stack spacing={3}>
              <Typography variant="body2" color="text.secondary">
                Customize your application experience.
              </Typography>
              <Box>
                <FormLabel>Theme Preference</FormLabel>
                <Box sx={{ mt: 1.5, display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                  <Button
                    variant={themePreference === 'dark' ? 'contained' : 'outlined'}
                    onClick={() => handleThemeChange('dark')}
                  >
                    Dark
                  </Button>
                  <Button
                    variant={themePreference === 'light' ? 'contained' : 'outlined'}
                    onClick={() => handleThemeChange('light')}
                  >
                    Light
                  </Button>
                  <Button
                    variant={themePreference === 'system' ? 'contained' : 'outlined'}
                    onClick={() => handleThemeChange('system')}
                  >
                    System
                  </Button>
                </Box>
              </Box>
            </Stack>
          </SectionCard>
        </Box>
      </Box>
    </Stack>
  )
}

export default Settings
