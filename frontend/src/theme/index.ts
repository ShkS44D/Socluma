import { alpha, createTheme } from '@mui/material/styles'

export type SocThemeMode = 'dark' | 'light'

export const createSocTheme = (mode: SocThemeMode = 'dark') => {
  const isLight = mode === 'light'
  const borderColor = isLight ? alpha('#0f172a', 0.14) : alpha('#7dd3fc', 0.18)
  const cardBackground = isLight ? 'rgba(255, 255, 255, 0.94)' : 'rgba(11, 18, 32, 0.88)'

  return createTheme({
  palette: {
    mode,
    primary: {
      main: isLight ? '#0284c7' : '#38bdf8',
      light: isLight ? '#38bdf8' : '#7dd3fc',
      dark: isLight ? '#0369a1' : '#0284c7',
    },
    secondary: {
      main: isLight ? '#4f46e5' : '#818cf8',
      light: isLight ? '#818cf8' : '#a5b4fc',
      dark: '#4f46e5',
    },
    success: {
      main: '#22c55e',
    },
    warning: {
      main: '#f59e0b',
    },
    error: {
      main: '#ef4444',
    },
    info: {
      main: '#38bdf8',
    },
    background: {
      default: isLight ? '#f8fafc' : '#020817',
      paper: isLight ? '#ffffff' : '#0b1220',
    },
    text: {
      primary: isLight ? '#0f172a' : '#e2e8f0',
      secondary: isLight ? '#475569' : '#94a3b8',
    },
    divider: borderColor,
  },
  shape: {
    borderRadius: 14,
  },
  spacing: 8,
  typography: {
    fontFamily: '"Inter", "Segoe UI", "Roboto", "Helvetica Neue", Arial, sans-serif',
    h3: {
      fontSize: '2rem',
      fontWeight: 700,
      letterSpacing: '-0.03em',
    },
    h4: {
      fontSize: '1.75rem',
      fontWeight: 700,
      letterSpacing: '-0.02em',
    },
    h5: {
      fontSize: '1.25rem',
      fontWeight: 700,
    },
    h6: {
      fontSize: '1rem',
      fontWeight: 600,
      letterSpacing: '0.01em',
    },
    subtitle1: {
      fontSize: '0.95rem',
      fontWeight: 600,
    },
    body1: {
      lineHeight: 1.6,
    },
    body2: {
      lineHeight: 1.55,
    },
    button: {
      textTransform: 'none',
      fontWeight: 600,
    },
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          backgroundImage: isLight
            ? 'linear-gradient(180deg, rgba(241, 245, 249, 0.92), rgba(248, 250, 252, 1))'
            : 'radial-gradient(circle at top, rgba(14, 165, 233, 0.08), transparent 30%), radial-gradient(circle at right, rgba(99, 102, 241, 0.1), transparent 22%)',
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          backgroundColor: isLight ? alpha('#ffffff', 0.94) : alpha('#020817', 0.92),
          borderBottom: `1px solid ${borderColor}`,
          boxShadow: 'none',
          backdropFilter: 'blur(16px)',
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          backgroundImage: 'none',
          backgroundColor: isLight ? '#ffffff' : '#030b17',
          borderRight: `1px solid ${borderColor}`,
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          backgroundColor: cardBackground,
          border: `1px solid ${borderColor}`,
          boxShadow: '0 18px 45px rgba(2, 8, 23, 0.28)',
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
        },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        head: {
          color: isLight ? '#334155' : '#cbd5e1',
          fontWeight: 600,
          borderBottom: `1px solid ${borderColor}`,
          backgroundColor: isLight ? alpha('#e2e8f0', 0.72) : alpha('#0f172a', 0.72),
        },
        body: {
          borderBottom: `1px solid ${isLight ? alpha('#0f172a', 0.08) : alpha('#7dd3fc', 0.08)}`,
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          fontWeight: 600,
          borderRadius: 999,
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 10,
        },
        contained: {
          boxShadow: 'none',
        },
      },
    },
    MuiOutlinedInput: {
      styleOverrides: {
        root: {
          backgroundColor: isLight ? alpha('#f8fafc', 0.9) : alpha('#0f172a', 0.62),
        },
        notchedOutline: {
          borderColor: borderColor,
        },
      },
    },
    MuiLinearProgress: {
      styleOverrides: {
        root: {
          borderRadius: 999,
          backgroundColor: isLight ? alpha('#cbd5e1', 0.9) : alpha('#1e293b', 0.9),
        },
      },
    },
  },
})
}

export const socTheme = createSocTheme('dark')

export default socTheme
