import { Box, Typography } from '@mui/material'

interface BrandLogoProps {
  size?: number
  showTagline?: boolean
}

export default function BrandLogo({ size = 40, showTagline = false }: BrandLogoProps) {
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.25 }}>
      <Box component="img" src="/socluma-mark.svg" alt="" aria-hidden="true"
        width={size} height={size} sx={{ flexShrink: 0 }} />
      <Box>
        <Typography component="span" sx={{ display: 'block', fontSize: size * 0.55,
          fontWeight: 800, letterSpacing: '-0.035em', lineHeight: 1.15 }}>
          Socluma
        </Typography>
        {showTagline && (
          <Typography component="span" sx={{ display: 'block', mt: 0.5,
            fontSize: 10, letterSpacing: '0.025em', color: 'text.secondary' }}>
            AI-Assisted Security Operations
          </Typography>
        )}
      </Box>
    </Box>
  )
}
