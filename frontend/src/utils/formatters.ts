export { formatDateTime, formatDatePKT } from './time'

export const formatCompactNumber = (value: number): string => {
    return new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 }).format(value)
}

export const formatPercent = (value: number): string => {
    return `${value.toFixed(0)}%`
}
