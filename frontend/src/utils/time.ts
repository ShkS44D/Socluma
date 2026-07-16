const PKT_TIMEZONE = "Asia/Karachi";

/**
 * Converts a date-like value to a Date object, treating naive dates as UTC.
 * @param date - Date, string, or number to convert
 * @returns Date object
 */
function parseDate(date: Date | string | number): Date {
    if (date instanceof Date) {
        return date;
    }
    
    // If string doesn't have timezone info, treat as UTC
    if (typeof date === "string" && !/(Z|[+-]\d{2}:?\d{2})$/i.test(date)) {
        return new Date(date + "Z");
    }
    
    return new Date(date);
}

/**
 * Formats a date in Pakistan Standard Time (PKT)
 * Example: "29 Jun 2026, 2:08 PM PKT"
 */
export function formatDateTimePKT(date: Date | string | number): string {
    const d = parseDate(date);
    
    // Check if date is valid
    if (isNaN(d.getTime())) {
        return "Invalid date";
    }
    
    const formatter = new Intl.DateTimeFormat("en-GB", {
        timeZone: PKT_TIMEZONE,
        day: "2-digit",
        month: "short",
        year: "numeric",
        hour: "numeric",
        minute: "2-digit",
        hour12: true,
    });
    
    const formattedDate = formatter.format(d);
    
    // Add "PKT" suffix
    return `${formattedDate} PKT`;
}

/**
 * Formats a date in Pakistan Standard Time (PKT) without time
 * Example: "29 Jun 2026"
 */
export function formatDatePKT(date: Date | string | number): string {
    const d = parseDate(date);
    
    if (isNaN(d.getTime())) {
        return "Invalid date";
    }
    
    const formatter = new Intl.DateTimeFormat("en-GB", {
        timeZone: PKT_TIMEZONE,
        day: "2-digit",
        month: "short",
        year: "numeric",
    });
    
    return formatter.format(d);
}

/**
 * Alias for formatDateTimePKT for backward compatibility
 */
export function formatDateTime(date: Date | string | number): string {
    return formatDateTimePKT(date);
}
