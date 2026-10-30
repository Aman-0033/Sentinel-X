/**
 * XSS Defense Utilities (Section 27)
 * Enforces text-only rendering, entity sanitization, and strict string coercion
 * to prevent Stored and Reflected Cross-Site Scripting.
 */

/**
 * Escapes potentially dangerous characters into HTML entity representations.
 * Used for any text that might be reflected into attributes or non-React contexts.
 */
export function sanitizeText(input: unknown): string {
  if (input === null || input === undefined) {
    return '';
  }
  const str = String(input);
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

/**
 * Validates that an indicator or search string does not contain suspicious injection payload patterns.
 */
export function isSafeQuery(input: string): boolean {
  if (!input) return true;
  const dangerousPatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/gi,
    /onerror=/gi,
    /onload=/gi,
    /eval\(/gi,
  ];
  return !dangerousPatterns.some((pattern) => pattern.test(input));
}

/**
 * Strips any HTML tags completely, ensuring only plain text remains.
 */
export function stripHtmlTags(input: string): string {
  if (!input) return '';
  return input.replace(/<\/?[^>]+(>|$)/g, '');
}
