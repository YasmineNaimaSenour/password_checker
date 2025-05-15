// Fixed implementation using Have I Been Pwned API
// This is a more secure approach than storing common passwords locally

crypto.subtle.digest()

// Common patterns to check against (still useful as an additional check)
const commonPatterns = [
  // Common numerical sequences
  "123456789", "987654321", "12345", "54321", "111111", "222222", "333333", "444444", 
  "555555", "666666", "777777", "888888", "999999", "000000",
  
  // Common keyboard patterns
  "qwerty", "asdfgh", "zxcvbn", "qwertyuiop", "asdfghjkl", "zxcvbnm", "qazwsx", "qweasd",
  "azerty", "qsdfgh", "wxcvbn", "azertyuiop", "qsdfghjkl", "wxcvbn", "aqwzsx", "azeqsd"
];

// Common suffixes people add to passwords
const commonSuffixes = [
  "1", "12", "123", "1234", "12345", "!", "!!", "?", "?!", "$", "#", "@", "2022", "2023", "2024", "2025"
];

async function sha1(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('').toUpperCase();
}


/**
 * Check if a password has been exposed in known data breaches using HIBP API
 * Uses k-anonymity model for privacy: only first 5 chars of hash are sent to API
 * @param {string} password - Password to check
 * @returns {Promise<number>} - Number of times the password appeared in breaches, 0 if not found
 */
async function checkHaveIBeenPwned(password) {
  // Create SHA-1 hash of the password using Web Crypto API
  const hash = await sha1(password);

  const prefix = hash.substring(0, 5);
  const suffix = hash.substring(5);

  try {
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: {
        'User-Agent': 'PasswordStrengthChecker/1.0',
        'Accept': 'text/plain'
      },
      signal: AbortSignal.timeout(5000)
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.text();
    const lines = data.split('\n');

    for (const line of lines) {
      const parts = line.split(':');
      if (parts.length !== 2) continue;
      const [returnedSuffix, count] = parts;
      if (returnedSuffix.trim() === suffix) {
        return parseInt(count.trim());
      }
    }

    return 0;
  } catch (error) {
    console.error('Error checking HIBP:', error.message);
    throw new Error(`HIBP API unavailable: ${error.message}`);
  }
}


/**
 * Check if password uses simple patterns
 * @param {string} password - Password to check
 * @returns {boolean} - True if the password starts with a common pattern
 */
function usesCommonPattern(password) {
  if (!password || password.length < 4) return true;
  
  // Convert to lowercase for comparison
  const lowercasePassword = password.toLowerCase();
  
  // Check if the password starts with a common pattern
  for (const pattern of commonPatterns) {
    if (lowercasePassword.includes(pattern)) {
      return true;
    }
  }
  
  // Check if the password is potentially a common word with a suffix
  for (const suffix of commonSuffixes) {
    if (lowercasePassword.endsWith(suffix) && lowercasePassword.length - suffix.length < 6) {
      return true; // Simple word + suffix is vulnerable
    }
  }
  
  // Check for repeated characters (e.g., "aaa")
  if (/(.)\1{2,}/.test(password)) {
    return true;
  }
  
  // Check for sequential characters (e.g., "abc", "123")
  const sequences = [
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789"
  ];
  
  for (const seq of sequences) {
    for (let i = 0; i < seq.length - 2; i++) {
      const triplet = seq.substring(i, i + 3);
      if (lowercasePassword.includes(triplet)) {
        return true;
      }
    }
  }
  
  // Check for very common passwords
  const veryCommonPasswords = ["password", "admin", "welcome", "letmein", "hello"];
  if (veryCommonPasswords.includes(lowercasePassword)) {
    return true;
  }
  
  return false;
}

/**
 * Estimate password cracking time and check breach databases
 * @param {string} password - Password to check
 * @returns {Promise<object>} - Cracking time and vulnerability assessment
 */
async function estimateCrackingTime(password) {
  if (!password) return { time: '0 seconds', vulnerable: true, breached: false, breachCount: 0 };
  
  // Initialize with breach data set to false
  let breachCount = 0;
  let breached = false;
  let breachError = null;
  
  try {
    // Check if password appears in breach databases
    breachCount = await checkHaveIBeenPwned(password);
    breached = breachCount > 0;
  } catch (error) {
    console.warn('HIBP API check failed:', error.message);
    breachError = error.message;
    // We'll continue with pattern checking as fallback
  }
  
  // Check for common patterns (always do this even if API worked)
  const usesPattern = usesCommonPattern(password);
  
  // If it's a known breached password or uses common patterns, it's very vulnerable
  if (breached || usesPattern) {
    return { 
      time: breached ? `Instantly (found in ${breachCount} data breaches)` : 'Instantly (common pattern)', 
      vulnerable: true,
      breached,
      breachCount: breachCount || 0,
      apiError: breachError
    };
  }
  
  // Calculate possible character sets
  let charactersInSet = 0;
  if (/[a-z]/.test(password)) charactersInSet += 26;
  if (/[A-Z]/.test(password)) charactersInSet += 26;
  if (/[0-9]/.test(password)) charactersInSet += 10;
  if (/[^A-Za-z0-9]/.test(password)) charactersInSet += 33; // Common special chars
  
  // If no character sets are used (empty password), return instant
  if (charactersInSet === 0) {
    return { time: 'Instantly', vulnerable: true, breached: false, breachCount: 0, apiError: breachError };
  }
  
  // Calculate combinations - using character set size and password length
  const combinations = Math.pow(charactersInSet, password.length);
  
  // Assume modern cracking speeds:
  // - Online attack: 1,000 guesses per second (rate limited)
  // - Offline fast hash: 1 billion guesses per second
  // - Dedicated hardware: 100 billion guesses per second
  const offlineGuessesPerSecond = 1000000000; // 1 billion
  
  // Calculate seconds to crack
  const seconds = combinations / offlineGuessesPerSecond;
  
  // Format time and determine vulnerability
  const formattedTime = formatCrackingTime(seconds);
  const vulnerable = seconds < 86400; // Consider vulnerable if crackable in less than a day
  
  return { 
    time: formattedTime, 
    vulnerable,
    breached: false,
    breachCount: 0,
    apiError: breachError
  };
}

/**
 * Format seconds into human-readable time
 * @param {number} seconds - Time in seconds
 * @returns {string} - Formatted time string
 */
function formatCrackingTime(seconds) {
  if (seconds < 1) return 'Instantly';
  if (seconds < 60) return Math.round(seconds) + ' seconds';
  if (seconds < 3600) return Math.round(seconds / 60) + ' minutes';
  if (seconds < 86400) return Math.round(seconds / 3600) + ' hours';
  if (seconds < 2592000) return Math.round(seconds / 86400) + ' days';
  if (seconds < 31536000) return Math.round(seconds / 2592000) + ' months';
  if (seconds < 315360000) return Math.round(seconds / 31536000) + ' years';
  if (seconds < 3153600000) return Math.round(seconds / 315360000) + ' decades';
  return 'centuries';
}

// Export functions for use in other files
if (typeof module !== 'undefined') {
  module.exports = {
    checkHaveIBeenPwned,
    usesCommonPattern,
    estimateCrackingTime
  };
}