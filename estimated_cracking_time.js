// This implementaion is temporary
// in production we'll connect to a password API

const commonPasswords = [
    // Top 100 most common passwords (sample from real breach data)
    "123456", "123456789", "qwerty", "password", "12345", "12345678", "111111", "1234567", 
    "123123", "1234567890", "000000", "1234", "iloveyou", "1q2w3e4r", "qwertyuiop", 
    "123", "monkey", "dragon", "baseball", "football", "letmein", "welcome", "admin",
    "princess", "sunshine", "master", "hottie", "loveme", "zaq1zaq1", "abc123", "trustno1",
    "shadow", "1234qwer", "password1", "121212", "qazwsx", "superman", "michael", "batman",
    "696969", "qwerty123", "asdfghjkl", "12345678910", "1q2w3e", "7777777", "charlie",
    "qweasd", "thomas", "donald", "asdfgh", "987654321", "q1w2e3r4", "qwer1234", "hunter",
    "jordan23", "freedom", "whatever", "1q2w3e4r5t", "pokemon", "jessica", "starwars",
    "qwe123", "soccer", "killer", "george", "andrew", "daniel", "asdf1234", "computer",
    "123456a", "abcd1234", "password123", "welcome1", "login", "888888", "654321", "ashley",
    "qwertyui", "michelle", "liverpool", "1qaz2wsx", "martin", "oliver", "mercedes", "tigers",
    "justin", "basketball", "666666", "jennifer", "anthony", "pepper", "joshua", "chelsea",
    "robert", "matthew", "12341234", "bandit", "summer", "corvette"
  ];
  
  // Additional patterns to check against
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
  
  // Function to check if password is in common password list or starts with a common pattern
  function isCommonPassword(password) {
    // Convert to lowercase for comparison
    const lowercasePassword = password.toLowerCase();
    
    // Direct match
    if (commonPasswords.includes(lowercasePassword)) {
      return true;
    }
    
    // Check if the password starts with a common pattern
    for (const pattern of commonPatterns) {
      if (lowercasePassword.startsWith(pattern)) {
        return true;
      }
    }
    
    // Check if the password is a common word with a common suffix
    for (const suffix of commonSuffixes) {
      const possibleBase = lowercasePassword.endsWith(suffix) ? 
        lowercasePassword.slice(0, -suffix.length) : '';
      
      if (possibleBase && commonPasswords.includes(possibleBase)) {
        return true;
      }
    }
    
    return false;
  }
  
  // Function to estimate password cracking time more accurately
  function estimateCrackingTime(password) {
    if (!password) return { time: '0 seconds', vulnerable: true };
    
    // Check if it's a common password
    if (isCommonPassword(password)) {
      return { time: 'Instantly (common password)', vulnerable: true };
    }
    
    // Calculate possible character sets
    let charactersInSet = 0;
    if (/[a-z]/.test(password)) charactersInSet += 26;
    if (/[A-Z]/.test(password)) charactersInSet += 26;
    if (/[0-9]/.test(password)) charactersInSet += 10;
    if (/[^A-Za-z0-9]/.test(password)) charactersInSet += 33; // Common special chars
    
    // If no character sets are used (empty password), return instant
    if (charactersInSet === 0) {
      return { time: 'Instantly', vulnerable: true };
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
    
    return { time: formattedTime, vulnerable };
  }
  
  // Format seconds into human-readable time
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
      commonPasswords,
      isCommonPassword,
      estimateCrackingTime
    };
  }