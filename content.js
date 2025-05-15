// Function to create the password strength panel
function createPasswordStrengthPanel(passwordInput) {
  const panel = document.createElement('div');
  
  // Set panel styles
  panel.style.cssText = `
    position: absolute;
    width: ${passwordInput.offsetWidth}px;
    background: #F9FAFB;
    border: 1px solid #E5E7EB;
    border-radius: 8px;
    padding: 16px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    z-index: 10000;
    display: none;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    color: #111827;
  `;

  // Create the panel content with inline HTML
  panel.innerHTML = `
    <div class="strength-meter" style="height: 8px; border-radius: 4px; background-color: #E5E7EB; margin: 12px 0 30px 0; overflow: hidden;">
      <div class="strength-progress" style="height: 100%; width: 0%; border-radius: 4px; transition: width 0.3s ease, background-color 0.3s ease;"></div>
    </div>
    <p class="strength-text" style="font-size: 14px; font-weight: 500; margin: 5px 0 12px 0; padding: 4px 0;">Password strength: <span class="strength-value">None</span></p>
    <div class="password-rules" style="display: flex; flex-direction: column; gap: 8px; margin-top: 8px; clear: both;">
      <div id="ruleLength" class="rule-item" style="display: flex; align-items: center; gap: 8px; font-size: 14px; color: #6B7280;">
        <span class="rule-icon" style="width: 16px; height: 16px; display: flex; align-items: center; justify-content: center; border-radius: 50%;">❌</span>
        <span class="text">At least 12 characters</span>
      </div>
      <div id="ruleUppercase" class="rule-item" style="display: flex; align-items: center; gap: 8px; font-size: 14px; color: #6B7280;">
        <span class="rule-icon" style="width: 16px; height: 16px; display: flex; align-items: center; justify-content: center; border-radius: 50%;">❌</span>
        <span class="text">Contains uppercase letter</span>
      </div>
      <div id="ruleLowercase" class="rule-item" style="display: flex; align-items: center; gap: 8px; font-size: 14px; color: #6B7280;">
        <span class="rule-icon" style="width: 16px; height: 16px; display: flex; align-items: center; justify-content: center; border-radius: 50%;">❌</span>
        <span class="text">Contains lowercase letter</span>
      </div>
      <div id="ruleNumber" class="rule-item" style="display: flex; align-items: center; gap: 8px; font-size: 14px; color: #6B7280;">
        <span class="rule-icon" style="width: 16px; height: 16px; display: flex; align-items: center; justify-content: center; border-radius: 50%;">❌</span>
        <span class="text">Contains number</span>
      </div>
      <div id="ruleSpecial" class="rule-item" style="display: flex; align-items: center; gap: 8px; font-size: 14px; color: #6B7280;">
        <span class="rule-icon" style="width: 16px; height: 16px; display: flex; align-items: center; justify-content: center; border-radius: 50%;">❌</span>
        <span class="text">Contains special character</span>
      </div>
      <div id="ruleNotBreached" class="rule-item" style="display: flex; align-items: center; gap: 8px; font-size: 14px; color: #6B7280;">
        <span class="rule-icon" style="width: 16px; height: 16px; display: flex; align-items: center; justify-content: center; border-radius: 50%;">❓</span>
        <span class="text">Not found in data breaches</span>
      </div>
    </div>
    <div class="cracking-info" style="margin-top: 12px; padding: 12px; border-radius: 8px; background-color: #F3F4F6;">
      <div class="cracking-title" style="font-size: 14px; font-weight: 500; margin: 0 0 8px 0;">Estimated cracking time:</div>
      <div class="cracking-time" style="font-size: 16px; font-weight: 600; margin: 0; color: #10B981;">-</div>
    </div>
  `;

  return panel;
}

// Debounce function to limit how often a function can be called
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// SHA-1 hash function using Web Crypto API
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
  
  // Common patterns to check against
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

// Function to analyze password and update panel
async function analyzePassword(password, panel) {
  const strength = calculatePasswordStrength(password);
  updateStrengthMeter(strength, panel);
  updateRuleIcons(password, panel);
  
  // Update "Not found in data breaches" rule to checking state
  const breachRuleElement = panel.querySelector('#ruleNotBreached');
  if (breachRuleElement) {
    const breachIcon = breachRuleElement.querySelector('.rule-icon');
    const breachText = breachRuleElement.querySelector('.text');
    
    if (breachIcon && breachText) {
      breachIcon.textContent = '⏳';
      breachText.textContent = 'Checking breach databases...';
      breachRuleElement.style.color = '#6B7280';
    }
  }
  
  // Update cracking time with real estimate from HIBP API
  try {
    const crackingInfo = await estimateCrackingTime(password);
    updateCrackingTimeWithApiData(crackingInfo, panel);
    
    // Now update the breach status
    if (breachRuleElement) {
      const breachIcon = breachRuleElement.querySelector('.rule-icon');
      const breachText = breachRuleElement.querySelector('.text');
      
      if (breachIcon && breachText) {
        if (crackingInfo.apiError) {
          breachIcon.textContent = '❓';
          breachText.textContent = 'Unable to check breach databases';
          breachRuleElement.style.color = '#F59E0B'; // Amber/orange for uncertain
        } else if (crackingInfo.breached) {
          breachIcon.textContent = '❌';
          breachText.textContent = `Found in ${crackingInfo.breachCount} data breaches`;
          breachRuleElement.style.color = '#EF4444'; // Red for breached
        } else {
          breachIcon.textContent = '✅';
          breachText.textContent = 'Not found in data breaches';
          breachRuleElement.style.color = '#10B981'; // Green for passed
        }
      }
    }
  } catch (error) {
    console.error('Error analyzing password:', error);
    // Fall back to the old method if the API call fails
    updateCrackingTime(password, panel);
    
    // Update breach status to error state
    if (breachRuleElement) {
      const breachIcon = breachRuleElement.querySelector('.rule-icon');
      const breachText = breachRuleElement.querySelector('.text');
      
      if (breachIcon && breachText) {
        breachIcon.textContent = '❓';
        breachText.textContent = 'Unable to check breach databases';
        breachRuleElement.style.color = '#F59E0B'; // Amber/orange for uncertain
      }
    }
  }
}

// Calculate password strength score
function calculatePasswordStrength(password) {
  if (!password) return 0;
  
  let strength = 0;
  
  // Length check (up to 36 points)
  strength += Math.min(36, password.length * 3);
  
  // Character variety checks (up to 60 points)
  if (/[A-Z]/.test(password)) strength += 16;
  if (/[a-z]/.test(password)) strength += 16;
  if (/[0-9]/.test(password)) strength += 16;
  if (/[^A-Za-z0-9]/.test(password)) strength += 16;
  
  // Check for common patterns
  if (usesCommonPattern(password)) {
    strength -= 40;
  } else {
    if (/123|abc|qwerty|password|admin|welcome/i.test(password)) {
      strength -= 20;
    }
    if (/(.)\1\1/.test(password)) {
      strength -= 10;
    }
    if (/(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(password)) {
      strength -= 10;
    }
  }
  
  return Math.max(0, Math.min(100, strength));
}

// Update strength meter
function updateStrengthMeter(strength, panel) {
  const progress = panel.querySelector('.strength-progress');
  const strengthValueSpan = panel.querySelector('.strength-value');
  const strengthTextElement = panel.querySelector('.strength-text');
  
  if (!progress || !strengthValueSpan) return;
  
  progress.style.width = strength + '%';
  
  let strengthText = 'None';
  progress.className = 'strength-progress';
  
  // Ensure the strength text is visible and properly positioned
  if (strengthTextElement) {
    strengthTextElement.style.display = 'block';
    strengthTextElement.style.position = 'relative';
    strengthTextElement.style.zIndex = '1';
    strengthTextElement.style.color = '#111827'; // Set the "Password strength:" text to black
  }
  
  // Set different colors based on strength
  if (strength < 25) {
    progress.style.backgroundColor = '#EF4444'; // Red
    strengthText = 'Weak';
    strengthValueSpan.style.color = '#EF4444'; // Red for weak
  } else if (strength < 50) {
    progress.style.backgroundColor = '#F59E0B'; // Amber
    strengthText = 'Fair';
    strengthValueSpan.style.color = '#EAB308'; // Yellow for fair
  } else if (strength < 75) {
    progress.style.backgroundColor = '#10B981'; // Green
    strengthText = 'Good';
    strengthValueSpan.style.color = '#10B981'; // Green for good
  } else {
    progress.style.backgroundColor = '#059669'; // Dark green
    strengthText = 'Strong';
    strengthValueSpan.style.color = '#047857'; // Darker green for strong
  }
  
  // Update only the value span, not the entire text
  strengthValueSpan.textContent = strengthText;
}

// Update rule icons
function updateRuleIcons(password, panel) {
  const rules = {
    ruleLength: password.length >= 12,
    ruleUppercase: /[A-Z]/.test(password),
    ruleLowercase: /[a-z]/.test(password),
    ruleNumber: /[0-9]/.test(password),
    ruleSpecial: /[^A-Za-z0-9]/.test(password)
  };

  for (const [ruleId, isPassed] of Object.entries(rules)) {
    const element = panel.querySelector(`#${ruleId}`);
    if (element) {
      const icon = element.querySelector('.rule-icon');
      if (icon) {
        icon.textContent = isPassed ? '✅' : '❌';
        element.style.color = isPassed ? '#10B981' : '#6B7280';
      }
    }
  }
}

// Legacy function (fallback if API fails)
function updateCrackingTime(password, panel) {
  const crackingTimeElement = panel.querySelector('.cracking-time');
  if (!crackingTimeElement) return;

  // Simplified estimation
  const strength = calculatePasswordStrength(password);
  
  let time = 'Instantly';
  let vulnerable = true;
  
  if (strength < 25) {
    time = 'Instantly';
    vulnerable = true;
  } else if (strength < 50) {
    time = 'A few hours to days';
    vulnerable = true;
  } else if (strength < 75) {
    time = 'A few months to years';
    vulnerable = false;
  } else {
    time = 'Centuries';
    vulnerable = false;
  }

  crackingTimeElement.textContent = time;
  crackingTimeElement.style.color = vulnerable ? '#EF4444' : '#10B981';
}

// Update cracking time with API data
function updateCrackingTimeWithApiData(result, panel) {
  const crackingTimeElement = panel.querySelector('.cracking-time');
  if (!crackingTimeElement) return;

  crackingTimeElement.textContent = result.time;
  crackingTimeElement.style.color = result.vulnerable ? '#EF4444' : '#10B981';
}

// Main function to initialize password strength checking
async function initializePasswordStrengthCheck() {
  // Find all password input fields
  const passwordInputs = document.querySelectorAll('input[type="password"]');
  
  for (const input of passwordInputs) {
    // Skip if we've already added the panel to this input
    if (input.dataset.hasPasswordPanel) continue;
    input.dataset.hasPasswordPanel = 'true';
    
    // Create and position the panel
    const panel = createPasswordStrengthPanel(input);
    document.body.appendChild(panel);
    
    // Position the panel below the input
    function updatePanelPosition() {
      const rect = input.getBoundingClientRect();
      panel.style.top = `${rect.bottom + window.scrollY + 5}px`;
      panel.style.left = `${rect.left + window.scrollX}px`;
      panel.style.width = `${rect.width}px`;
    }
    
    // Debounced update function - analyze password with delay
    const debouncedAnalyze = debounce(async () => {
      await analyzePassword(input.value, panel);
    }, 500); // Increased to 500ms to avoid too many API calls
    
    // Show/hide panel on focus/blur
    input.addEventListener('focus', () => {
      // Update position first
      updatePanelPosition();
      // Force a reflow to ensure position is updated
      panel.offsetHeight;
      // Show the panel
      panel.style.display = 'block';
      // Analyze immediately
      analyzePassword(input.value, panel);
    });
    
    input.addEventListener('blur', () => {
      setTimeout(() => {
        panel.style.display = 'none';
      }, 200);
    });
    
    // Update panel on input with debounce
    input.addEventListener('input', debouncedAnalyze);
    
    // Update position on scroll and resize with debounce
    const debouncedUpdatePosition = debounce(updatePanelPosition, 100);
    window.addEventListener('scroll', debouncedUpdatePosition);
    window.addEventListener('resize', debouncedUpdatePosition);
  }
}

// Initialize when the page loads
document.addEventListener('DOMContentLoaded', () => {
  initializePasswordStrengthCheck().catch(console.error);
});

// Optimized MutationObserver for password fields
const observer = new MutationObserver((mutations) => {
  // Only process mutations that might contain password inputs
  const hasRelevantChanges = mutations.some(mutation => {
    return mutation.addedNodes.length > 0 && 
           (mutation.target.tagName === 'FORM' || 
            mutation.target.querySelector('input[type="password"]'));
  });
  
  if (hasRelevantChanges) {
    initializePasswordStrengthCheck().catch(console.error);
  }
});

// Only observe form elements and their containers
const formElements = document.querySelectorAll('form, div, section, main, article');
formElements.forEach(element => {
  observer.observe(element, {
    childList: true,
    subtree: true
  });
});