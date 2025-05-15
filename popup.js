document.addEventListener('DOMContentLoaded', function() {
  const passwordInput = document.getElementById('password');
  const togglePassword = document.getElementById('togglePassword');
  const strengthProgress = document.getElementById('strengthProgress');
  const strengthText = document.getElementById('strengthValue');
  const crackingTimeElement = document.getElementById('crackingTime');
  const breachInfoElement = document.getElementById('breachInfo');
  
  // Rule elements
  const ruleLength = document.getElementById('ruleLength');
  const ruleUppercase = document.getElementById('ruleUppercase');
  const ruleLowercase = document.getElementById('ruleLowercase');
  const ruleNumber = document.getElementById('ruleNumber');
  const ruleSpecial = document.getElementById('ruleSpecial');
  const ruleCommon = document.getElementById('ruleCommon');
  const ruleBreached = document.getElementById('ruleBreached');
  
  // Toggle password visibility
  togglePassword.addEventListener('click', function() {
    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', type);
    togglePassword.textContent = type === 'password' ? '👁️' : '🔒';
  });

  // Debounce function to limit API calls
  function debounce(func, wait) {
    let timeout;
    return function(...args) {
      clearTimeout(timeout);
      timeout = setTimeout(() => func.apply(this, args), wait);
    };
  }

  // Check password strength on input (debounced to avoid excessive API calls)
  passwordInput.addEventListener('input', debounce(function() {
    const password = passwordInput.value;
    analyzePassword(password);
  }, 500)); // 500ms debounce (increased from 300ms to reduce API load)
  
  // Function to analyze password strength and update UI
  async function analyzePassword(password) {
    console.log('[UI DEBUG] Starting password analysis');
    
    // Reset UI elements
    resetAnalysisUI();
    
    // Skip analysis for empty passwords
    if (!password) {
      console.log('[UI DEBUG] Empty password, skipping analysis');
      updateEmptyPasswordUI();
      return;
    }
    
    // Show "checking..." indicator for the breach check
    if (breachInfoElement) {
      breachInfoElement.textContent = "Checking breach databases...";
      breachInfoElement.className = "breach-checking";
    }
    
    // Update the visual elements immediately based on basic checks
    updateBasicStrength(password);
    updateRuleIcons(password, null); // Initially update without breach data
    
    // Make the API call to check breaches (async)
    try {
      console.log('[UI DEBUG] Calling estimateCrackingTime API');
      const result = await estimateCrackingTime(password);
      console.log('[UI DEBUG] API call completed successfully:', result);
      
      updateCrackingTime(result);
      updateBreachInfo(result);
      updateRuleIcons(password, result); // Update again with breach data
      
      // Adjust strength score based on breach status
      if (result.breached || result.vulnerable) {
        const adjustedStrength = calculatePasswordStrength(password, result);
        updateStrengthMeter(adjustedStrength);
      }
    } catch (error) {
      console.error('[UI ERROR] Error analyzing password:', error);
      console.error('[UI ERROR] Error details:', { 
        message: error.message,
        name: error.name,
        stack: error.stack
      });
      handleApiFailure(password, error);
    }
  }
  
  // Reset UI elements for new analysis
  function resetAnalysisUI() {
    if (breachInfoElement) {
      breachInfoElement.textContent = "";
      breachInfoElement.className = "";
    }
    
    if (crackingTimeElement) {
      crackingTimeElement.textContent = "";
      crackingTimeElement.className = "cracking-time";
    }
  }
  
  // Update UI for empty password
  function updateEmptyPasswordUI() {
    updateStrengthMeter(0);
    
    if (crackingTimeElement) {
      crackingTimeElement.textContent = "Enter a password";
    }
    
    if (breachInfoElement) {
      breachInfoElement.textContent = "No password entered";
      breachInfoElement.className = "breach-none";
    }
    
    // Update rule icons for empty password
    if (ruleLength) updateRuleIcon(ruleLength, false);
    if (ruleUppercase) updateRuleIcon(ruleUppercase, false);
    if (ruleLowercase) updateRuleIcon(ruleLowercase, false);
    if (ruleNumber) updateRuleIcon(ruleNumber, false);
    if (ruleSpecial) updateRuleIcon(ruleSpecial, false);
    if (ruleCommon) updateRuleIcon(ruleCommon, false);
    if (ruleBreached) updateRuleIcon(ruleBreached, false);
  }
  
  // Handle API failures gracefully
  function handleApiFailure(password, error) {
    // Fall back to basic strength check
    const fallbackStrength = calculatePasswordStrength(password, { vulnerable: usesCommonPattern(password) });
    updateStrengthMeter(fallbackStrength);
    
    // Update cracking time with estimate
    if (crackingTimeElement) {
      crackingTimeElement.textContent = 'API unavailable, using basic estimates';
      crackingTimeElement.className = 'cracking-time api-unavailable';
    }
    
    // Update breach info
    if (breachInfoElement) {
      breachInfoElement.textContent = 'Could not check breach databases';
      breachInfoElement.className = "breach-error";
      
      // Add more specific error info if available
      if (error && error.message) {
        breachInfoElement.title = `Error: ${error.message}`;
      }
    }
    
    // Update rule icons with local checks only
    updateRuleIcons(password, { 
      vulnerable: usesCommonPattern(password),
      breached: false
    });
  }

  // Update basic strength immediately while waiting for API response
  function updateBasicStrength(password) {
    const strength = calculatePasswordStrength(password);
    updateStrengthMeter(strength);
  }

  // Calculate password strength using enhanced algorithm
  function calculatePasswordStrength(password, breachResult = null) {
    if (!password) return 0;
    
    let strength = 0;
    
    // Length check (up to 36 points)
    strength += Math.min(36, password.length * 3);
    
    // Character variety checks (up to 64 points)
    if (/[A-Z]/.test(password)) strength += 16; // uppercase
    if (/[a-z]/.test(password)) strength += 16; // lowercase
    if (/[0-9]/.test(password)) strength += 16; // numbers
    if (/[^A-Za-z0-9]/.test(password)) strength += 16; // special chars
    
    // Penalties based on breach data and common patterns
    if (breachResult) {
      // Heavy penalty if found in breaches
      if (breachResult.breached) {
        const breachPenalty = Math.min(60, 20 + (Math.log10(breachResult.breachCount) * 10));
        strength -= breachPenalty;
      }
      
      // Penalty if very vulnerable according to cracking time
      if (breachResult.vulnerable && !breachResult.breached) {
        strength -= 30;
      }
    } else {
      // If no breach data, check for common patterns
      if (usesCommonPattern(password)) {
        strength -= 20;
      }
      
      // Decrease for repeated characters
      if (/(.)\1\1/.test(password)) {
        strength -= 10;
      }
      
      // Decrease for sequential characters
      if (/(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(password)) {
        strength -= 10;
      }
    }
    
    return Math.max(0, Math.min(100, strength));
  }

  function updateStrengthMeter(strength) {
    // Update the progress bar width
    strengthProgress.style.width = strength + '%';
    
    // Remove all previous classes
    strengthProgress.className = 'strength-progress';
    strengthText.className = 'strength-text';
    
    // Add appropriate class based on strength
    if (strength < 25) {
      strengthProgress.classList.add('progress-weak');
      strengthText.classList.add('strength-weak');
      strengthText.textContent = 'Weak';
    } else if (strength < 50) {
      strengthProgress.classList.add('progress-fair');
      strengthText.classList.add('strength-fair');
      strengthText.textContent = 'Fair';
    } else if (strength < 75) {
      strengthProgress.classList.add('progress-good');
      strengthText.classList.add('strength-good');
      strengthText.textContent = 'Good';
    } else {
      strengthProgress.classList.add('progress-strong');
      strengthText.classList.add('strength-strong');
      strengthText.textContent = 'Strong';
    }
  }

  function updateRuleIcons(password, breachResult) {
    // Check each rule and update the icon
    // Length rule
    updateRuleIcon(ruleLength, password.length >= 12);
    
    // Uppercase rule
    updateRuleIcon(ruleUppercase, /[A-Z]/.test(password));
    
    // Lowercase rule
    updateRuleIcon(ruleLowercase, /[a-z]/.test(password));
    
    // Number rule
    updateRuleIcon(ruleNumber, /[0-9]/.test(password));
    
    // Special character rule
    updateRuleIcon(ruleSpecial, /[^A-Za-z0-9]/.test(password));
    
    // Common pattern rule
    if (ruleCommon) {
      let isCommon;
      
      if (breachResult) {
        // If we have breach data, use that to determine if password uses common patterns
        isCommon = breachResult.vulnerable && !breachResult.breached;
      } else {
        // Otherwise use simple pattern check
        isCommon = usesCommonPattern(password);
      }
      
      updateRuleIcon(ruleCommon, !isCommon);
    }
    
    // Breach check rule
    if (ruleBreached && breachResult) {
      // If we have breach results
      if (breachResult.apiError) {
        // API error state
        ruleBreached.textContent = '⚠️';
        ruleBreached.className = 'rule-warning';
        ruleBreached.title = 'Could not check breach database: ' + breachResult.apiError;
      } else {
        // Normal state
        updateRuleIcon(ruleBreached, !breachResult.breached);
        ruleBreached.title = breachResult.breached ? 
          `Found in ${breachResult.breachCount} data breaches` : 
          'Not found in known data breaches';
      }
    } else if (ruleBreached) {
      // If we don't have results yet, show as pending
      ruleBreached.textContent = '⏳';
      ruleBreached.className = 'rule-pending';
      ruleBreached.title = 'Checking breach databases...';
    }
  }

  function updateRuleIcon(element, isPassed) {
    if (!element) return;
    
    element.textContent = isPassed ? '✅' : '❌';
    element.classList.remove(isPassed ? 'rule-failed' : 'rule-passed');
    element.classList.add(isPassed ? 'rule-passed' : 'rule-failed');
  }
  
  // Update the cracking time display
  function updateCrackingTime(result) {
    if (!crackingTimeElement) return;
    
    crackingTimeElement.textContent = result.time;
    
    // Update styling based on vulnerability
    crackingTimeElement.className = 'cracking-time';
    if (result.vulnerable) {
      crackingTimeElement.classList.add('vulnerable');
    }
    
    // Add API error indicator if needed
    if (result.apiError) {
      crackingTimeElement.classList.add('api-unavailable');
      crackingTimeElement.title = result.apiError;
    }
  }
  
  // Update breach information display
  function updateBreachInfo(result) {
    if (!breachInfoElement) return;
    
    if (result.apiError) {
      breachInfoElement.textContent = `API Error: ${result.apiError.substring(0, 50)}${result.apiError.length > 50 ? '...' : ''}`;
      breachInfoElement.className = "breach-error";
      breachInfoElement.title = result.apiError;
    } else if (result.breached) {
      breachInfoElement.textContent = `Found in ${result.breachCount.toLocaleString()} data breaches!`;
      breachInfoElement.className = "breach-found";
    } else {
      breachInfoElement.textContent = "Not found in known data breaches";
      breachInfoElement.className = "breach-clean";
    }
  }
  
  // Function to check if password uses simple patterns
  // This is a duplicate of the function in the main file, but needed for frontend validation
  function usesCommonPattern(password) {
    if (!password || password.length < 4) return true;
    
    // Convert to lowercase for comparison
    const lowercasePassword = password.toLowerCase();
    
    // List of common patterns to check
    const commonPatterns = [
      "123", "abc", "qwerty", "password", "admin", "welcome", "letmein"
    ];
    
    // Check for common patterns
    for (const pattern of commonPatterns) {
      if (lowercasePassword.includes(pattern)) {
        return true;
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
    
    // Common suffixes
    const commonSuffixes = ["1", "123", "!", "@"];
    for (const suffix of commonSuffixes) {
      if (lowercasePassword.endsWith(suffix) && lowercasePassword.length - suffix.length < 6) {
        return true; // Simple word + suffix is vulnerable
      }
    }
    
    return false;
  }
  
  // Handle messages from content script
  window.addEventListener('message', function(event) {
    if (event.data.action === 'updatePassword') {
      // Update password field
      passwordInput.value = event.data.password;
      
      // Trigger analysis
      analyzePassword(event.data.password);
    }
  });
  
  // Notify content script that popup is ready
  window.parent.postMessage({ action: 'popupReady' }, '*');
});