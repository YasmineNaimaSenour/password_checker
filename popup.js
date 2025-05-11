document.addEventListener('DOMContentLoaded', function() {
  const passwordInput = document.getElementById('password');
  const togglePassword = document.getElementById('togglePassword');
  const strengthProgress = document.getElementById('strengthProgress');
  const strengthText = document.getElementById('strengthValue');
  const crackingTimeElement = document.getElementById('crackingTime');
  
  // Rule elements
  const ruleLength = document.getElementById('ruleLength');
  const ruleUppercase = document.getElementById('ruleUppercase');
  const ruleLowercase = document.getElementById('ruleLowercase');
  const ruleNumber = document.getElementById('ruleNumber');
  const ruleSpecial = document.getElementById('ruleSpecial');
  const ruleDictionary = document.getElementById('ruleDictionary');
  
  // Toggle password visibility
  togglePassword.addEventListener('click', function() {
    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', type);
    togglePassword.textContent = type === 'password' ? '👁️' : '🔒';
  });

  // Check password strength on input
  passwordInput.addEventListener('input', function() {
    const password = passwordInput.value;
    analyzePassword(password);
  });
  
  // Function to analyze password strength and update UI
  function analyzePassword(password) {
    const strength = calculatePasswordStrength(password);
    updateStrengthMeter(strength);
    updateRuleIcons(password);
    updateCrackingTime(password);
  }

  // Calculate password strength using enhanced algorithm
  function calculatePasswordStrength(password) {
    if (!password) return 0;
    
    let strength = 0;
    
    // Length check (up to 36 points)
    strength += Math.min(36, password.length * 3);
    
    // Character variety checks (up to 60 points)
    if (/[A-Z]/.test(password)) strength += 16; // uppercase
    if (/[a-z]/.test(password)) strength += 16; // lowercase
    if (/[0-9]/.test(password)) strength += 16; // numbers
    if (/[^A-Za-z0-9]/.test(password)) strength += 16; // special chars
    
    // Check for common passwords and patterns (up to -40 points)
    if (typeof isCommonPassword === 'function' && isCommonPassword(password)) {
      strength -= 40;
    } else {
      // Check for common patterns ourselves if the external function isn't available
      if (/123|abc|qwerty|password|admin|welcome/i.test(password)) {
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
    
    // Length bonus for longer passwords
    if (password.length > 12) {
      strength += (password.length - 12) * 2;
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

  function updateRuleIcons(password) {
    // Check each rule and update the icon
    // Length rule
    updateRuleIcon(ruleLength, password.length >= 8);
    
    // Uppercase rule
    updateRuleIcon(ruleUppercase, /[A-Z]/.test(password));
    
    // Lowercase rule
    updateRuleIcon(ruleLowercase, /[a-z]/.test(password));
    
    // Number rule
    updateRuleIcon(ruleNumber, /[0-9]/.test(password));
    
    // Special character rule
    updateRuleIcon(ruleSpecial, /[^A-Za-z0-9]/.test(password));
    
    // Dictionary word rule (if present)
    if (ruleDictionary) {
      const isDictionaryPassword = typeof isCommonPassword === 'function' ? 
        isCommonPassword(password) : 
        /123|abc|qwerty|password|admin|welcome/i.test(password);
        
      updateRuleIcon(ruleDictionary, !isDictionaryPassword);
    }
  }

  function updateRuleIcon(element, isPassed) {
    if (!element) return;
    
    element.textContent = isPassed ? '✅' : '❌';
    element.classList.remove(isPassed ? 'rule-failed' : 'rule-passed');
    element.classList.add(isPassed ? 'rule-passed' : 'rule-failed');
  }
  
  // Update the cracking time display
  function updateCrackingTime(password) {
    if (!crackingTimeElement) return;
    
    let result;
    
    if (typeof estimateCrackingTime === 'function') {
      // Use the imported function if available
      result = estimateCrackingTime(password);
    } else {
      // Simplified internal implementation as fallback
      result = simplifiedCrackingTimeEstimate(password);
    }
    
    crackingTimeElement.textContent = result.time;
    
    // Update styling based on vulnerability
    crackingTimeElement.className = 'cracking-time';
    if (result.vulnerable) {
      crackingTimeElement.classList.add('vulnerable');
    }
  }
  
  // Simple fallback cracking time estimator
  function simplifiedCrackingTimeEstimate(password) {
    if (!password) return { time: 'Instantly', vulnerable: true };
    
    let charactersInSet = 0;
    if (/[a-z]/.test(password)) charactersInSet += 26;
    if (/[A-Z]/.test(password)) charactersInSet += 26;
    if (/[0-9]/.test(password)) charactersInSet += 10;
    if (/[^A-Za-z0-9]/.test(password)) charactersInSet += 33;
    
    // If no character sets are used
    if (charactersInSet === 0) {
      return { time: 'Instantly', vulnerable: true };
    }
    
    const combinations = Math.pow(charactersInSet, password.length);
    const guessesPerSecond = 1000000000; // 1 billion
    const seconds = combinations / guessesPerSecond;
    
    let timeString;
    let vulnerable = true;
    
    if (seconds < 1) timeString = 'Instantly';
    else if (seconds < 60) timeString = Math.round(seconds) + ' seconds';
    else if (seconds < 3600) timeString = Math.round(seconds / 60) + ' minutes';
    else if (seconds < 86400) timeString = Math.round(seconds / 3600) + ' hours';
    else if (seconds < 2592000) {
      timeString = Math.round(seconds / 86400) + ' days';
      vulnerable = false;
    }
    else if (seconds < 31536000) {
      timeString = Math.round(seconds / 2592000) + ' months';
      vulnerable = false;
    }
    else {
      timeString = Math.round(seconds / 31536000) + ' years';
      vulnerable = false;
    }
    
    return { time: timeString, vulnerable };
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