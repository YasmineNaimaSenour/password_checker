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
    <div class="strength-meter" style="height: 8px; border-radius: 4px; background-color: #E5E7EB; margin: 8px 0; overflow: hidden;">
      <div class="strength-progress" style="height: 100%; width: 0%; border-radius: 4px; transition: width 0.3s ease, background-color 0.3s ease;"></div>
    </div>
    <p class="strength-text" style="font-size: 14px; font-weight: 500; margin: 0;">Password strength: <span class="strength-value">None</span></p>
    <div class="password-rules" style="display: flex; flex-direction: column; gap: 8px; margin-top: 8px;">
      <div id="ruleLength" class="rule-item" style="display: flex; align-items: center; gap: 8px; font-size: 14px; color: #6B7280;">
        <span class="rule-icon" style="width: 16px; height: 16px; display: flex; align-items: center; justify-content: center; border-radius: 50%;">❌</span>
        <span class="text">At least 8 characters</span>
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
      <div id="ruleDictionary" class="rule-item" style="display: flex; align-items: center; gap: 8px; font-size: 14px; color: #6B7280;">
        <span class="rule-icon" style="width: 16px; height: 16px; display: flex; align-items: center; justify-content: center; border-radius: 50%;">❌</span>
        <span class="text">Not a common password</span>
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

// Function to analyze password and update panel
function analyzePassword(password, panel) {
  const strength = calculatePasswordStrength(password);
  updateStrengthMeter(strength, panel);
  updateRuleIcons(password, panel);
  updateCrackingTime(password, panel);
}

// Calculate password strength (reused from popup.js)
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
  if (isCommonPassword(password)) {
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
  
  if (password.length > 12) {
    strength += (password.length - 12) * 2;
  }
  
  return Math.max(0, Math.min(100, strength));
}

// Update strength meter
function updateStrengthMeter(strength, panel) {
  const progress = panel.querySelector('.strength-progress');
  const text = panel.querySelector('.strength-text');
  
  if (!progress || !text) return;
  
  progress.style.width = strength + '%';
  
  progress.className = 'strength-progress';
  text.className = 'strength-text';
  
  if (strength < 25) {
    progress.classList.add('progress-weak');
    text.classList.add('strength-weak');
    text.textContent = 'Weak';
  } else if (strength < 50) {
    progress.classList.add('progress-fair');
    text.classList.add('strength-fair');
    text.textContent = 'Fair';
  } else if (strength < 75) {
    progress.classList.add('progress-good');
    text.classList.add('strength-good');
    text.textContent = 'Good';
  } else {
    progress.classList.add('progress-strong');
    text.classList.add('strength-strong');
    text.textContent = 'Strong';
  }
}

// Update rule icons
function updateRuleIcons(password, panel) {
  const rules = {
    ruleLength: password.length >= 8,
    ruleUppercase: /[A-Z]/.test(password),
    ruleLowercase: /[a-z]/.test(password),
    ruleNumber: /[0-9]/.test(password),
    ruleSpecial: /[^A-Za-z0-9]/.test(password),
    ruleDictionary: !isCommonPassword(password)
  };

  for (const [ruleId, isPassed] of Object.entries(rules)) {
    const element = panel.querySelector(`#${ruleId}`);
    if (element) {
      const icon = element.querySelector('.rule-icon');
      if (icon) {
        icon.textContent = isPassed ? '✅' : '❌';
        element.classList.remove(isPassed ? 'rule-failed' : 'rule-passed');
        element.classList.add(isPassed ? 'rule-passed' : 'rule-failed');
      }
    }
  }
}

// Update cracking time
function updateCrackingTime(password, panel) {
  const crackingTimeElement = panel.querySelector('.cracking-time');
  if (!crackingTimeElement) return;

  const result = estimateCrackingTime(password);
  crackingTimeElement.textContent = `Estimated cracking time: ${result.time}`;
  
  crackingTimeElement.className = 'cracking-time';
  if (result.vulnerable) {
    crackingTimeElement.classList.add('vulnerable');
  }
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
    }
    
    // Debounced update function
    const debouncedAnalyze = debounce(() => {
      analyzePassword(input.value, panel);
    }, 300);
    
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