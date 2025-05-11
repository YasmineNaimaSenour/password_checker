// Monitor password fields and automatically open dropdown only for signup forms
(function() {
  // State tracking
  let currentPasswordField = null;
  let dropdownOpen = false;
  
  // Function to find password fields on the page
  function findPasswordFields() {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    
    passwordFields.forEach(field => {
      // Skip if we've already processed this field
      if (field.hasAttribute('data-pw-checker-enhanced')) {
        return;
      }
      
      // Mark as processed
      field.setAttribute('data-pw-checker-enhanced', 'true');
      
      // Add event listeners
      field.addEventListener('focus', event => {
        if (isSignupForm(field)) {
          currentPasswordField = event.target;
          openDropdown(currentPasswordField);
        }
      });
      
      field.addEventListener('input', event => {
        if (currentPasswordField === event.target && dropdownOpen) {
          // Send password value to dropdown
          sendPasswordToDropdown(event.target.value);
        }
      });
      
      field.addEventListener('blur', event => {
        // Give time for possible click on dropdown before closing
        setTimeout(() => {
          if (!dropdownIsActive()) {
            closeDropdown();
            currentPasswordField = null;
          }
        }, 200);
      });
    });
  }
  
  // Function to determine if this is likely a signup form
  function isSignupForm(passwordField) {
    // Strategy: Check for common signup indicators in the form or nearby elements
    
    // 1. Check if there's a "confirm password" field in the same form
    const form = passwordField.closest('form');
    if (form) {
      const inputs = form.querySelectorAll('input[type="password"]');
      if (inputs.length >= 2) return true;
    }
    
    // 2. Check nearby text for signup-related terms (within parent or grandparent)
    const container = passwordField.closest('form') || 
                     passwordField.parentElement || 
                     passwordField.parentElement?.parentElement;
    
    if (container) {
      const text = container.innerText.toLowerCase();
      const signupTerms = [
        'sign up', 'signup', 'register', 'create account', 'join', 'new account',
        'get started', 'create password', 'confirm password'
      ];
      
      for (const term of signupTerms) {
        if (text.includes(term)) return true;
      }
    }
    
    // 3. Check for login-specific terms (negative indicators)
    if (container) {
      const text = container.innerText.toLowerCase();
      const loginTerms = [
        'sign in', 'signin', 'log in', 'login', 'forgot password', 'reset password'
      ];
      
      let hasLoginTerm = false;
      for (const term of loginTerms) {
        if (text.includes(term)) {
          hasLoginTerm = true;
          break;
        }
      }
      
      // If it has a login term but no signup terms, it's likely not a signup form
      if (hasLoginTerm) return false;
    }
    
    // 4. Check URL for signup indicators
    const url = window.location.href.toLowerCase();
    const signupUrlTerms = ['signup', 'register', 'join', 'create', 'new'];
    for (const term of signupUrlTerms) {
      if (url.includes(term)) return true;
    }
    
    // For testing purposes - enable on all password fields until signup detection is verified
    return true; // TEMPORARY: Remove this line and uncomment the next line when testing is complete
    // return false; // Default to false - better to miss some signup forms than annoy users during login
  }
  
  // Function to open the dropdown panel
  function openDropdown(passwordField) {
    if (dropdownOpen) return;
    
    const rect = passwordField.getBoundingClientRect();
    const viewportHeight = window.innerHeight;
    
    // Get the width of the password field for the dropdown
    const fieldWidth = Math.max(rect.width, 250); // Minimum width of 250px
    
    // Create dropdown iframe
    const dropdown = document.createElement('iframe');
    dropdown.id = 'pw-checker-dropdown';
    
    // Calculate optimal position
    let positionTop, positionLeft;
    
    // Position below input field by default
    positionTop = rect.bottom + window.scrollY;
    positionLeft = rect.left + window.scrollX;
    
    // Adjust if would go off screen
    if (positionTop + 150 > viewportHeight + window.scrollY) {
      // Position above input instead
      positionTop = rect.top + window.scrollY - 150;
    }
    
    dropdown.style.cssText = `
      position: absolute;
      top: ${positionTop}px;
      left: ${positionLeft}px;
      width: ${fieldWidth}px;
      height: 150px;
      border: none;
      border-radius: 4px;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
      background-color: white;
      z-index: 2147483647;
      opacity: 0;
      transform: translateY(-5px);
      transition: opacity 0.2s ease, transform 0.2s ease;
    `;
    
    // Create source URL for the dropdown (using a custom page without input field)
    dropdown.src = chrome.runtime.getURL('dropdown.html');
    
    // Append to body
    document.body.appendChild(dropdown);
    
    // Animate in after a short delay
    setTimeout(() => {
      dropdown.style.opacity = '1';
      dropdown.style.transform = 'translateY(0)';
      dropdownOpen = true;
      
      // Initialize with current password if field has value
      if (passwordField.value) {
        // Wait a bit to ensure iframe is loaded
        setTimeout(() => {
          sendPasswordToDropdown(passwordField.value);
        }, 100);
      }
    }, 50);
    
    // Add listener for messages from dropdown
    window.addEventListener('message', handleDropdownMessages);
    
    // Close dropdown when clicking outside
    document.addEventListener('click', handleOutsideClick);
  }
  
  // Close the dropdown
  function closeDropdown() {
    const dropdown = document.getElementById('pw-checker-dropdown');
    if (dropdown) {
      dropdown.style.opacity = '0';
      dropdown.style.transform = 'translateY(-5px)';
      
      // Remove after animation completes
      setTimeout(() => {
        if (dropdown && dropdown.parentNode) {
          dropdown.parentNode.removeChild(dropdown);
        }
        dropdownOpen = false;
      }, 200);
    }
    
    // Remove event listeners
    window.removeEventListener('message', handleDropdownMessages);
    document.removeEventListener('click', handleOutsideClick);
  }
  
  // Handle clicks outside the dropdown
  function handleOutsideClick(event) {
    const dropdown = document.getElementById('pw-checker-dropdown');
    
    // Close if click outside dropdown and password field
    if (dropdown && 
        event.target !== dropdown && 
        event.target !== currentPasswordField && 
        !dropdown.contains(event.target) && 
        !currentPasswordField.contains(event.target)) {
      closeDropdown();
    }
  }
  
  // Check if dropdown is currently being interacted with
  function dropdownIsActive() {
    const dropdown = document.getElementById('pw-checker-dropdown');
    return document.activeElement === dropdown;
  }
  
  // Send password text to dropdown iframe
  function sendPasswordToDropdown(password) {
    const dropdown = document.getElementById('pw-checker-dropdown');
    if (dropdown && dropdown.contentWindow) {
      // Use postMessage to send data to the iframe
      dropdown.contentWindow.postMessage({
        action: 'updatePassword',
        password: password
      }, '*');
      
      // For debugging
      console.log('[PasswordChecker] Sending password to dropdown:', password ? '(password value sent)' : 'empty');
    } else {
      console.log('[PasswordChecker] Dropdown or contentWindow not available');
    }
  }
  
  // Handle messages from dropdown
  // Enhance the handleDropdownMessages function
  function handleDropdownMessages(event) {
    // Make sure message is from our dropdown
    const dropdown = document.getElementById('pw-checker-dropdown');
    if (!dropdown || event.source !== dropdown.contentWindow) {
      return;
    }
    
    console.log('[PasswordChecker] Received message from dropdown:', event.data.action);
    
    if (event.data.action === 'close') {
      closeDropdown();
    } else if (event.data.action === 'popupReady') {
      // Dropdown is loaded and ready - send initial password if available
      console.log('[PasswordChecker] Dropdown reports ready');
      if (currentPasswordField && currentPasswordField.value) {
        sendPasswordToDropdown(currentPasswordField.value);
      }
    } else if (event.data.action === 'debug') {
      // For debugging
      console.log('[PasswordChecker] Debug from dropdown:', event.data.message);
    }
  }
  
  // Run initial search for password fields
  findPasswordFields();
  
  // Use MutationObserver to detect dynamically added password fields
  const observer = new MutationObserver((mutations) => {
    let shouldScan = false;
    
    for (const mutation of mutations) {
      if (mutation.type === 'childList' && mutation.addedNodes.length) {
        shouldScan = true;
        break;
      }
    }
    
    if (shouldScan) {
      findPasswordFields();
    }
  });
  
  // Start observing
  observer.observe(document.body, { 
    childList: true, 
    subtree: true 
  });
  
  // For debugging in console
  console.log('[PasswordChecker] Content script loaded');
})();