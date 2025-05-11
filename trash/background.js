// Keep track of active tabs with password fields
let activePasswordFields = {};

// Listen for messages from content scripts
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab ? sender.tab.id : null;
  
  if (message.action === 'passwordFieldDetected') {
    // Record that this tab has a password field
    if (tabId) {
      activePasswordFields[tabId] = true;
    }
    sendResponse({ success: true });
  }
  else if (message.action === 'getPasswordFieldStatus') {
    // Return whether the current tab has password fields
    sendResponse({ hasPasswordField: activePasswordFields[tabId] || false });
  }
  else if (message.action === 'closePopup') {
    // Forward close command to content script
    if (tabId) {
      browser.tabs.sendMessage(tabId, { action: 'closePopup' });
    }
    sendResponse({ success: true });
  }
});

// Clean up when tabs are closed
browser.tabs.onRemoved.addListener((tabId) => {
  if (activePasswordFields[tabId]) {
    delete activePasswordFields[tabId];
  }
});