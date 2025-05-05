// Add this at the top of popup.js
const MODEL_COEFFICIENTS = {
  "UsingIP": 0.75,
  "LongURL": 0.63,
  "ShortURL": 0.85,
  "Symbol@": 0.72,
  "Redirecting//": 0.81,
  "PrefixSuffix-": 0.65,
  "SubDomains": 0.73,
  "HTTPS": -0.45,
  "DomainRegLen": -0.35,
  "UsingPopupWindow": 0.68,
  "Iframe": 0.71,
  "Redirection": 0.83,
  "AgeofDomain": -0.52,
  "DNSRecording": -0.48,
  "WebsiteTraffic": -0.41,
  "PageRank": -0.39,
  "GoogleIndex": -0.57,
  "LinksPointingToPage": -0.32,
  "StatsReport": -0.35
};

document.addEventListener('DOMContentLoaded', function() {
  // Load stats from storage
  chrome.storage.local.get(['analyzedCount', 'blockedCount', 'protectionActive'], function(data) {
    document.getElementById('analyzed-count').textContent = data.analyzedCount || 0;
    document.getElementById('blocked-count').textContent = data.blockedCount || 0;
    
    // Set toggle state
    document.getElementById('protection').checked = 
      data.protectionActive === undefined ? true : data.protectionActive;
  });
  
  // Toggle protection
  document.getElementById('protection').addEventListener('change', function(e) {
    const isActive = e.target.checked;
    chrome.storage.local.set({ protectionActive: isActive });
    
    // Notify the background script with proper error handling
    chrome.runtime.sendMessage(
      { action: 'toggleProtection', value: isActive },
      function(response) {
        // Handle response if needed
        console.log("Toggle response:", response);
        // Silent failure if background page isn't ready
      }
    );
  });
  
  // Check current site button
  document.getElementById('check-current').addEventListener('click', function() {
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
      const activeTab = tabs[0];
      const url = activeTab.url;
  
      if (!url || url.startsWith("chrome://") || url.startsWith("about:") || url.startsWith("chrome-extension://")) {
        showResult("This page cannot be analyzed.");
        return;
      }
  
      // Extract features from the URL (and possibly heuristics)
      const features = extractFeaturesFromURL(url);
  
      // Compute the phishing score using model coefficients
      const score = computePhishingScore(features);
  
      showResult(score > 0.5 ? "⚠️ Phishing site detected!" : "✅ This site looks safe.");
      
      // Update stats
      chrome.storage.local.get(['analyzedCount', 'blockedCount'], function(data) {
        const analyzedCount = (data.analyzedCount || 0) + 1;
        const blockedCount = (data.blockedCount || 0) + (score > 0.5 ? 1 : 0);
        chrome.storage.local.set({ analyzedCount, blockedCount });
  
        document.getElementById('analyzed-count').textContent = analyzedCount;
        document.getElementById('blocked-count').textContent = blockedCount;
      });
    });
  });
  
  // Display result to user
  function showResult(text) {
    document.getElementById("top-risk").textContent = text;
  }
  
  // Example heuristic feature extractor (expand based on your dataset)
  function extractFeaturesFromURL(url) {
    return {
      "UsingIP": /\d{1,3}(?:\.\d{1,3}){3}/.test(url) ? 1 : 0,
      "LongURL": url.length > 75 ? 1 : 0,
      "ShortURL": url.length < 20 ? 1 : 0,
      "Symbol@": url.includes('@') ? 1 : 0,
      "Redirecting//": (url.match(/\/\//g) || []).length > 2 ? 1 : 0,
      "PrefixSuffix-": url.includes('-') ? 1 : 0,
      "SubDomains": (url.match(/\./g) || []).length > 3 ? 1 : 0,
      "HTTPS": url.startsWith("https") ? 1 : 0,
      // Add static values (not available from URL directly)
      "DomainRegLen": 0, "Favicon": 0, "NonStdPort": 0,
      "HTTPSDomainURL": 0, "RequestURL": 0, "AnchorURL": 0,
      "LinksInScriptTags": 0, "ServerFormHandler": 0, "InfoEmail": 0,
      "AbnormalURL": 0, "WebsiteForwarding": 0, "StatusBarCust": 0,
      "DisableRightClick": 0, "UsingPopupWindow": 0, "IframeRedirection": 0,
      "AgeofDomain": 0, "DNSRecording": 0, "WebsiteTraffic": 0,
      "PageRank": 0, "GoogleIndex": 0, "LinksPointingToPage": 0,
      "StatsReport": 0
    };
  }
  
  // Score calculator
  function computePhishingScore(features) {
    let score = 0;
    for (let key in MODEL_COEFFICIENTS) {
      score += (features[key] || 0) * MODEL_COEFFICIENTS[key];
    }
    return score;
  }
});

