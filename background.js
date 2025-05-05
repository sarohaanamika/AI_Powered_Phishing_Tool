const SAFE_REDIRECT_URL = "https://github.com/sarohaanamika";
const MODEL_FEATURES = [
  "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//", 
  "PrefixSuffix-", "SubDomains", "HTTPS", "DomainRegLen", "UsingPopupWindow", 
  "Iframe", "Redirection", "AgeofDomain", "DNSRecording", "WebsiteTraffic", 
  "PageRank", "GoogleIndex", "LinksPointingToPage", "StatsReport"
];

// Pre-trained model coefficients (you'll need to export these from your Python model)
const MODEL_COEFFICIENTS = {
  // This will be populated with your actual model coefficients
  // For demonstration, using placeholder values
  "UsingIP": 0.75,
  "LongURL": 0.63,
  "ShortURL": 0.85,
  "Symbol@": 0.72,
  "Redirecting//": 0.81,
  "PrefixSuffix-": 0.65,
  "SubDomains": 0.73,
  "HTTPS": -0.45,  // Negative as HTTPS is generally good
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

// Add this near the beginning of background.js after defining MODEL_COEFFICIENTS
chrome.storage.local.set({ 'modelCoefficients': MODEL_COEFFICIENTS });

// Constants for feature extraction
const SHORT_URL_THRESHOLD = 20;
const LONG_URL_THRESHOLD = 75;
const URL_REGEX = /^(http|https):\/\/[^ "]+$/;
const IP_REGEX = /^(http|https):\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
const SHORTENED_SERVICES = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 
  'buff.ly', 'adf.ly', 'bit.do', 'cur.lv', 'tiny.cc', 'shorturl.at'
];

// Feature extraction functions
function extractFeatures(url, domContent) {
  const features = {};
  
  // Basic URL features
  features["UsingIP"] = IP_REGEX.test(url) ? 1 : -1;
  features["LongURL"] = url.length > LONG_URL_THRESHOLD ? 1 : -1;
  
  // Check for URL shortening services
  const domain = new URL(url).hostname;
  features["ShortURL"] = SHORTENED_SERVICES.some(service => domain.includes(service)) ? 1 : -1;
  
  // Symbol features
  features["Symbol@"] = url.includes('@') ? 1 : -1;
  features["Redirecting//"] = url.includes('//') && url.lastIndexOf('//') > 6 ? 1 : -1;
  features["PrefixSuffix-"] = domain.includes('-') ? 1 : -1;
  
  // Domain features
  const subdomains = domain.split('.').length - 2;
  features["SubDomains"] = subdomains > 2 ? 1 : -1;
  features["HTTPS"] = url.startsWith('https://') ? -1 : 1;
  features["DomainRegLen"] = domain.length < 8 ? 1 : -1;
  
  // Content-based features (would require DOM analysis)
  features["UsingPopupWindow"] = domContent.includes('window.open') ? 1 : -1;
  features["Iframe"] = domContent.includes('<iframe') ? 1 : -1;
  features["Redirection"] = domContent.includes('window.location.replace') || 
                          domContent.includes('window.location.href') ? 1 : -1;
  
  // These features would require API calls in a real implementation
  // For demo purposes, we'll use placeholder values
  features["AgeofDomain"] = -1;  // Placeholder
  features["DNSRecording"] = -1; // Placeholder
  features["WebsiteTraffic"] = -1; // Placeholder
  features["PageRank"] = -1; // Placeholder
  features["GoogleIndex"] = -1; // Placeholder
  features["LinksPointingToPage"] = -1; // Placeholder
  features["StatsReport"] = -1; // Placeholder
  
  return features;
}

function predictWithGradientBoosting(features) {
    // Check if MODEL_COEFFICIENTS is defined
    if (typeof MODEL_COEFFICIENTS === 'undefined') {
      console.error("MODEL_COEFFICIENTS is not defined");
      return -1; // Default to "legitimate" if coefficients are missing
    }
    
    // Rest of your function
    let score = 0;
    for (const feature in features) {
      if (MODEL_COEFFICIENTS.hasOwnProperty(feature)) {
        score += features[feature] * MODEL_COEFFICIENTS[feature];
      }
    }
    
    return score > 0 ? 1 : -1;
  }

// Add this helper function to check if a URL is restricted
function isRestrictedUrl(url) {
    try {
      const parsedUrl = new URL(url);
      return ['chrome:', 'chrome-extension:', 'devtools:', 'edge:', 'about:', 'data:'].includes(parsedUrl.protocol.slice(0, -1));
    } catch (e) {
      return true; // If URL parsing fails, consider it restricted
    }
  }

// Modify your analyzePage function
async function analyzePage(tabId, url) {
    try {
      // Skip analysis for restricted URLs
      if (isRestrictedUrl(url)) {
        console.log("Skipping analysis for restricted URL:", url);
        return;
      }
      
      // Get the page content
      let domContent = "";
      try {
        const [result] = await chrome.scripting.executeScript({
          target: { tabId },
          function: () => document.documentElement.outerHTML
        });
        domContent = result.result;
      } catch (e) {
        console.error("Failed to get page content:", e);
        // Continue with limited analysis if DOM content isn't available
      }
    
    // Extract features
    const features = extractFeatures(url, domContent);
    
    // Make prediction
    const prediction = predictWithGradientBoosting(features);
    
    // Log the results
    console.log("URL analyzed:", url);
    console.log("Features:", features);
    console.log("Prediction:", prediction);
    
    // If phishing is detected, redirect the user
    if (prediction === 1) {
      console.log("Phishing site detected. Redirecting...");
      chrome.tabs.update(tabId, { url: `${SAFE_REDIRECT_URL}?original=${encodeURIComponent(url)}` });
      
      // Update stats
      chrome.storage.local.get(['blockedCount'], function(data) {
        const newCount = (data.blockedCount || 0) + 1;
        chrome.storage.local.set({ blockedCount: newCount });
      });
    }
    
    // Update analyzed count
    chrome.storage.local.get(['analyzedCount'], function(data) {
      const newCount = (data.analyzedCount || 0) + 1;
      chrome.storage.local.set({ analyzedCount: newCount });
    });
  } catch (error) {
    console.error("Error analyzing page:", error);
  }
}

// Listen for navigation events
chrome.webNavigation.onCompleted.addListener(async (details) => {
  // Check if protection is active
  chrome.storage.local.get(['protectionActive'], function(data) {
    const isActive = data.protectionActive === undefined ? true : data.protectionActive;
    
    // Only analyze if protection is active and it's the main frame
    if (isActive && details.frameId === 0) {
      analyzePage(details.tabId, details.url);
    }
  });
});

// Listen for messages from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'checkSite') {
    analyzePage(message.tabId, message.url);
    // Send a response to avoid connection error
    sendResponse({status: "analyzing"});
    return true; // Required to use sendResponse asynchronously
  }
  if (message.action === 'toggleProtection') {
    // Handle protection toggle
    console.log("Protection toggled:", message.value);
    // Send a response to avoid connection error
    sendResponse({status: "protection toggled"});
    return true; 
  }
});