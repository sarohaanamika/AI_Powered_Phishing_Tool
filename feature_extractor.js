// feature_extractor.js - Detailed implementation of feature extraction

/**
 * Complete feature extraction based on the 30 features in the phishing dataset
 * This maps to the features used in the original Python model
 */
class PhishingFeatureExtractor {
    constructor() {
      // Constants for feature extraction
      this.SHORT_URL_THRESHOLD = 20;
      this.LONG_URL_THRESHOLD = 75;
      this.IP_REGEX = /^(http|https):\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
      this.SHORTENED_SERVICES = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 
        'buff.ly', 'adf.ly', 'bit.do', 'cur.lv', 'tiny.cc', 'shorturl.at'
      ];
    }
  
    /**
     * Extract all features from a URL and page content
     * @param {string} url - The URL to analyze
     * @param {string} domContent - The HTML content of the page
     * @returns {Object} - Object containing all extracted features
     */
    extractAllFeatures(url, domContent) {
      try {
        const urlObj = new URL(url);
        const domain = urlObj.hostname;
        const path = urlObj.pathname;
        
        return {
          // Address-based features
          "UsingIP": this.checkForIP(url),
          "LongURL": this.checkLongURL(url),
          "ShortURL": this.checkShortURL(url),
          "Symbol@": this.checkAtSymbol(url),
          "Redirecting//": this.checkDoubleSlashRedirect(url),
          "PrefixSuffix-": this.checkDashInDomain(domain),
          "SubDomains": this.checkSubDomains(domain),
          "HTTPS": this.checkHTTPS(url),
          "DomainRegLen": this.checkDomainRegistrationLength(domain),
          
          // Abnormal-based features
          "RequestURL": this.checkExternalRequestURLs(domContent, domain),
          "URLofAnchor": this.checkAnchorURLs(domContent, domain),
          "LinksInTags": this.checkLinksInMetaScriptTags(domContent, domain),
          "SFH": this.checkServerFormHandler(domContent),
          "SubmittingToEmail": this.checkSubmitToEmail(domContent),
          "AbnormalURL": this.checkAbnormalURL(url, domain),
          
          // HTML & JavaScript-based features
          "WebsiteForwarding": this.checkWebsiteForwarding(domContent),
          "StatusBarCust": this.checkStatusBarCustomization(domContent),
          "DisablingRightClick": this.checkRightClickDisabled(domContent),
          "UsingPopupWindow": this.checkPopupWindow(domContent),
          "Iframe": this.checkIframeRedirection(domContent),
          
          // Domain-based features
          "AgeofDomain": -1, // Would require WHOIS API
          "DNSRecording": -1, // Would require DNS lookup
          "WebsiteTraffic": -1, // Would require traffic data
          "PageRank": -1, // Would require PageRank data
          "GoogleIndex": -1, // Would require Google search API
          "LinksPointingToPage": this.countLinksPointingToPage(domContent),
          "StatsReport": -1, // Would require external data
          
          // Additional features
          "Redirection": this.checkRedirection(domContent),
          "FaviconDomain": this.checkFaviconDomain(domContent, domain),
          "PortInURL": this.checkPortInURL(url),
          "HTTPSDomainURL": this.checkHTTPSinDomainURL(url)
        };
      } catch (error) {
        console.error("Error extracting features:", error);
        // Return default values for all features in case of error
        return this.getDefaultFeatures();
      }
    }
  
    // Feature extraction methods
    
    // 1. Using IP Address
    checkForIP(url) {
      return this.IP_REGEX.test(url) ? 1 : -1;
    }
    
    // 2. Long URL
    checkLongURL(url) {
      return url.length > this.LONG_URL_THRESHOLD ? 1 : -1;
    }
    
    // 3. Short URL service
    checkShortURL(url) {
      const domain = new URL(url).hostname;
      return this.SHORTENED_SERVICES.some(service => domain.includes(service)) ? 1 : -1;
    }
    
    // 4. @ Symbol in URL
    checkAtSymbol(url) {
      return url.includes('@') ? 1 : -1;
    }
    
    // 5. Double slash redirect
    checkDoubleSlashRedirect(url) {
      // Check for // in the URL path (not in the protocol)
      return url.includes('//') && url.lastIndexOf('//') > 8 ? 1 : -1;
    }
    
    // 6. Prefix-Suffix with dash
    checkDashInDomain(domain) {
      return domain.includes('-') ? 1 : -1;
    }
    
    // 7. Number of subdomains
    checkSubDomains(domain) {
      const subdomainCount = domain.split('.').length - 2;
      return subdomainCount > 2 ? 1 : -1;
    }
    
    // 8. HTTPS protocol
    checkHTTPS(url) {
      return url.startsWith('https://') ? -1 : 1;
    }
    
    // 9. Domain registration length
    checkDomainRegistrationLength(domain) {
      // This would require a WHOIS lookup in practice
      // For the browser extension, we'll use domain length as a proxy
      return domain.length < 8 ? 1 : -1;
    }
    
    // 10. Request URL
    checkExternalRequestURLs(domContent, domain) {
      try {
        const parser = new DOMParser();
        const doc = parser.parseFromString(domContent, "text/html");
        
        // Check images, scripts, and links
        const resources = [
          ...Array.from(doc.querySelectorAll('img')),
          ...Array.from(doc.querySelectorAll('script')),
          ...Array.from(doc.querySelectorAll('link'))
        ];
        
        let externalResourceCount = 0;
        let totalResourceCount = 0;
        
        resources.forEach(resource => {
          let src = resource.src || resource.href;
          if (src) {
            totalResourceCount++;
            try {
              const resourceDomain = new URL(src).hostname;
              if (resourceDomain && resourceDomain !== domain) {
                externalResourceCount++;
              }
            } catch (e) {
              // Relative URL or invalid URL, consider it internal
            }
          }
        });
        
        // Calculate the percentage of external resources
        const externalRatio = totalResourceCount > 0 ? 
          externalResourceCount / totalResourceCount : 0;
          
        return externalRatio > 0.5 ? 1 : -1;
      } catch (e) {
        return 0; // Default if parsing fails
      }
    }
    
    // 11. URL of Anchor
    checkAnchorURLs(domContent, domain) {
      try {
        const parser = new DOMParser();
        const doc = parser.parseFromString(domContent, "text/html");
        
        const anchors = Array.from(doc.querySelectorAll('a'));
        let suspiciousCount = 0;
        
        anchors.forEach(anchor => {
          const href = anchor.getAttribute('href');
          if (href) {
            if (href === '#' || href.startsWith('javascript:') || 
                href.includes('void(0)') || href === '') {
              suspiciousCount++;
            } else {
              try {
                const anchorDomain = new URL(href, document.baseURI).hostname;
                if (anchorDomain && anchorDomain !== domain) {
                  suspiciousCount++;
                }
              } catch (e) {
                // Invalid URL, consider it suspicious
                suspiciousCount++;
              }
            }
          }
        });
        
        // Calculate the ratio of suspicious anchors
        const suspiciousRatio = anchors.length > 0 ? 
          suspiciousCount / anchors.length : 0;
          
        return suspiciousRatio > 0.5 ? 1 : -1;
      } catch (e) {
        return 0; // Default if parsing fails
      }
    }
    
    // 12. Links in Meta, Script, and Link tags
    checkLinksInMetaScriptTags(domContent, domain) {
      try {
        const parser = new DOMParser();
        const doc = parser.parseFromString(domContent, "text/html");
        
        const metaLinks = Array.from(doc.querySelectorAll('meta')).filter(
          meta => meta.getAttribute('http-equiv') === 'refresh' || meta.getAttribute('content')?.includes('URL=')
        );
        
        const scriptLinks = Array.from(doc.querySelectorAll('script')).filter(
          script => script.getAttribute('src')
        );
        
        const linkTags = Array.from(doc.querySelectorAll('link')).filter(
          link => link.getAttribute('href')
        );
        
        const totalTags = metaLinks.length + scriptLinks.length + linkTags.length;
        let externalCount = 0;
        
        const checkExternalURL = (url) => {
          try {
            const urlDomain = new URL(url, document.baseURI).hostname;
            return urlDomain !== domain;
          } catch (e) {
            return false;
          }
        };
        
        metaLinks.forEach(meta => {
          const content = meta.getAttribute('content');
          if (content && content.includes('URL=')) {
            const url = content.split('URL=')[1];
            if (checkExternalURL(url)) externalCount++;
          }
        });
        
        scriptLinks.forEach(script => {
          if (checkExternalURL(script.getAttribute('src'))) externalCount++;
        });
        
        linkTags.forEach(link => {
          if (checkExternalURL(link.getAttribute('href'))) externalCount++;
        });
        
        const externalRatio = totalTags > 0 ? externalCount / totalTags : 0;
        return externalRatio > 0.5 ? 1 : -1;
      } catch (e) {
        return 0; // Default if parsing fails
      }
    }
    
    // 13. Server Form Handler
    checkServerFormHandler(domContent) {
      try {
        const parser = new DOMParser();
        const doc = parser.parseFromString(domContent, "text/html");
        
        const forms = Array.from(doc.querySelectorAll('form'));
        let suspiciousCount = 0;
        
        forms.forEach(form => {
          const action = form.getAttribute('action');
          if (!action || action === '' || action === 'about:blank') {
            suspiciousCount++;
          }
        });
        
        return forms.length > 0 && suspiciousCount / forms.length > 0.5 ? 1 : -1;
      } catch (e) {
        return 0; // Default if parsing fails
      }
    }
    
    // 14. Submitting to Email
    checkSubmitToEmail(domContent) {
      return domContent.includes('mailto:') || 
             domContent.includes('mail()') || 
             /action\s*=\s*["']mailto:/i.test(domContent) ? 1 : -1;
    }
    
    // 15. Abnormal URL
    checkAbnormalURL(url, domain) {
      try {
        // Check if the URL contains the domain name
        // This is a simplified check - in reality this would compare against WHOIS data
        return url.includes(domain) ? -1 : 1;
      } catch (e) {
        return 0; // Default if check fails
      }
    }
    
    // 16. Website Forwarding
    checkWebsiteForwarding(domContent) {
      const redirectCount = (domContent.match(/window\.location/g) || []).length +
                           (domContent.match(/document\.location/g) || []).length +
                           (domContent.match(/href\s*=\s*["'][^"']*/g) || []).length;
      return redirectCount > 3 ? 1 : -1;
    }
    
    // 17. Status Bar Customization
    checkStatusBarCustomization(domContent) {
      return domContent.includes('onmouseover="window.status') ||
             domContent.includes('void(0)') ||
             domContent.includes('return false') ? 1 : -1;
    }
    
    // 18. Right Click Disabled
    checkRightClickDisabled(domContent) {
      return domContent.includes('preventDefault()') ||
             domContent.includes('oncontextmenu="return false"') ||
             domContent.includes('event.button==2') ? 1 : -1;
    }
    
    // 19. Popup Window
    checkPopupWindow(domContent) {
      return domContent.includes('window.open') ||
             domContent.includes('alert(') ? 1 : -1;
    }
    
    // 20. Iframe Redirection
    checkIframeRedirection(domContent) {
      return domContent.includes('<iframe') ? 1 : -1;
    }
    
    // 24. Links Pointing to Page
    countLinksPointingToPage(domContent) {
      // This would typically require external information
      // For a browser extension we'll look at internal links
      try {
        const parser = new DOMParser();
        const doc = parser.parseFromString(domContent, "text/html");
        
        const links = doc.querySelectorAll('a');
        // A legitimate site typically has many internal links
        return links.length > 5 ? -1 : 1;
      } catch (e) {
        return 0; // Default if parsing fails
      }
    }
    
    // 28. Redirection
    checkRedirection(domContent) {
      return domContent.includes('window.location.replace') || 
             domContent.includes('window.location.href=') ||
             domContent.includes('window.location=') ||
             domContent.includes('document.location=') ? 1 : -1;
    }
    
    // 29. Favicon from different domain
    checkFaviconDomain(domContent, domain) {
      try {
        const parser = new DOMParser();
        const doc = parser.parseFromString(domContent, "text/html");
        
        const favicon = doc.querySelector('link[rel="shortcut icon"], link[rel="icon"]');
        if (favicon) {
          const href = favicon.getAttribute('href');
          if (href) {
            try {
              const faviconDomain = new URL(href, document.baseURI).hostname;
              if (faviconDomain && faviconDomain !== domain) {
                return 1;
              }
            } catch (e) {
              // Relative URL or invalid URL, consider it internal
            }
          }
        }
        return -1;
      } catch (e) {
        return 0; // Default if parsing fails
      }
    }
    
    // 30. Port in URL
    checkPortInURL(url) {
      try {
        const urlObj = new URL(url);
        // Check if explicit port is specified
        return urlObj.port ? 1 : -1;
      } catch (e) {
        return 0; // Default if URL parsing fails
      }
    }
    
    // 31. HTTPS in domain part of URL
    checkHTTPSinDomainURL(url) {
      try {
        const domain = new URL(url).hostname;
        return domain.includes('https') ? 1 : -1;
      } catch (e) {
        return 0; // Default if URL parsing fails
      }
    }
    
    // Get default feature values when extraction fails
    getDefaultFeatures() {
      // Return all features with a default value of 0 (unknown)
      return {
        "UsingIP": 0,
        "LongURL": 0,
        "ShortURL": 0,
        "Symbol@": 0,
        "Redirecting//": 0,
        "PrefixSuffix-": 0,
        "SubDomains": 0,
        "HTTPS": 0,
        "DomainRegLen": 0,
        "RequestURL": 0,
        "URLofAnchor": 0,
        "LinksInTags": 0,
        "SFH": 0,
        "SubmittingToEmail": 0,
        "AbnormalURL": 0,
        "WebsiteForwarding": 0,
        "StatusBarCust": 0,
        "DisablingRightClick": 0,
        "UsingPopupWindow": 0,
        "Iframe": 0,
        "AgeofDomain": 0,
        "DNSRecording": 0,
        "WebsiteTraffic": 0,
        "PageRank": 0,
        "GoogleIndex": 0,
        "LinksPointingToPage": 0,
        "StatsReport": 0,
        "Redirection": 0,
        "FaviconDomain": 0,
        "PortInURL": 0,
        "HTTPSDomainURL": 0
      };
    }
  }