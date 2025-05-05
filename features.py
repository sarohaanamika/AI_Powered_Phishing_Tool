import re
import numpy as np
from urllib.parse import urlparse

def extract_features(url):
    features = []
    parsed = urlparse(url)
    hostname = parsed.netloc
    path = parsed.path

    # Length of URL
    features.append(len(url))

    # Number of dots
    features.append(url.count('.'))

    # Presence of '@' symbol
    features.append(1 if '@' in url else 0)

    # Presence of '-' symbol
    features.append(1 if '-' in url else 0)

    # Count of subdomains
    features.append(len(hostname.split('.')) - 2)

    # Presence of IP address in domain
    features.append(1 if re.match(r'\\d+\\.\\d+\\.\\d+\\.\\d+', hostname) else 0)

    # Presence of suspicious keywords
    keywords = ['login', 'verify', 'update', 'secure', 'account']
    features.append(1 if any(keyword in url.lower() for keyword in keywords) else 0)

    return np.array(features).reshape(1, -1)
