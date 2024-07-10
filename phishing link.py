import requests
from urllib.parse import urlparse
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn import metrics
import re

def follow_redirects(url):
    """
    Follows URL redirections and returns the final URL and HTTP status code.
    """
    try:
        response = requests.head(url, allow_redirects=True)
        final_url = response.url
        http_status = response.status_code
        return final_url, http_status
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None, None

def extract_domain(url):
    """
    Extracts the domain from the URL.
    """
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    if domain.startswith('www.'):
        domain = domain[4:]  # Remove 'www.' if present
    return domain

def check_blacklist(url):
    """
    Check if the domain is in a known phishing blacklist.
    """
    phishing_blacklist = [
        'badwebsite1.com',
        'evilphisher.org',
        'malicious-site.biz',
        # Add more domains as needed
    ]
    
    domain = extract_domain(url)
    if domain in phishing_blacklist:
        return True
    
    return False

def detect_phishing_ml(url, model, vectorizer):
    """
    Detect phishing using machine learning model.
    """
    features = vectorizer.transform([url])
    prediction = model.predict(features)
    return prediction[0] == 'phishing'

def detect_phishing(url, model, vectorizer):
    """
    Detect phishing based on URL characteristics and machine learning.
    """
    try:
        # Follow redirections and get final URL
        final_url, http_status = follow_redirects(url)
        
        if final_url:
            print(f"Final URL after redirection: {final_url}")
            print(f"HTTP Status Code: {http_status}")
            
            # Check if the final URL is in a phishing blacklist
            if check_blacklist(final_url):
                return True
            
            # Check for other phishing indicators
            if re.search(r'\bsecure\b|\blogin\b|\baccount\b|\bverify\b|\bupdate\b|\bsignin\b', final_url, re.IGNORECASE):
                return True
            
            # Detect phishing using machine learning model
            if detect_phishing_ml(final_url, model, vectorizer):
                return True
        
        return False
    
    except Exception as e:
        print(f"Error detecting phishing: {e}")
        return False

# Sample data for ML model
data = [
    ("http://example.com/login", "phishing"),
    ("http://secure.example.com/verify", "phishing"),
    ("http://examplebank.com/account", "phishing"),
    ("http://trustedsite.com/home", "legitimate"),
    ("http://example.com/shop", "legitimate"),
    ("http://online.example.com", "legitimate"),
]

# Prepare the dataset for ML model
urls, labels = zip(*data)
vectorizer = CountVectorizer()
X = vectorizer.fit_transform(urls)
y = labels

# Split the dataset for training and testing
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train the ML model
model = MultinomialNB()
model.fit(X_train, y_train)

# Evaluate the model (optional, for verification purposes)
y_pred = model.predict(X_test)
print(metrics.classification_report(y_test, y_pred))

# Example usage with user input
if __name__ == "__main__":
    url = input("Enter a URL to analyze: ").strip()
    
    # Detect phishing
    is_phishing = detect_phishing(url, model, vectorizer)
    
    if is_phishing:
        print("Phishing Detected!")
    else:
        print("No Phishing Detected.")
