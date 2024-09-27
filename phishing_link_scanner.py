#phishing link scanner
import tldextract  #takes a domain, divides it into subdomain, its domain and post fix
import Levenshtein as lv
import re

legitimate_domains = ['example.com','google.com','facebook.com', 'pinterest.com']

test_urls = [
    'http://example.co',
    'http://example.com',
    'hhtp://pintrest.com',
    'https://google.com',
    'http://192.168.4.4',
    'http://go0gle.com'
]

def ip_address(test_urls):      # Checks presence of IP address in URL
    
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    if ip_pattern.search(url):
        return True

def extract_domain_parts(url):
    extracted = tldextract.extract(url)
    return extracted.subdomain, extracted.domain, extracted.suffix

def is_mispelled_domain(domain, legitimate_domains, threshold = 0.9):
    for legit_domain in legitimate_domains:
        similarity = lv.ratio(domain, legit_domain)
        if similarity >= threshold:
            print(f"Potential phishing detected: {url}" )
    return True       



def is_phishing_url (url, legitimate_domains):
    subdomain, domain, suffix = extract_domain_parts(url)

    if f"{domain}.{suffix}" in legitimate_domains:
        return False
    
    if is_mispelled_domain(domain, legitimate_domains):
        print(f"Potential phishing detected: {url}" )
        return True
    
    if ip_address(test_urls):
        print(f"Potential phishing detected: {url}" )
        return True

if __name__ == '__main__':
    for url in test_urls:
        is_phishing_url(url, legitimate_domains)
