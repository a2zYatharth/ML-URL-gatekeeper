import re
import urllib.parse
import socket
import ssl
import whois
from bs4 import BeautifulSoup
from datetime import datetime

class HybridFeatureExtractor:
    def __init__(self, target_url, dom_content):
        self.raw_url = target_url
        self.parsed_url = urllib.parse.urlparse(target_url)
        self.domain = self.parsed_url.netloc
        self.dom_content = dom_content
        self.soup = BeautifulSoup(dom_content, 'html.parser') if dom_content else None

    def extract_lexical(self):
        url_string = self.raw_url
        letters = sum(c.isalpha() for c in url_string)
        digits = sum(c.isdigit() for c in url_string)
        
        return {
            "url_length": len(url_string),
            "dot_count": url_string.count('.'),
            "at_symbol_present": 1 if '@' in url_string else 0,
            "hyphen_count": url_string.count('-'),
            "digit_to_letter_ratio": round(digits / letters, 3) if letters > 0 else 0
        }

    def extract_content(self):
        if not self.soup:
            return {"iframe_count": -1, "hidden_forms": -1, "password_fields": -1}

        iframes = self.soup.find_all('iframe')
        password_inputs = self.soup.find_all('input', type='password')
        
        hidden_forms = 0
        for form in self.soup.find_all('form'):
            if 'hidden' in form.get('style', '').lower() or form.get('type') == 'hidden':
                hidden_forms += 1

        return {
            "iframe_count": len(iframes),
            "hidden_forms": hidden_forms,
            "password_fields": len(password_inputs)
        }

    def extract_hyperlinks(self):
        if not self.soup:
            return {"external_link_ratio": -1.0, "empty_anchors": -1}

        anchors = self.soup.find_all('a', href=True)
        total_links = len(anchors)
        external_links = 0
        empty_anchors = 0

        for a in anchors:
            href = a.get('href', '')
            if href == '#' or href.startswith('javascript:void(0)'):
                empty_anchors += 1
            elif href.startswith('http') and self.domain not in href:
                external_links += 1

        external_ratio = round(external_links / total_links, 3) if total_links > 0 else 0.0

        return {
            "external_link_ratio": external_ratio,
            "empty_anchors": empty_anchors
        }

    def extract_security(self):
        security_features = {"domain_age_days": -1, "ssl_days_to_expire": -1}

        try:
            domain_info = whois.whois(self.domain)
            creation_date = domain_info.creation_date
            if type(creation_date) is list:
                creation_date = creation_date[0]
            
            if creation_date:
                age = (datetime.now() - creation_date).days
                security_features["domain_age_days"] = age
        except Exception:
            pass

        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    expire_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                    days_to_expire = (expire_date - datetime.utcnow()).days
                    security_features["ssl_days_to_expire"] = days_to_expire
        except Exception:
            pass 

        return security_features

    def build_vector(self):
        vector = {}
        vector.update(self.extract_lexical())
        vector.update(self.extract_content())
        vector.update(self.extract_hyperlinks())
        vector.update(self.extract_security())
        return vector