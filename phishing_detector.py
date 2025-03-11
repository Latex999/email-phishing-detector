#!/usr/bin/env python3

import argparse
import email
import re
import json
import logging
import os
import sys
from email.parser import BytesParser, Parser
from email.policy import default
from urllib.parse import urlparse
import tldextract
import requests
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('phishing_detector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('phishing_detector')

# Load configuration
def load_config():
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        print(f"{Fore.RED}Error loading configuration. Using default settings.{Style.RESET_ALL}")
        return {
            "suspicious_keywords": [
                "urgent", "verify", "update", "account", "bank", "password", "confirm", "suspicious",
                "unusual activity", "security", "login", "verify your account", "click here", "important",
                "alert", "attention", "immediately", "expire", "suspended", "validate", "unauthorized"
            ],
            "suspicious_tlds": [
                ".tk", ".pw", ".cf", ".ga", ".gq", ".ml", ".xyz", ".top", ".club", ".work", ".date",
                ".racing", ".stream", ".bid", ".review", ".trade", ".accountant", ".science", ".win", ".party"
            ],
            "suspicious_senders": [
                "noreply@", "security@", "service@", "support@", "account@", "team@", "update@", "info@", 
                "help@", "admin@", "no-reply@", "notification@", "do-not-reply@"
            ],
            "weight_thresholds": {
                "low": 1.0,
                "medium": 3.0,
                "high": 5.0,
                "critical": 8.0
            }
        }

# Global configuration
config = load_config()

# Phishing detection class
class PhishingDetector:
    def __init__(self, config):
        self.config = config
        self.suspicious_keywords = config.get('suspicious_keywords', [])
        self.suspicious_tlds = config.get('suspicious_tlds', [])
        self.suspicious_senders = config.get('suspicious_senders', [])
        self.weight_thresholds = config.get('weight_thresholds', {})
        self.results = {
            'score': 0.0,
            'flags': [],
            'urls': [],
            'risk_level': 'safe',
            'header_analysis': {},
            'content_analysis': {}
        }
    
    def analyze_email(self, email_data):
        """Main method to analyze an email for phishing indicators"""
        try:
            # Parse the email
            if isinstance(email_data, bytes):
                parser = BytesParser(policy=default)
                msg = parser.parsebytes(email_data)
            else:
                parser = Parser(policy=default)
                msg = parser.parsestr(email_data)
            
            # Analyze headers
            self._analyze_headers(msg)
            
            # Analyze content
            self._analyze_content(msg)
            
            # Calculate final risk score and level
            self._calculate_risk_level()
            
            return self.results
            
        except Exception as e:
            logger.error(f"Error analyzing email: {e}")
            return {'error': str(e)}
    
    def _analyze_headers(self, msg):
        """Analyze email headers for suspicious patterns"""
        header_analysis = {}
        
        # Check sender domain
        from_header = msg.get('From', '')
        sender_analysis = self._analyze_sender(from_header)
        header_analysis['sender'] = sender_analysis
        
        # Check for SPF, DKIM, and DMARC
        authentication = self._check_email_authentication(msg)
        header_analysis['authentication'] = authentication
        
        # Check if Reply-To differs from From
        reply_to = msg.get('Reply-To', '')
        if reply_to and reply_to.lower() != from_header.lower() and '@' in reply_to and '@' in from_header:
            reply_to_domain = reply_to.split('@')[-1].strip('>')
            from_domain = from_header.split('@')[-1].strip('>')
            if reply_to_domain != from_domain:
                header_analysis['reply_to_mismatch'] = {
                    'description': 'Reply-To domain differs from From domain',
                    'from': from_header,
                    'reply_to': reply_to,
                    'weight': 1.5
                }
                self.results['score'] += 1.5
                self.results['flags'].append('Reply-To mismatch')
        
        # Check Subject for suspicious keywords
        subject = msg.get('Subject', '')
        subject_analysis = self._analyze_text(subject, section='subject')
        if subject_analysis['suspicious_count'] > 0:
            header_analysis['subject'] = {
                'text': subject,
                'suspicious_keywords': subject_analysis['suspicious_keywords'],
                'weight': subject_analysis['weight']
            }
            self.results['score'] += subject_analysis['weight']
            if subject_analysis['suspicious_count'] > 0:
                self.results['flags'].append('Suspicious subject')
        
        self.results['header_analysis'] = header_analysis
    
    def _analyze_sender(self, from_header):
        """Analyze the sender information"""
        result = {'weight': 0, 'issues': []}
        
        if not from_header:
            result['issues'].append('Missing From header')
            result['weight'] += 2.0
            self.results['score'] += 2.0
            self.results['flags'].append('Missing sender information')
            return result
        
        # Extract email address from the From header
        email_match = re.search(r'[\w\.-]+@[\w\.-]+', from_header)
        if email_match:
            email_address = email_match.group(0)
            domain = email_address.split('@')[-1]
            
            # Check if domain is suspicious
            ext = tldextract.extract(domain)
            tld = f".{ext.suffix}"
            
            if tld in self.suspicious_tlds:
                result['issues'].append(f'Suspicious TLD: {tld}')
                result['weight'] += 2.0
                self.results['score'] += 2.0
                self.results['flags'].append('Suspicious sender domain')
            
            # Check for suspicious sender patterns
            for pattern in self.suspicious_senders:
                if pattern in email_address.lower():
                    result['issues'].append(f'Suspicious sender pattern: {pattern}')
                    result['weight'] += 0.5
                    self.results['score'] += 0.5
                    if 'Suspicious sender pattern' not in self.results['flags']:
                        self.results['flags'].append('Suspicious sender pattern')
        else:
            result['issues'].append('Could not extract email from From header')
            result['weight'] += 1.0
            self.results['score'] += 1.0
            self.results['flags'].append('Invalid sender format')
        
        return result
    
    def _check_email_authentication(self, msg):
        """Check SPF, DKIM, and DMARC authentication headers"""
        result = {'weight': 0, 'issues': []}
        
        # Check SPF
        received_spf = None
        for header in msg._headers:
            if header[0].lower() == 'received-spf':
                received_spf = header[1]
                break
        
        if not received_spf or 'pass' not in received_spf.lower():
            result['issues'].append('SPF check failed or missing')
            result['weight'] += 1.0
            self.results['score'] += 1.0
            self.results['flags'].append('SPF authentication issue')
        
        # Look for DKIM-Signature header
        dkim_header = None
        for header in msg._headers:
            if header[0].lower() == 'dkim-signature':
                dkim_header = header[1]
                break
        
        if not dkim_header:
            result['issues'].append('DKIM signature missing')
            result['weight'] += 1.0
            self.results['score'] += 1.0
            self.results['flags'].append('DKIM authentication issue')
        
        # Check for DMARC
        authentication_results = None
        for header in msg._headers:
            if header[0].lower() == 'authentication-results':
                authentication_results = header[1]
                break
        
        if not authentication_results or 'dmarc=pass' not in authentication_results.lower():
            result['issues'].append('DMARC check failed or missing')
            result['weight'] += 1.0
            self.results['score'] += 1.0
            self.results['flags'].append('DMARC authentication issue')
        
        return result
    
    def _analyze_content(self, msg):
        """Analyze email content for suspicious patterns"""
        content_analysis = {}
        
        # Get email body
        body = self._get_email_body(msg)
        
        # Check for suspicious text in the body
        if body:
            body_analysis = self._analyze_text(body, section='body')
            content_analysis['text'] = {
                'suspicious_keywords': body_analysis['suspicious_keywords'],
                'suspicious_count': body_analysis['suspicious_count'],
                'weight': body_analysis['weight']
            }
            self.results['score'] += body_analysis['weight']
            if body_analysis['suspicious_count'] > 0:
                self.results['flags'].append('Suspicious content')
        
        # Check for URLs in the body
        if body:
            urls = self._extract_urls(body)
            url_analysis = self._analyze_urls(urls)
            content_analysis['urls'] = url_analysis
            self.results['urls'] = urls
            
            # Add to score
            if url_analysis['suspicious_count'] > 0:
                self.results['score'] += url_analysis['weight']
                self.results['flags'].append('Suspicious URLs')
        
        # Check for attachments
        attachments = self._check_attachments(msg)
        if attachments['suspicious']:
            content_analysis['attachments'] = attachments
            self.results['score'] += attachments['weight']
            self.results['flags'].append('Suspicious attachments')
        
        # Check for urgency language
        urgency_score = self._check_urgency(body)
        if urgency_score > 0:
            content_analysis['urgency'] = {
                'detected': True,
                'weight': urgency_score
            }
            self.results['score'] += urgency_score
            self.results['flags'].append('Urgency indicators')
        
        self.results['content_analysis'] = content_analysis
    
    def _get_email_body(self, msg):
        """Extract the email body text"""
        body = ""
        
        if msg.is_multipart():
            for part in msg.get_payload():
                if part.get_content_type() == "text/plain" or part.get_content_type() == "text/html":
                    try:
                        charset = part.get_content_charset() or 'utf-8'
                        body += part.get_payload(decode=True).decode(charset, errors='ignore')
                    except Exception as e:
                        logger.error(f"Error decoding email part: {e}")
        else:
            try:
                charset = msg.get_content_charset() or 'utf-8'
                body = msg.get_payload(decode=True).decode(charset, errors='ignore')
            except Exception as e:
                logger.error(f"Error decoding email body: {e}")
        
        # Remove HTML tags if present
        body = re.sub(r'<[^>]+>', ' ', body)
        return body
    
    def _analyze_text(self, text, section):
        """Analyze text for suspicious keywords"""
        result = {
            'suspicious_keywords': [],
            'suspicious_count': 0,
            'weight': 0
        }
        
        if not text:
            return result
        
        text_lower = text.lower()
        
        # Check for suspicious keywords
        for keyword in self.suspicious_keywords:
            if keyword.lower() in text_lower:
                result['suspicious_keywords'].append(keyword)
                result['suspicious_count'] += 1
                
                # Apply different weights based on section
                if section == 'subject':
                    result['weight'] += 0.8  # Higher weight for keywords in subject
                else:  # body
                    result['weight'] += 0.3  # Lower weight for keywords in body
        
        return result
    
    def _extract_urls(self, text):
        """Extract URLs from text"""
        # URL regex pattern
        url_pattern = r'https?://[\w\.-]+\.[a-zA-Z]{2,}(?:[\w\./-]*)'
        urls = re.findall(url_pattern, text)
        
        # Also look for "masked" URLs in HTML href attributes
        href_pattern = r'href=[\'"]?(https?://[^\'"">]+)'
        hrefs = re.findall(href_pattern, text)
        
        return list(set(urls + hrefs))  # Remove duplicates
    
    def _analyze_urls(self, urls):
        """Analyze URLs for suspicious patterns"""
        result = {
            'suspicious_urls': [],
            'suspicious_count': 0,
            'weight': 0
        }
        
        if not urls:
            return result
        
        for url in urls:
            suspicious = False
            reasons = []
            
            # Parse the URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Extract TLD
            ext = tldextract.extract(domain)
            tld = f".{ext.suffix}"
            
            # Check for suspicious TLDs
            if tld in self.suspicious_tlds:
                suspicious = True
                reasons.append(f"Suspicious TLD: {tld}")
            
            # Check for IP address instead of domain
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
                suspicious = True
                reasons.append("IP address used in URL")
            
            # Check for URL shorteners (simplified)
            url_shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cli.gs', 'ow.ly']
            if any(shortener in domain for shortener in url_shorteners):
                suspicious = True
                reasons.append("URL shortener detected")
            
            # Check for suspicious URL patterns (e.g., misleading domains)
            typical_brands = ['paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 'netflix']
            for brand in typical_brands:
                if brand in domain and brand not in ext.domain:
                    suspicious = True
                    reasons.append(f"Possible brand impersonation: {brand}")
            
            if suspicious:
                result['suspicious_urls'].append({
                    'url': url,
                    'reasons': reasons
                })
                result['suspicious_count'] += 1
                result['weight'] += 1.5  # Suspicious URLs are strong indicators
        
        return result
    
    def _check_attachments(self, msg):
        """Check for suspicious attachments"""
        result = {
            'suspicious': False,
            'suspicious_attachments': [],
            'weight': 0
        }
        
        if not msg.is_multipart():
            return result
        
        suspicious_extensions = [
            '.exe', '.bat', '.cmd', '.scr', '.js', '.jar', '.vbs', '.ps1', '.wsf', 
            '.msi', '.hta', '.com', '.pif', '.reg', '.msc', '.dll', '.vbe', '.jse', '.lnk'
        ]
        
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                if filename:
                    file_ext = os.path.splitext(filename.lower())[1]
                    if file_ext in suspicious_extensions:
                        result['suspicious'] = True
                        result['suspicious_attachments'].append({
                            'filename': filename,
                            'extension': file_ext
                        })
                        result['weight'] += 3.0  # Suspicious attachments are very strong indicators
        
        return result
    
    def _check_urgency(self, body):
        """Check for language indicating urgency"""
        if not body:
            return 0
        
        urgency_keywords = [
            'urgent', 'immediately', 'right now', 'as soon as possible', 'asap',
            'warning', 'alert', 'important', 'attention', 'critical', 'now',
            'expires', 'expiring', 'deadline', 'limited time', 'act now',
            '24 hours', 'tomorrow', 'suspended', 'disabled', 'verify now',
            'confirm now', 'validate now', 'login now'
        ]
        
        weight = 0
        body_lower = body.lower()
        
        for keyword in urgency_keywords:
            if keyword in body_lower:
                weight += 0.5  # Add weight for each urgency indicator found
                
        # Cap at 2.0
        return min(weight, 2.0)
    
    def _calculate_risk_level(self):
        """Calculate the final risk level based on the phishing score"""
        thresholds = self.weight_thresholds
        score = self.results['score']
        
        if score >= thresholds.get('critical', 8.0):
            self.results['risk_level'] = 'critical'
        elif score >= thresholds.get('high', 5.0):
            self.results['risk_level'] = 'high'
        elif score >= thresholds.get('medium', 3.0):
            self.results['risk_level'] = 'medium'
        elif score >= thresholds.get('low', 1.0):
            self.results['risk_level'] = 'low'
        else:
            self.results['risk_level'] = 'safe'

# Main function to run the detector
def main():
    parser = argparse.ArgumentParser(description='Email Phishing Detector')
    parser.add_argument('email_file', nargs='?', help='Path to the email file to analyze')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # If no email file is provided, check if input is being piped
    if not args.email_file and not sys.stdin.isatty():
        email_data = sys.stdin.buffer.read()
    elif args.email_file:
        try:
            with open(args.email_file, 'rb') as f:
                email_data = f.read()
        except Exception as e:
            print(f"{Fore.RED}Error reading email file: {e}{Style.RESET_ALL}")
            return 1
    else:
        parser.print_help()
        return 1
    
    # Create detector and analyze the email
    detector = PhishingDetector(config)
    results = detector.analyze_email(email_data)
    
    # Output results
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        _print_results(results, verbose=args.verbose)
    
    return 0

def _print_results(results, verbose=False):
    """Print the results in a human-readable format"""
    if 'error' in results:
        print(f"{Fore.RED}Error: {results['error']}{Style.RESET_ALL}")
        return
    
    risk_level = results['risk_level']
    score = results['score']
    
    # Color based on risk level
    if risk_level == 'critical':
        risk_color = Fore.RED + Style.BRIGHT
    elif risk_level == 'high':
        risk_color = Fore.RED
    elif risk_level == 'medium':
        risk_color = Fore.YELLOW
    elif risk_level == 'low':
        risk_color = Fore.YELLOW + Style.DIM
    else:  # safe
        risk_color = Fore.GREEN
    
    # Print summary
    print("\n" + "=" * 60)
    print(f"\n{Fore.CYAN}EMAIL PHISHING ANALYSIS RESULTS{Style.RESET_ALL}\n")
    print(f"Risk Level: {risk_color}{risk_level.upper()}{Style.RESET_ALL}")
    print(f"Phishing Score: {risk_color}{score:.2f}{Style.RESET_ALL}")
    
    if results['flags']:
        print(f"\n{Fore.CYAN}Detected Issues:{Style.RESET_ALL}")
        for flag in results['flags']:
            print(f" - {flag}")
    
    # Print suspicious URLs if any
    if results['urls'] and results.get('content_analysis', {}).get('urls', {}).get('suspicious_urls'):
        print(f"\n{Fore.CYAN}Suspicious URLs:{Style.RESET_ALL}")
        for url_info in results['content_analysis']['urls']['suspicious_urls']:
            print(f" - {url_info['url']}")
            for reason in url_info['reasons']:
                print(f"   {Fore.YELLOW}→ {reason}{Style.RESET_ALL}")
    
    # Print verbose details if requested
    if verbose:
        print(f"\n{Fore.CYAN}Detailed Analysis:{Style.RESET_ALL}")
        
        # Header analysis
        if results.get('header_analysis'):
            print(f"\n{Fore.CYAN}Header Analysis:{Style.RESET_ALL}")
            header = results['header_analysis']
            
            # Sender analysis
            if header.get('sender', {}).get('issues'):
                print(f"  {Fore.YELLOW}Sender Issues:{Style.RESET_ALL}")
                for issue in header['sender']['issues']:
                    print(f"   - {issue}")
            
            # Authentication issues
            if header.get('authentication', {}).get('issues'):
                print(f"  {Fore.YELLOW}Authentication Issues:{Style.RESET_ALL}")
                for issue in header['authentication']['issues']:
                    print(f"   - {issue}")
            
            # Subject issues
            if header.get('subject', {}).get('suspicious_keywords'):
                print(f"  {Fore.YELLOW}Subject Contains:{Style.RESET_ALL}")
                print(f"   - \"{header['subject']['text']}\"")
                print(f"   - Suspicious keywords: {', '.join(header['subject']['suspicious_keywords'])}")
            
            # Reply-To mismatch
            if header.get('reply_to_mismatch'):
                print(f"  {Fore.YELLOW}Reply-To Mismatch:{Style.RESET_ALL}")
                print(f"   - From: {header['reply_to_mismatch']['from']}")
                print(f"   - Reply-To: {header['reply_to_mismatch']['reply_to']}")
        
        # Content analysis
        if results.get('content_analysis'):
            print(f"\n{Fore.CYAN}Content Analysis:{Style.RESET_ALL}")
            content = results['content_analysis']
            
            # Suspicious text
            if content.get('text', {}).get('suspicious_keywords'):
                print(f"  {Fore.YELLOW}Suspicious Keywords in Body:{Style.RESET_ALL}")
                print(f"   - {', '.join(content['text']['suspicious_keywords'])}")
            
            # Urgency indicators
            if content.get('urgency', {}).get('detected'):
                print(f"  {Fore.YELLOW}Urgency Language Detected{Style.RESET_ALL}")
            
            # Suspicious attachments
            if content.get('attachments', {}).get('suspicious_attachments'):
                print(f"  {Fore.YELLOW}Suspicious Attachments:{Style.RESET_ALL}")
                for attachment in content['attachments']['suspicious_attachments']:
                    print(f"   - {attachment['filename']} ({attachment['extension']})")
    
    print("\n" + "=" * 60 + "\n")

if __name__ == "__main__":
    sys.exit(main())