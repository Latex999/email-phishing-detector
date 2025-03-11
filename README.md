# Email Phishing Detector

A powerful tool that analyzes email headers and content to detect phishing attempts by identifying suspicious patterns commonly used in phishing emails.

## Features

- Analyzes email headers for authentication issues (SPF, DKIM, DMARC)
- Scans email content for suspicious keywords and phrases
- Detects misleading or malicious URLs
- Identifies urgency language commonly used in phishing attempts
- Checks for suspicious attachments
- Provides a risk assessment score and classification
- Detailed analysis report with explanations
- Easy to use command-line interface
- Configurable detection rules

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/Latex999/email-phishing-detector.git
   cd email-phishing-detector
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

Analyze an email file:

```bash
python phishing_detector.py path/to/email.eml
```

### Advanced Options

- Output results in JSON format:
  ```bash
  python phishing_detector.py path/to/email.eml --json
  ```

- Enable verbose output with detailed analysis:
  ```bash
  python phishing_detector.py path/to/email.eml --verbose
  ```

- Analyze an email from standard input:
  ```bash
  cat path/to/email.eml | python phishing_detector.py
  ```

## Configuration

The detection rules can be customized by editing the `config.json` file.

- `suspicious_keywords`: List of keywords that are common in phishing emails
- `suspicious_tlds`: List of top-level domains frequently used in phishing campaigns
- `suspicious_senders`: Common sender patterns in phishing emails
- `weight_thresholds`: Threshold values for risk level classification

## Example Output

```
====================================================================

EMAIL PHISHING ANALYSIS RESULTS

Risk Level: HIGH
Phishing Score: 7.50

Detected Issues:
 - SPF authentication issue
 - DKIM authentication issue
 - Suspicious content
 - Suspicious URLs
 - Urgency indicators

Suspicious URLs:
 - http://securemyaccount.example-login.com/verify
   → Possible brand impersonation: example

====================================================================
```

## Example Emails

The `examples` directory contains sample emails that can be used to test the detector:

- `safe_email.eml`: A legitimate email with proper authentication
- `phishing_email.eml`: A typical phishing email with multiple suspicious indicators
- `spear_phishing.eml`: A targeted spear-phishing attempt

![image](https://github.com/user-attachments/assets/dec795d0-1a12-4daf-97d2-266647a03138)


## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
