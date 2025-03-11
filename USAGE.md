# Email Phishing Detector - Usage Guide

This guide provides detailed instructions for using the Email Phishing Detector tool.

## Setup

1. Clone the repository and install dependencies:
   ```bash
   git clone https://github.com/Latex999/email-phishing-detector.git
   cd email-phishing-detector
   pip install -r requirements.txt
   ```

2. Ensure the script is executable (Unix/Linux/macOS):
   ```bash
   chmod +x phishing_detector.py
   ```

## Basic Usage

### Analyzing a Single Email File

```bash
python phishing_detector.py path/to/email.eml
```

Example:
```bash
python phishing_detector.py examples/phishing_email.eml
```

This will analyze the email and display a summary of the results, including:
- Risk level (Safe, Low, Medium, High, Critical)
- Phishing score
- Detected issues
- Suspicious URLs (if any)

### Output Formats

#### Default Output (Human-Readable)

The default output is formatted for human readability with color coding:
- Green: Safe
- Yellow: Low/Medium Risk
- Red: High/Critical Risk

#### JSON Output

For programmatic use or integration with other tools, you can get JSON output:

```bash
python phishing_detector.py examples/phishing_email.eml --json
```

This will output the full analysis results in JSON format, which can be piped to other tools or saved to a file:

```bash
python phishing_detector.py examples/phishing_email.eml --json > results.json
```

### Verbose Output

For detailed analysis information, use the verbose flag:

```bash
python phishing_detector.py examples/phishing_email.eml --verbose
```

This will show:
- Full header analysis
- Details about suspicious content
- Authentication issues
- And more

### Analyzing Emails from Standard Input

You can pipe email content directly to the tool:

```bash
cat examples/phishing_email.eml | python phishing_detector.py
```

Or:

```bash
python some_email_fetcher.py | python phishing_detector.py
```

## Batch Processing

You can process multiple emails using shell scripting:

### Bash Example:

```bash
#!/bin/bash
for email in emails/*.eml; do
  echo "Analyzing $email..."
  python phishing_detector.py "$email"
  echo "-----------------------------------"
done
```

## Customizing the Tool

### Configuration

The detection rules can be customized by editing `config.json`:

- `suspicious_keywords`: Keywords commonly found in phishing emails
- `suspicious_tlds`: Top-level domains frequently used in phishing campaigns
- `suspicious_senders`: Sender patterns common in phishing emails
- `weight_thresholds`: Threshold values for risk classification

### Adding Custom Rules

To add custom rules:

1. Edit `config.json` to add new patterns or keywords
2. Restart the tool for changes to take effect

## Example Usage Scenarios

### 1. Basic Check

```bash
python phishing_detector.py examples/safe_email.eml
```

### 2. Detailed Analysis with Verbose Output

```bash
python phishing_detector.py examples/phishing_email.eml --verbose
```

### 3. Processing Multiple Emails with JSON Output

```bash
for email in examples/*.eml; do
  echo "Processing $email:"
  python phishing_detector.py "$email" --json
  echo "-----------------------------------"
done
```

## Troubleshooting

If you encounter any issues:

1. Ensure you have all required dependencies installed
2. Check the log file (`phishing_detector.log`) for error messages
3. For encoding issues, ensure your email files use standard encodings

## Integration Ideas

The tool can be integrated with:

- Email clients and servers to automatically scan incoming messages
- Security monitoring systems
- SOC workflows
- Custom alerting systems