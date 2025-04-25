# WAF Testing Framework - Usage Guide

This comprehensive guide explains how to use the WAF Testing Framework effectively, from basic usage to advanced configurations.

## Table of Contents

- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Configuration-Based Testing](#configuration-based-testing)
- [Common Use Cases](#common-use-cases)
- [Command Line Options](#command-line-options)
- [Interpreting Results](#interpreting-results)
- [Troubleshooting](#troubleshooting)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/waf-testing.git
cd waf-testing

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install required dependencies
pip install -r requirements.txt
```

## Basic Usage

The simplest way to test a website:

```bash
# Test a website against default AWS WAF rules
python -m runners.multi_waf_tester https://example.com
```

### Listing Available Rules and Categories

```bash
# List all available rule modules
python -m runners.multi_waf_tester --list-modules

# List all rule categories
python -m runners.multi_waf_tester --list-categories

# List all rules
python -m runners.multi_waf_tester --list-rules
```

## Configuration-Based Testing

For more complex testing scenarios, using YAML configuration files is recommended:

### Step 1: Create Your Configuration File

Create a YAML file (or use one of the provided templates in the `configs/` directory):

```yaml
# aws_waf_test.yaml
global:
  workers: 4
  generate_report: true
  verbose: false
  debug: false
  timeout: 30
  output_dir: "./reports/aws_waf_test"
  html_report: true
  recommendations: true

targets:
  - url: "https://example.com"
    name: "Example Website"
    waf_type: "AWS"
    
    rules:
      include: ["aws_rules"]
      categories: ["sql", "xss"]
      max_vectors: 10
    
    request:
      delay: 0.5
      timeout: 10
      headers:
        Content-Type: "application/json"
        User-Agent: "WAF-Tester/1.0"
```

### Step 2: Run the Test with Your Configuration

```bash
python -m runners.multi_waf_tester --config configs/aws_waf_test.yaml
```

### Step 3: Review Results

The tool will display results in the console and generate reports in your specified output directory.

## Common Use Cases

### Testing Only Specific Categories of Attacks

Focus on particular attack types:

```bash
# Test only XSS protection
python -m runners.multi_waf_tester https://example.com --category xss

# Test only SQL injection protection
python -m runners.multi_waf_tester https://example.com --category sql

# Test only admin panel protection
python -m runners.multi_waf_tester https://example.com --category admin
```

### Generate a Comprehensive Report

For detailed analysis and sharing with team members:

```bash
# Generate JSON and HTML reports
python -m runners.multi_waf_tester https://example.com --html-report

# Include remediation recommendations
python -m runners.multi_waf_tester https://example.com --html-report --recommendations
```

### Gentle Testing for Production Environments

When testing production systems, use these options to minimize impact:

```bash
# Increase delay between requests and reduce concurrency
python -m runners.multi_waf_tester https://example.com --delay 1.0 --workers 2

# Limit the number of test vectors per rule
python -m runners.multi_waf_tester https://example.com --max-vectors 25
```

### Testing Multiple Targets

Test multiple websites simultaneously using configuration files:

```yaml
targets:
  - url: "https://api.example.com"
    name: "API Server"
  - url: "https://app.example.com"
    name: "Web Application"
  - url: "https://admin.example.com"
    name: "Admin Portal"
```

### Testing with Authentication

For protected endpoints:

```yaml
request:
  headers:
    Authorization: "Bearer ${API_TOKEN}"
  auth:
    type: "bearer"
    token: "${API_TOKEN}"
```

You can provide environment variables through:
- System environment variables
- Command line: `--set-env API_TOKEN=your-token`

## Command Line Options

```
Usage: python -m runners.multi_waf_tester [options]

Options:
  -c, --config FILE          Load configuration from YAML file
  -t, --target URL           Target URL to test
  -u, --url URL              Alias for --target
  -m, --module MODULE        Specify rule module to use
  -r, --rules RULES          Comma-separated list of rules to test
  --category CATEGORY        Test specific category of rules
  --max-vectors N            Maximum number of test vectors per rule
  -d, --delay SECONDS        Delay between requests in seconds
  -w, --workers N            Number of parallel workers
  --timeout SECONDS          Request timeout in seconds
  -v, --verbose              Enable verbose output
  --debug                    Enable debug output
  --html-report              Generate HTML report
  --recommendations          Generate recommendations for bypasses
  --list-modules             List available rule modules
  --list-categories          List available rule categories
  --list-rules               List available rules
  --set-env KEY=VALUE        Set environment variable for configuration
  -h, --help                 Show this help message and exit
```

## Interpreting Results

After running the test, you'll see output like this:

```
==== WAF Bypass Test Summary ====
Target URL: https://example.com
Total Rules Tested: 22
Rules With Bypasses: 2
Rules With Errors: 0
Total Bypasses Found: 5

Bypasses by Component:
  querystring: 3
  body: 2

==== Rules with successful bypasses ====

CrossSiteScripting_QUERYARGUMENTS: Blocks requests with cross-site scripting patterns in query arguments

Example bypasses:
  Vector: <svg/onload=alert(1)>
  Component: querystring
  Method: GET
  Status: 200 (Base: 403)
```

### What to Look For

1. **Rules With Bypasses**: Number of WAF rules that were successfully bypassed
2. **Total Bypasses Found**: Total number of distinct bypass techniques that worked
3. **Bypasses by Component**: Which request components (body, querystring, etc.) were vulnerable
4. **Rules with successful bypasses**: Detailed information on each bypass, including:
   - The rule that was bypassed
   - The vector that succeeded in bypassing the rule
   - The request component that was used
   - The HTTP method used
   - The status codes received

### Interpreting Status Codes

- **positive_status_codes** (e.g., 200, 201): These indicate the WAF did NOT block the request, which may represent a bypass if the payload was malicious
- **negative_status_codes** (e.g., 403, 400): These indicate the WAF successfully blocked the request

## Troubleshooting

### Rate Limiting

If you encounter 429 (Too Many Requests) errors:

```bash
# Increase the delay between requests
python -m runners.multi_waf_tester https://example.com --delay 2.0
```

### Timeout Errors

If requests are timing out:

```bash
# Increase the timeout value
python -m runners.multi_waf_tester https://example.com --timeout 30
```

### Too Many Test Vectors

If testing is taking too long:

```bash
# Limit the number of test vectors per rule
python -m runners.multi_waf_tester https://example.com --max-vectors 50
```

### False Positives

If you suspect false positives:

1. Run with verbose mode to see more details:
   ```bash
   python -m runners.multi_waf_tester https://example.com -v
   ```

2. Manually verify reported bypasses with tools like curl or Postman

---

Always ensure you have proper authorization before testing any system. 