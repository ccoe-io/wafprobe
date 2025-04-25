# WAF Testing Framework - Configuration Reference

This document provides a comprehensive reference for all configuration options available in the WAF Testing Framework.

## Table of Contents

- [Configuration File Structure](#configuration-file-structure)
- [Global Settings](#global-settings)
- [Target Configuration](#target-configuration)
  - [Basic Properties](#target-basic-properties)
  - [Rules Configuration](#target-rules-configuration)
  - [Request Parameters](#request-parameters)
  - [Detection Configuration](#detection-configuration)
- [Size Limits Configuration](#size-limits-configuration)
- [Environment Variables](#using-environment-variables)
- [Complete Example](#complete-example)
- [Available Rule Modules](#available-rule-modules)

## Configuration File Structure

The YAML configuration file has the following main sections:

```yaml
global:         # Global settings for the testing tool
targets:        # List of target APIs to test
size_limits:    # Size limits for request components
```

## Global Settings

Global settings control the overall behavior of the testing tool:

```yaml
global:
  workers: 4               # Number of parallel workers to use for testing
  generate_report: true    # Whether to generate a report
  verbose: false           # Verbose output (detailed logs)
  debug: false             # Debug output (very detailed logs)
  timeout: 30              # Global timeout in seconds
  output_dir: "reports"    # Directory to store reports
  html_report: true        # Generate HTML report
  recommendations: true    # Generate recommendations for bypasses
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `workers` | Integer | 4 | Number of parallel workers for concurrent testing |
| `generate_report` | Boolean | true | Controls whether reports are generated |
| `verbose` | Boolean | false | Enables verbose logging output |
| `debug` | Boolean | false | Enables debug-level logging (more detailed than verbose) |
| `timeout` | Integer | 30 | Global timeout in seconds for all operations |
| `output_dir` | String | "./reports" | Directory where reports will be stored |
| `html_report` | Boolean | false | Whether to generate an HTML report |
| `recommendations` | Boolean | false | Whether to generate remediation recommendations |

## Target Configuration

Each target represents an API endpoint to test. Multiple targets can be specified:

```yaml
targets:
  - url: "https://example-api.example.com/api/v1"
    name: "Example API"
    description: "Example REST API endpoint"
    waf_type: "AWS"        # Type of WAF (AWS, Azure, etc.)
    
    rules:                 # Rules configuration for this target
      # Rules configuration (see below)
    
    request:               # Request parameters
      # Request parameters (see below)
    
    detection:             # Response detection configuration
      # Detection configuration (see below)
```

### Target Basic Properties

Basic properties that identify the target:

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `url` | String | Yes | The URL of the API endpoint to test |
| `name` | String | No | A friendly name for the target (defaults to URL if not provided) |
| `description` | String | No | A description of the target |
| `waf_type` | String | No | Type of WAF protecting the target (e.g., "AWS", "Azure", "Cloudflare") |

### Target Rules Configuration

Configure which rules and attack vectors to test:

```yaml
rules:
  include:
    - "aws_rules"        # Use AWS rules module for this target
  categories:
    - "sql"              # Target SQL injection rules
    - "xss"              # Target XSS rules
  rule_names: []         # Include specific rules by name
  max_vectors: 0         # 0 means use all vectors
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `include` | List | [] | List of rule modules to include (e.g., "aws_rules", "graphql_rules") |
| `categories` | List | [] | List of rule categories to include (e.g., "sql", "xss", "admin") |
| `rule_names` | List | [] | List of specific rule names to include |
| `max_vectors` | Integer | 0 | Maximum number of test vectors per rule (0 means all) |

### Request Parameters

Configure how requests are sent to the target:

```yaml
request:
  delay: 0.5             # Delay between requests in seconds
  timeout: 10            # Request timeout in seconds
  headers:
    Content-Type: "application/json"
    Accept: "application/json"
    User-Agent: "WAF-Tester/1.0"
  cookies: {}
  auth:
    type: "basic"        # Type of authentication (basic, bearer, etc.)
    username: "tester"   # Username for basic auth
    password: "password" # Password for basic auth
  
  # Query parameter format for different test injection points
  query_format:
    normal: "query={}"   # Format for normal query parameter
    json: "json={}"      # Format for JSON query parameter
  
  # Body format for different test injection points
  body_format:
    normal: "{{ \"query\": \"{}\" }}"      # String in JSON
    raw: "{}"                              # Raw payload
    json_value: "{{ \"filter\": {} }}"     # JSON value in JSON
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `delay` | Float | 0.5 | Delay between requests in seconds |
| `timeout` | Integer | 10 | Request timeout in seconds |
| `headers` | Object | {} | Custom HTTP headers to include in requests |
| `cookies` | Object | {} | Custom cookies to include in requests |
| `auth.type` | String | null | Authentication type ("basic", "bearer") |
| `auth.username` | String | null | Username for basic authentication |
| `auth.password` | String | null | Password for basic authentication |
| `auth.token` | String | null | Token for bearer authentication |

#### Format Strings

The `query_format` and `body_format` sections define how payload vectors are formatted in requests:

| Option | Description |
|--------|-------------|
| `query_format.normal` | Format for embedding vectors in query parameters (e.g., "query={}") |
| `query_format.json` | Format for embedding JSON vectors in query parameters (e.g., "json={}") |
| `body_format.normal` | Format for embedding vectors in request body as strings |
| `body_format.raw` | Format for embedding raw vectors in request body |
| `body_format.json_value` | Format for embedding JSON vectors in request body |

**Note**: In the format strings, the `{}` placeholder is replaced with the attack vector.

### Detection Configuration

Configure how to detect if a WAF is blocking attacks:

```yaml
detection:
  positive_status_codes: [200, 201, 202, 204]  # Success status codes
  negative_status_codes: [400, 403, 422]       # Blocked status codes
  block_patterns:                              # Patterns indicating blocking
    - "Access denied"
    - "Request blocked"
    - "Invalid request"
  bypass_patterns:                             # Patterns indicating bypass
    - "\"data\":"
    - "\"items\":"
    - "\"results\":"
```

| Option | Type | Description |
|--------|------|-------------|
| `positive_status_codes` | List | HTTP status codes indicating a successful request (potential WAF bypass) |
| `negative_status_codes` | List | HTTP status codes indicating a blocked request (WAF working correctly) |
| `block_patterns` | List | Response body patterns indicating a blocked request |
| `bypass_patterns` | List | Response body patterns indicating a successful bypass |

## Size Limits Configuration

Configure maximum sizes for various request components:

```yaml
size_limits:
  body: 1048576      # 1MB
  query: 2048        # 2KB
  cookie: 4096       # 4KB
  uri: 4096          # 4KB
  header: 8192       # 8KB
  size_multiplier: 2 # Multiplier for size testing
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `body` | Integer | 1048576 | Maximum size in bytes for request body |
| `query` | Integer | 2048 | Maximum size in bytes for query string |
| `cookie` | Integer | 4096 | Maximum size in bytes for cookies |
| `uri` | Integer | 4096 | Maximum size in bytes for URI |
| `header` | Integer | 8192 | Maximum size in bytes for headers |
| `size_multiplier` | Integer | 2 | Multiplier for size limit testing |

## Using Environment Variables

You can use environment variables in your configuration with the `${VAR_NAME}` syntax:

```yaml
request:
  headers:
    Authorization: "Bearer ${API_TOKEN}"
  auth:
    username: "${USERNAME}"
    password: "${PASSWORD}"
```

These will be replaced with the corresponding environment variable values at runtime.

### Setting Environment Variables

There are multiple ways to set environment variables for use in your configuration:

1. **System environment variables**:
   ```bash
   # Linux/macOS
   export API_TOKEN="your-secret-token"
   
   # Windows
   set API_TOKEN=your-secret-token
   ```

2. **Command line arguments**:
   ```bash
   python -m runners.multi_waf_tester --config waf_config.yaml --set-env API_TOKEN=your-secret-token
   ```

## Complete Example

Here's a complete configuration example:

```yaml
global:
  workers: 4
  generate_report: true
  verbose: false
  debug: false
  timeout: 30
  output_dir: "reports"
  html_report: true
  recommendations: true

targets:
  - url: "https://api.example.com/api"
    name: "Production API"
    description: "Main production REST API"
    waf_type: "AWS"
    
    rules:
      include:
        - "aws_rules"
      categories:
        - "sql"
        - "xss"
      max_vectors: 10
    
    request:
      delay: 1.0
      timeout: 15
      headers:
        Content-Type: "application/json"
        Authorization: "Bearer ${AUTH_TOKEN}"
      body_format:
        normal: "{{ \"query\": \"{}\" }}"
    
    detection:
      positive_status_codes: [200]
      negative_status_codes: [400, 403, 422]
      block_patterns:
        - "Access denied"
      bypass_patterns:
        - "\"data\":"

size_limits:
  body: 1048576
  query: 2048
```

## Available Rule Modules

The testing framework includes several rule modules for different types of applications:

| Module | Description |
|--------|-------------|
| `aws_rules` | Rules for AWS WAF and common web vulnerabilities |
| `graphql_rules` | GraphQL-specific vulnerabilities and attack vectors |
| `kubernetes_rules` | Kubernetes API server vulnerabilities |
| `documentdb_rules` | DocumentDB/MongoDB-specific vulnerabilities |

You can use the command-line tool to list all available rule modules:

```bash
python -m runners.multi_waf_tester --list-modules
```

## Available Categories

Common categories include:

- `sql` - SQL injection attacks
- `xss` - Cross-site scripting attacks
- `admin` - Admin interface protection
- `nosql` - NoSQL injection attacks
- `size` - Size restriction tests
- `path` - Path traversal attacks

To see all available categories:

```bash
python -m runners.multi_waf_tester --list-categories
```

---

*Always ensure you have proper authorization before testing any system.* 