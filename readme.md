# WAF Testing Framework

<div align="center">
  <img src="https://img.shields.io/badge/Security-WAF%20Testing-D93B4B?style=for-the-badge&logo=shieldsdotio&logoColor=white" alt="WAF Testing"/>
  <br/>
  <img src="https://img.shields.io/badge/AWS-WAF-FF9900?style=flat-square&logo=amazonaws&logoColor=white" alt="AWS WAF"/>
  <img src="https://img.shields.io/badge/GraphQL-API-E10098?style=flat-square&logo=graphql&logoColor=white" alt="GraphQL"/>
  <img src="https://img.shields.io/badge/Kubernetes-Security-326CE5?style=flat-square&logo=kubernetes&logoColor=white" alt="Kubernetes"/>
  <img src="https://img.shields.io/badge/NoSQL-Testing-47A248?style=flat-square&logo=mongodb&logoColor=white" alt="NoSQL"/>
  <img src="https://img.shields.io/badge/Language-Python-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python"/>
  <br/>
  <p><strong>Comprehensive WAF Testing Framework for Multiple Technologies</strong></p>
</div>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#features">Features</a> •
  <a href="#supported-technologies">Supported Technologies</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#documentation">Documentation</a>
</p>

## Overview

This tool helps you test if your web applications and APIs are properly protected against various attack vectors. It attempts to bypass your WAF (Web Application Firewall) using technology-specific attack vectors and reports any vulnerabilities.

## Features

<table>
  <tr>
    <td width="50%">
      <h3>🛡️ Comprehensive Testing</h3>
      <p>Tests multiple categories of attacks with hundreds of attack vectors across different technologies</p>
    </td>
    <td width="50%">
      <h3>📊 Detailed Reports</h3>
      <p>Generates JSON and HTML reports showing which attacks were blocked and which bypassed your WAF</p>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>🔧 Easy Configuration</h3>
      <p>Simple YAML configuration files or command-line arguments to customize testing</p>
    </td>
    <td width="50%">
      <h3>🔌 Integration-Ready</h3>
      <p>Easily integrate with CI/CD pipelines for automated security testing</p>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>🧩 Modular Design</h3>
      <p>Easily extend with new attack vectors, rules, and technology modules</p>
    </td>
    <td width="50%">
      <h3>🚀 Beginner-Friendly</h3>
      <p>Simple CLI interface with easy-to-understand documentation</p>
    </td>
  </tr>
</table>

## Supported Technologies

The framework currently supports WAF testing for the following technologies:

| Technology | Description | Example Vectors |
|------------|-------------|-----------------|
| **AWS WAF** | Testing for AWS WAF rules and protections | SQL injection, XSS, LFI, RFI, SSRF, etc. |
| **GraphQL** | Testing GraphQL API security | Introspection, injection, DoS, authentication bypass |
| **Kubernetes** | Testing Kubernetes API security | Pod execution, privilege escalation, info disclosure |
| **NoSQL Databases** | Testing document database security | NoSQL injection, auth bypass, operator abuse |

## Installation

```bash
# Clone the repository
git clone https://github.com/your-username/waf-testing.git
cd waf-testing

# Set up a virtual environment (recommended)
python -m venv waf-test-env
source waf-test-env/bin/activate  # On Windows: waf-test-env\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

```bash
# List available rule modules
python -m runners.multi_waf_tester --list-modules

# List available rule categories
python -m runners.multi_waf_tester --list-categories

# Run a test using a configuration file
python -m runners.multi_waf_tester --config configs/aws_waf_example.yaml
```

## Documentation

For more detailed information, check these guides:

- [USAGE.md](USAGE.md) - Comprehensive guide to using the tool
- [CONFIGURATION.md](CONFIGURATION.md) - Complete configuration reference
- [CONTRIBUTING.md](CONTRIBUTING.md) - Guide for contributors

## Who Should Use This Tool?

- **Security Professionals** testing WAF configurations
- **DevOps Engineers** integrating security into CI/CD pipelines
- **API Developers** securing their endpoints
- **Penetration Testers** evaluating application security
- **Security Researchers** studying attack techniques

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">
  <p>If you find this tool helpful, please consider giving it a ⭐️!</p>
  <p>Made with ❤️ by security researchers, for security researchers</p>
</div>