#!/usr/bin/env python3
"""
DocumentDB/MongoDB WAF Rules

This module defines the rules specific to DocumentDB and MongoDB testing, focusing on
various NoSQL injection and MongoDB-specific attack vectors and vulnerabilities.
"""

from typing import List, Dict
import sys
import os

# Add parent directory to path to allow imports from core module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.engine import WafRule

# Import vectors
from vectors.documentdb import DocumentDBVectors

def get_category_mappings() -> Dict[str, str]:
    """
    Get category mappings for DocumentDB/MongoDB rules.
    
    Returns:
        Dictionary mapping category keywords to rule name patterns
    """
    return {
        # DocumentDB/MongoDB specific mappings
        "nosql": "DocumentDB",
        "mongodb": "DocumentDB",
        "documentdb": "DocumentDB",
        "auth_bypass": "AuthBypass",
        "basic": "Basic",
        "extraction": "Extraction",
        "js": "JSInjection",
        "javascript": "JSInjection",
        "operators": "OperatorAbuse",
        "operator_abuse": "OperatorAbuse",
        "command": "CommandInjection",
        "bypass": "WAFBypass",
        "waf_bypass": "WAFBypass"
    }

def get_categories() -> Dict[str, str]:
    """
    Get categories for DocumentDB/MongoDB testing.
    
    Returns:
        Dictionary mapping category names to descriptions
    """
    return {
        "nosql": "NoSQL database attacks including MongoDB and DocumentDB",
        "mongodb": "MongoDB-specific attacks and vulnerabilities",
        "documentdb": "Amazon DocumentDB-specific attacks and vulnerabilities",
        "auth_bypass": "Authentication bypass techniques for NoSQL databases",
        "basic": "Basic NoSQL injection patterns",
        "extraction": "Data extraction and exfiltration techniques",
        "js": "JavaScript injection in MongoDB queries",
        "operators": "MongoDB operator abuse techniques",
        "command": "MongoDB command injection attacks",
        "bypass": "WAF bypass techniques for NoSQL databases"
    }

# Main function to get all rules - needed for the rule loading system
def get_rules() -> List[WafRule]:
    """
    Get all DocumentDB/MongoDB WAF rules for testing.
    
    Returns:
        List of WafRule objects for testing DocumentDB/MongoDB WAF rules
    """
    return create_documentdb_rules_all()


def create_documentdb_basic_rules() -> List[WafRule]:
    """
    Create test rules for basic DocumentDB/MongoDB injection patterns.
    
    Returns:
        List of WafRule objects for testing basic DocumentDB/MongoDB injection patterns
    """
    rules = []
    
    # Basic NoSQL injection patterns
    rules.append(
        WafRule(
            name="DocumentDB_Basic_QUERYSTRING",
            description="Blocks basic MongoDB/NoSQL injection patterns in query strings",
            test_vectors=DocumentDBVectors.basic(),
            request_components=["querystring"]
        )
    )
    
    rules.append(
        WafRule(
            name="DocumentDB_Basic_BODY",
            description="Blocks basic MongoDB/NoSQL injection patterns in request body",
            test_vectors=DocumentDBVectors.basic(),
            request_components=["body"]
        )
    )
    
    return rules


def create_documentdb_auth_bypass_rules() -> List[WafRule]:
    """
    Create test rules for DocumentDB/MongoDB authentication bypass attacks.
    
    Returns:
        List of WafRule objects for testing DocumentDB/MongoDB authentication bypass protections
    """
    rules = []
    
    # Authentication bypass attempts
    rules.append(
        WafRule(
            name="DocumentDB_AuthBypass_QUERYSTRING",
            description="Blocks MongoDB authentication bypass attempts in query strings",
            test_vectors=DocumentDBVectors.auth_bypass(),
            request_components=["querystring"]
        )
    )
    
    rules.append(
        WafRule(
            name="DocumentDB_AuthBypass_BODY",
            description="Blocks MongoDB authentication bypass attempts in request body",
            test_vectors=DocumentDBVectors.auth_bypass(),
            request_components=["body"]
        )
    )
    
    return rules


def create_documentdb_extraction_rules() -> List[WafRule]:
    """
    Create test rules for DocumentDB/MongoDB data extraction attacks.
    
    Returns:
        List of WafRule objects for testing DocumentDB/MongoDB data extraction protections
    """
    rules = []
    
    # Data extraction attacks
    rules.append(
        WafRule(
            name="DocumentDB_Extraction_QUERYSTRING",
            description="Blocks MongoDB data extraction attempts in query strings",
            test_vectors=DocumentDBVectors.extraction(),
            request_components=["querystring"]
        )
    )
    
    rules.append(
        WafRule(
            name="DocumentDB_Extraction_BODY",
            description="Blocks MongoDB data extraction attempts in request body",
            test_vectors=DocumentDBVectors.extraction(),
            request_components=["body"]
        )
    )
    
    return rules


def create_documentdb_js_injection_rules() -> List[WafRule]:
    """
    Create test rules for DocumentDB/MongoDB JavaScript injection attacks.
    
    Returns:
        List of WafRule objects for testing DocumentDB/MongoDB JavaScript injection protections
    """
    rules = []
    
    # JavaScript injection attacks
    rules.append(
        WafRule(
            name="DocumentDB_JSInjection_QUERYSTRING",
            description="Blocks MongoDB JavaScript injection attempts in query strings",
            test_vectors=DocumentDBVectors.js_injection(),
            request_components=["querystring"]
        )
    )
    
    rules.append(
        WafRule(
            name="DocumentDB_JSInjection_BODY",
            description="Blocks MongoDB JavaScript injection attempts in request body",
            test_vectors=DocumentDBVectors.js_injection(),
            request_components=["body"]
        )
    )
    
    return rules


def create_documentdb_operator_abuse_rules() -> List[WafRule]:
    """
    Create test rules for DocumentDB/MongoDB operator abuse attacks.
    
    Returns:
        List of WafRule objects for testing DocumentDB/MongoDB operator abuse protections
    """
    rules = []
    
    # MongoDB operator abuse attacks
    rules.append(
        WafRule(
            name="DocumentDB_OperatorAbuse_QUERYSTRING",
            description="Blocks MongoDB operator abuse attempts in query strings",
            test_vectors=DocumentDBVectors.operator_abuse(),
            request_components=["querystring"]
        )
    )
    
    rules.append(
        WafRule(
            name="DocumentDB_OperatorAbuse_BODY",
            description="Blocks MongoDB operator abuse attempts in request body",
            test_vectors=DocumentDBVectors.operator_abuse(),
            request_components=["body"]
        )
    )
    
    return rules


def create_documentdb_command_injection_rules() -> List[WafRule]:
    """
    Create test rules for DocumentDB/MongoDB command injection attacks.
    
    Returns:
        List of WafRule objects for testing DocumentDB/MongoDB command injection protections
    """
    rules = []
    
    # MongoDB command injection attacks
    rules.append(
        WafRule(
            name="DocumentDB_CommandInjection_QUERYSTRING",
            description="Blocks MongoDB command injection attempts in query strings",
            test_vectors=DocumentDBVectors.command_injection(),
            request_components=["querystring"]
        )
    )
    
    rules.append(
        WafRule(
            name="DocumentDB_CommandInjection_BODY",
            description="Blocks MongoDB command injection attempts in request body",
            test_vectors=DocumentDBVectors.command_injection(),
            request_components=["body"]
        )
    )
    
    return rules


def create_documentdb_waf_bypass_rules() -> List[WafRule]:
    """
    Create test rules for DocumentDB/MongoDB WAF bypass techniques.
    
    Returns:
        List of WafRule objects for testing DocumentDB/MongoDB WAF bypass protections
    """
    rules = []
    
    # WAF bypass techniques
    rules.append(
        WafRule(
            name="DocumentDB_WAFBypass_QUERYSTRING",
            description="Tests MongoDB WAF bypass techniques in query strings",
            test_vectors=DocumentDBVectors.waf_bypass(),
            request_components=["querystring"]
        )
    )
    
    rules.append(
        WafRule(
            name="DocumentDB_WAFBypass_BODY",
            description="Tests MongoDB WAF bypass techniques in request body",
            test_vectors=DocumentDBVectors.waf_bypass(),
            request_components=["body"]
        )
    )
    
    rules.append(
        WafRule(
            name="DocumentDB_WAFBypass_HEADER",
            description="Tests MongoDB WAF bypass techniques in headers",
            test_vectors=DocumentDBVectors.waf_bypass(),
            request_components=["header"]
        )
    )
    
    return rules


def create_documentdb_rules_all() -> List[WafRule]:
    """
    Create test rules for all DocumentDB/MongoDB attack vectors.
    
    Returns:
        List of WafRule objects for testing all DocumentDB/MongoDB rule sets
    """
    rules = []
    
    # Combine all rule sets
    rules.extend(create_documentdb_basic_rules())
    rules.extend(create_documentdb_auth_bypass_rules())
    rules.extend(create_documentdb_extraction_rules())
    rules.extend(create_documentdb_js_injection_rules())
    rules.extend(create_documentdb_operator_abuse_rules())
    rules.extend(create_documentdb_command_injection_rules())
    rules.extend(create_documentdb_waf_bypass_rules())
    
    return rules


if __name__ == "__main__":
    print("DocumentDB/MongoDB WAF Rules module loaded.")
    print(f"Basic Rules: {len(create_documentdb_basic_rules())} rules")
    print(f"Auth Bypass Rules: {len(create_documentdb_auth_bypass_rules())} rules")
    print(f"Data Extraction Rules: {len(create_documentdb_extraction_rules())} rules")
    print(f"JavaScript Injection Rules: {len(create_documentdb_js_injection_rules())} rules")
    print(f"Operator Abuse Rules: {len(create_documentdb_operator_abuse_rules())} rules")
    print(f"Command Injection Rules: {len(create_documentdb_command_injection_rules())} rules")
    print(f"WAF Bypass Rules: {len(create_documentdb_waf_bypass_rules())} rules")
    print(f"All Rules: {len(create_documentdb_rules_all())} rules") 