#!/usr/bin/env python3
"""
GraphQL WAF Rules

This module defines the rules specific to GraphQL API testing, focusing on
various GraphQL-specific attack vectors and vulnerabilities.
"""

from typing import List, Dict
import sys
import os

# Add parent directory to path to allow imports from core module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.engine import WafRule

# Import vectors
from vectors.graphql import GraphQLVectors

def get_category_mappings() -> Dict[str, str]:
    """
    Get category mappings for GraphQL WAF rules.
    
    Returns:
        Dictionary mapping category keywords to rule name patterns
    """
    return {
        # GraphQL specific mappings
        "graphql": "GraphQL",
        "introspection": "Introspection",
        "jwt": "JWT",
        "nosqli": "NoSQLi",
        "sqli": "SQLi",
        "dos": "DoS",
        "ssrf": "SSRF",
        "rce": "RCE",
        "authbypass": "AuthBypass",
        "wafbypass": "WAFBypass",
        "misc": "Misc"
    }

def get_categories() -> Dict[str, str]:
    """
    Get categories for GraphQL WAF testing.
    
    Returns:
        Dictionary mapping category names to descriptions
    """
    return {
        "graphql": "GraphQL-specific attacks and vulnerabilities",
        "introspection": "GraphQL schema introspection attacks",
        "jwt": "JSON Web Token attacks in GraphQL",
        "nosqli": "NoSQL injection via GraphQL",
        "sqli": "SQL injection via GraphQL",
        "dos": "Denial of Service attacks against GraphQL",
        "ssrf": "Server-Side Request Forgery via GraphQL",
        "rce": "Remote Code Execution via GraphQL",
        "authbypass": "Authentication bypass techniques for GraphQL",
        "wafbypass": "Techniques to bypass WAF rules in GraphQL",
        "misc": "Miscellaneous GraphQL attack vectors"
    }

# Main function to get all rules - needed for the rule loading system
def get_rules() -> List[WafRule]:
    """
    Get all GraphQL WAF rules for testing.
    
    Returns:
        List of WafRule objects for testing GraphQL WAF rules
    """
    return create_graphql_rules_all()


def create_graphql_basic_rules() -> List[WafRule]:
    """
    Create test rules for basic GraphQL operations.
    
    Returns:
        List of WafRule objects for testing basic GraphQL operations
    """
    rules = []
    
    # Basic GraphQL query patterns - These should generally be allowed, but tested for baseline
    rules.append(
        WafRule(
            name="GraphQL_Basic_Query",
            description="Tests basic GraphQL query patterns",
            test_vectors=GraphQLVectors.basic(),
            request_components=["body"]
        )
    )
    
    return rules


def create_graphql_introspection_rules() -> List[WafRule]:
    """
    Create test rules for GraphQL introspection attacks.
    
    Returns:
        List of WafRule objects for testing GraphQL introspection protections
    """
    rules = []
    
    # Introspection queries - Often need to be limited in production
    rules.append(
        WafRule(
            name="GraphQL_Introspection_BODY",
            description="Blocks GraphQL introspection queries that can reveal schema details",
            test_vectors=GraphQLVectors.introspection(),
            request_components=["body"]
        )
    )
    
    return rules


def create_graphql_auth_bypass_rules() -> List[WafRule]:
    """
    Create test rules for GraphQL authentication bypass attacks.
    
    Returns:
        List of WafRule objects for testing GraphQL authentication bypass protections
    """
    rules = []
    
    # Authentication bypass attempts
    rules.append(
        WafRule(
            name="GraphQL_AuthBypass_BODY",
            description="Blocks GraphQL authentication bypass attempts in request body",
            test_vectors=GraphQLVectors.auth_bypass(),
            request_components=["body"]
        )
    )
    
    return rules


def create_graphql_injection_rules() -> List[WafRule]:
    """
    Create test rules for GraphQL injection attacks (SQL, NoSQL).
    
    Returns:
        List of WafRule objects for testing GraphQL injection protections
    """
    rules = []
    
    # SQL injection through GraphQL
    rules.append(
        WafRule(
            name="GraphQL_SQLi_BODY",
            description="Blocks SQL injection attempts through GraphQL queries",
            test_vectors=GraphQLVectors.sql_injection(),
            request_components=["body"]
        )
    )
    
    # NoSQL injection through GraphQL
    rules.append(
        WafRule(
            name="GraphQL_NoSQLi_BODY",
            description="Blocks NoSQL injection attempts through GraphQL queries",
            test_vectors=GraphQLVectors.nosql_injection(),
            request_components=["body"]
        )
    )
    
    return rules


def create_graphql_dos_rules() -> List[WafRule]:
    """
    Create test rules for GraphQL denial of service attacks.
    
    Returns:
        List of WafRule objects for testing GraphQL DoS protections
    """
    rules = []
    
    # DoS attack vectors
    rules.append(
        WafRule(
            name="GraphQL_DoS_BODY",
            description="Blocks GraphQL queries that could cause denial of service",
            test_vectors=GraphQLVectors.dos(),
            request_components=["body"]
        )
    )
    
    return rules


def create_graphql_ssrf_rules() -> List[WafRule]:
    """
    Create test rules for GraphQL SSRF attacks.
    
    Returns:
        List of WafRule objects for testing GraphQL SSRF protections
    """
    rules = []
    
    # SSRF attack vectors
    rules.append(
        WafRule(
            name="GraphQL_SSRF_BODY",
            description="Blocks server-side request forgery attempts through GraphQL",
            test_vectors=GraphQLVectors.ssrf(),
            request_components=["body"]
        )
    )
    
    return rules


def create_graphql_rce_rules() -> List[WafRule]:
    """
    Create test rules for GraphQL remote code execution attacks.
    
    Returns:
        List of WafRule objects for testing GraphQL RCE protections
    """
    rules = []
    
    # RCE attack vectors
    rules.append(
        WafRule(
            name="GraphQL_RCE_BODY",
            description="Blocks remote code execution attempts through GraphQL",
            test_vectors=GraphQLVectors.rce(),
            request_components=["body"]
        )
    )
    
    return rules


def create_graphql_waf_bypass_rules() -> List[WafRule]:
    """
    Create test rules for GraphQL WAF bypass techniques.
    
    Returns:
        List of WafRule objects for testing GraphQL WAF bypass protections
    """
    rules = []
    
    # WAF bypass techniques
    rules.append(
        WafRule(
            name="GraphQL_WAFBypass_BODY",
            description="Tests GraphQL WAF bypass techniques in request body",
            test_vectors=GraphQLVectors.waf_bypass(),
            request_components=["body"]
        )
    )
    
    # WAF bypass via headers (using same vectors but in headers)
    rules.append(
        WafRule(
            name="GraphQL_WAFBypass_HEADER",
            description="Tests GraphQL WAF bypass techniques in headers",
            test_vectors=GraphQLVectors.waf_bypass(),
            request_components=["header"]
        )
    )
    
    return rules


def create_graphql_jwt_attack_rules() -> List[WafRule]:
    """
    Create test rules for GraphQL JWT attacks.
    
    Returns:
        List of WafRule objects for testing GraphQL JWT attack protections
    """
    rules = []
    
    # JWT attack vectors
    rules.append(
        WafRule(
            name="GraphQL_JWT_BODY",
            description="Blocks JWT attacks through GraphQL operations",
            test_vectors=GraphQLVectors.jwt_attacks(),
            request_components=["body"]
        )
    )
    
    return rules


def create_graphql_misc_rules() -> List[WafRule]:
    """
    Create test rules for miscellaneous GraphQL attacks.
    
    Returns:
        List of WafRule objects for testing miscellaneous GraphQL protections
    """
    rules = []
    
    # Miscellaneous attack vectors
    rules.append(
        WafRule(
            name="GraphQL_Misc_BODY",
            description="Blocks miscellaneous GraphQL-based attacks",
            test_vectors=GraphQLVectors.misc(),
            request_components=["body"]
        )
    )
    
    return rules


def create_graphql_rules_all() -> List[WafRule]:
    """
    Create test rules for all GraphQL attack vectors.
    
    Returns:
        List of WafRule objects for testing all GraphQL rule sets
    """
    rules = []
    
    # Combine all rule sets
    rules.extend(create_graphql_basic_rules())
    rules.extend(create_graphql_introspection_rules())
    rules.extend(create_graphql_auth_bypass_rules())
    rules.extend(create_graphql_injection_rules())
    rules.extend(create_graphql_dos_rules())
    rules.extend(create_graphql_ssrf_rules())
    rules.extend(create_graphql_rce_rules())
    rules.extend(create_graphql_waf_bypass_rules())
    rules.extend(create_graphql_jwt_attack_rules())
    rules.extend(create_graphql_misc_rules())
    
    return rules


if __name__ == "__main__":
    print("GraphQL WAF Rules module loaded.")
    print(f"Basic Rules: {len(create_graphql_basic_rules())} rules")
    print(f"Introspection Rules: {len(create_graphql_introspection_rules())} rules")
    print(f"Auth Bypass Rules: {len(create_graphql_auth_bypass_rules())} rules")
    print(f"Injection Rules: {len(create_graphql_injection_rules())} rules")
    print(f"DoS Rules: {len(create_graphql_dos_rules())} rules")
    print(f"SSRF Rules: {len(create_graphql_ssrf_rules())} rules")
    print(f"RCE Rules: {len(create_graphql_rce_rules())} rules")
    print(f"WAF Bypass Rules: {len(create_graphql_waf_bypass_rules())} rules")
    print(f"JWT Attack Rules: {len(create_graphql_jwt_attack_rules())} rules")
    print(f"Miscellaneous Rules: {len(create_graphql_misc_rules())} rules")
    print(f"All Rules: {len(create_graphql_rules_all())} rules") 