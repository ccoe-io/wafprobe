#!/usr/bin/env python3
"""
Kubernetes WAF Rules

This module defines the rules specific to Kubernetes API testing, focusing on
various Kubernetes-specific attack vectors and vulnerabilities.
"""

from typing import List, Dict
import sys
import os

# Add parent directory to path to allow imports from core module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.engine import WafRule

# Import vectors
from vectors.kubernetes import KubernetesVectors

def get_category_mappings() -> Dict[str, str]:
    """
    Get category mappings for Kubernetes WAF rules.
    
    Returns:
        Dictionary mapping category keywords to rule name patterns
    """
    return {
        # Kubernetes specific mappings
        "k8s": "K8s",
        "kubernetes": "K8s",
        "pod": "PodExec",
        "podexec": "PodExec",
        "infodisclosure": "InfoDisclosure",
        "maliciousworkload": "MaliciousWorkload",
        "commandinjection": "CommandInjection",
        "wafbypass": "WAFBypass",
        "dos": "DoS",
        "basicendpoints": "BasicEndpoints",
        "authbypass": "AuthBypass"
    }

def get_categories() -> Dict[str, str]:
    """
    Get categories for Kubernetes WAF testing.
    
    Returns:
        Dictionary mapping category names to descriptions
    """
    return {
        "k8s": "Kubernetes API attacks and vulnerabilities",
        "pod": "Pod execution and container breakout attacks",
        "infodisclosure": "Information disclosure attacks against Kubernetes",
        "maliciousworkload": "Malicious workload creation in Kubernetes",
        "commandinjection": "Command injection attacks via Kubernetes API",
        "wafbypass": "Techniques to bypass WAF rules in Kubernetes context",
        "dos": "Denial of Service attacks against Kubernetes API",
        "basicendpoints": "Basic Kubernetes API endpoint testing",
        "authbypass": "Authentication bypass techniques for Kubernetes"
    }

# Main function to get all rules - needed for the rule loading system
def get_rules() -> List[WafRule]:
    """
    Get all Kubernetes WAF rules for testing.
    
    Returns:
        List of WafRule objects for testing Kubernetes WAF rules
    """
    return create_kubernetes_rules_all()


def create_kubernetes_basic_rules() -> List[WafRule]:
    """
    Create test rules for basic Kubernetes API endpoints.
    
    Returns:
        List of WafRule objects for testing basic Kubernetes API access patterns
    """
    rules = []
    
    # Basic Kubernetes API endpoint patterns
    rules.append(
        WafRule(
            name="K8s_BasicEndpoints_URI",
            description="Tests access to basic Kubernetes API endpoints",
            test_vectors=KubernetesVectors.basic(),
            request_components=["uri"]
        )
    )
    
    return rules


def create_kubernetes_auth_bypass_rules() -> List[WafRule]:
    """
    Create test rules for Kubernetes authentication bypass attempts.
    
    Returns:
        List of WafRule objects for testing Kubernetes authentication bypass protections
    """
    rules = []
    
    # Authentication bypass attempts
    rules.append(
        WafRule(
            name="K8s_AuthBypass_HEADER",
            description="Blocks Kubernetes authentication bypass attempts in headers",
            test_vectors=KubernetesVectors.auth_bypass(),
            request_components=["header"]
        )
    )
    
    rules.append(
        WafRule(
            name="K8s_AuthBypass_URI",
            description="Blocks Kubernetes authentication bypass attempts in URI paths",
            test_vectors=KubernetesVectors.auth_bypass(),
            request_components=["uri"]
        )
    )
    
    return rules


def create_kubernetes_pod_exec_rules() -> List[WafRule]:
    """
    Create test rules for Kubernetes pod execution and container breakout attempts.
    
    Returns:
        List of WafRule objects for testing Kubernetes pod exec protections
    """
    rules = []
    
    # Pod execution and container breakout attempts
    rules.append(
        WafRule(
            name="K8s_PodExec_URI",
            description="Blocks attempts to execute commands in Kubernetes pods via URI",
            test_vectors=KubernetesVectors.pod_exec(),
            request_components=["uri"]
        )
    )
    
    rules.append(
        WafRule(
            name="K8s_PodExec_BODY",
            description="Blocks attempts to execute commands in Kubernetes pods via request body",
            test_vectors=KubernetesVectors.pod_exec(),
            request_components=["body"]
        )
    )
    
    return rules


def create_kubernetes_info_disclosure_rules() -> List[WafRule]:
    """
    Create test rules for Kubernetes information disclosure attacks.
    
    Returns:
        List of WafRule objects for testing Kubernetes information disclosure protections
    """
    rules = []
    
    # Information disclosure attacks
    rules.append(
        WafRule(
            name="K8s_InfoDisclosure_URI",
            description="Blocks attempts to access sensitive Kubernetes resources via URI",
            test_vectors=KubernetesVectors.info_disclosure(),
            request_components=["uri"]
        )
    )
    
    return rules


def create_kubernetes_malicious_workload_rules() -> List[WafRule]:
    """
    Create test rules for Kubernetes malicious workload creation.
    
    Returns:
        List of WafRule objects for testing Kubernetes malicious workload protections
    """
    rules = []
    
    # Malicious workload creation attempts
    rules.append(
        WafRule(
            name="K8s_MaliciousWorkload_BODY",
            description="Blocks attempts to create malicious Kubernetes workloads",
            test_vectors=KubernetesVectors.malicious_workloads(),
            request_components=["body"]
        )
    )
    
    return rules


def create_kubernetes_command_injection_rules() -> List[WafRule]:
    """
    Create test rules for Kubernetes command injection attacks.
    
    Returns:
        List of WafRule objects for testing Kubernetes command injection protections
    """
    rules = []
    
    # Command injection attacks
    rules.append(
        WafRule(
            name="K8s_CommandInjection_BODY",
            description="Blocks command injection attempts in Kubernetes API requests",
            test_vectors=KubernetesVectors.command_injection(),
            request_components=["body"]
        )
    )
    
    rules.append(
        WafRule(
            name="K8s_CommandInjection_URI",
            description="Blocks command injection attempts in Kubernetes URI paths",
            test_vectors=KubernetesVectors.command_injection(),
            request_components=["uri"]
        )
    )
    
    return rules


def create_kubernetes_waf_bypass_rules() -> List[WafRule]:
    """
    Create test rules for Kubernetes WAF bypass techniques.
    
    Returns:
        List of WafRule objects for testing Kubernetes WAF bypass protections
    """
    rules = []
    
    # WAF bypass techniques in various request components
    rules.append(
        WafRule(
            name="K8s_WAFBypass_HEADER",
            description="Tests Kubernetes WAF bypass techniques in headers",
            test_vectors=KubernetesVectors.waf_bypass(),
            request_components=["header"]
        )
    )
    
    rules.append(
        WafRule(
            name="K8s_WAFBypass_URI",
            description="Tests Kubernetes WAF bypass techniques in URI paths",
            test_vectors=KubernetesVectors.waf_bypass(),
            request_components=["uri"]
        )
    )
    
    rules.append(
        WafRule(
            name="K8s_WAFBypass_QUERYSTRING",
            description="Tests Kubernetes WAF bypass techniques in query strings",
            test_vectors=KubernetesVectors.waf_bypass(),
            request_components=["querystring"]
        )
    )
    
    rules.append(
        WafRule(
            name="K8s_WAFBypass_BODY",
            description="Tests Kubernetes WAF bypass techniques in request bodies",
            test_vectors=KubernetesVectors.waf_bypass(),
            request_components=["body"]
        )
    )
    
    return rules


def create_kubernetes_dos_rules() -> List[WafRule]:
    """
    Create test rules for Kubernetes denial of service attacks.
    
    Returns:
        List of WafRule objects for testing Kubernetes DoS protections
    """
    rules = []
    
    # DoS attack vectors
    rules.append(
        WafRule(
            name="K8s_DoS_URI",
            description="Blocks Kubernetes API requests that could cause DoS",
            test_vectors=KubernetesVectors.dos(),
            request_components=["uri"]
        )
    )
    
    rules.append(
        WafRule(
            name="K8s_DoS_BODY",
            description="Blocks Kubernetes API payloads that could cause DoS",
            test_vectors=KubernetesVectors.dos(),
            request_components=["body"]
        )
    )
    
    return rules


def create_kubernetes_rules_all() -> List[WafRule]:
    """
    Create test rules for all Kubernetes attack vectors.
    
    Returns:
        List of WafRule objects for testing all Kubernetes rule sets
    """
    rules = []
    
    # Combine all rule sets
    rules.extend(create_kubernetes_basic_rules())
    rules.extend(create_kubernetes_auth_bypass_rules())
    rules.extend(create_kubernetes_pod_exec_rules())
    rules.extend(create_kubernetes_info_disclosure_rules())
    rules.extend(create_kubernetes_malicious_workload_rules())
    rules.extend(create_kubernetes_command_injection_rules())
    rules.extend(create_kubernetes_waf_bypass_rules())
    rules.extend(create_kubernetes_dos_rules())
    
    return rules


if __name__ == "__main__":
    print("Kubernetes WAF Rules module loaded.")
    print(f"Basic Rules: {len(create_kubernetes_basic_rules())} rules")
    print(f"Auth Bypass Rules: {len(create_kubernetes_auth_bypass_rules())} rules")
    print(f"Pod Execution Rules: {len(create_kubernetes_pod_exec_rules())} rules")
    print(f"Information Disclosure Rules: {len(create_kubernetes_info_disclosure_rules())} rules")
    print(f"Malicious Workload Rules: {len(create_kubernetes_malicious_workload_rules())} rules")
    print(f"Command Injection Rules: {len(create_kubernetes_command_injection_rules())} rules")
    print(f"WAF Bypass Rules: {len(create_kubernetes_waf_bypass_rules())} rules")
    print(f"DoS Rules: {len(create_kubernetes_dos_rules())} rules")
    print(f"All Rules: {len(create_kubernetes_rules_all())} rules") 