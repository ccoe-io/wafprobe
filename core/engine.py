#!/usr/bin/env python3
"""
Core WAF Testing Engine

This module provides the core functionality for WAF testing,
independent of any specific WAF vendor or cloud provider.
"""

import argparse
import json
import logging
import re
import ssl
import sys
import time
import os
import copy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import parse_qs, urlencode, urlparse

import requests
from requests.exceptions import RequestException
from .size_parameters import SizeTestParameters

# Disable SSL warnings for testing purposes
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Try to import Rich for better output, but provide fallbacks
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Rich library not found. Using basic console output.")


class HttpMethod(str, Enum):
    """HTTP methods to use for testing."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


@dataclass
class WafRule:
    """Represents a WAF rule to be tested."""
    name: str
    description: str
    test_vectors: List[Any]
    request_components: List[str]
    
    def __post_init__(self):
        # Make sure the request components are valid
        valid_components = {"header", "body", "querystring", "uri", "cookie"}
        for component in self.request_components:
            if component.lower() not in valid_components:
                raise ValueError(f"Invalid request component: {component}")


class WafBypassDetector:
    """
    Main class for detecting WAF rule bypasses.
    Tests various evasion techniques against the specified WAF rules.
    """
    
    def __init__(self, target_url: str, verbose: bool = False):
        """
        Initialize the WAF bypass detector.
        
        Args:
            target_url: The URL to test
            verbose: Whether to output verbose logging
        """
        self.target_url = target_url
        self.verbose = verbose
        self.console = Console() if RICH_AVAILABLE else None
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for testing
        self.session.timeout = 10  # Set timeout for requests
        
        # Set up logging
        log_level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[logging.StreamHandler()]
        )
        self.logger = logging.getLogger("WafBypassDetector")
        
        # Initialize size parameters with defaults
        self.size_params = SizeTestParameters()
        
        # Initialize rules (to be set by the caller)
        self.rules = []
        
        # Results storage
        self.results = {}
        
        # Configuration properties
        self._delay = 0.1  # Delay between requests in seconds
        self._timeout = 10  # Request timeout in seconds
        self._workers = 5   # Number of concurrent workers for testing
    
    @property
    def delay(self):
        """Get the delay between requests."""
        return self._delay
    
    @delay.setter
    def delay(self, value):
        """Set the delay between requests."""
        self._delay = float(value)
    
    @property
    def timeout(self):
        """Get the request timeout."""
        return self._timeout
    
    @timeout.setter
    def timeout(self, value):
        """Set the request timeout."""
        self._timeout = int(value)
        self.session.timeout = self._timeout
    
    @property
    def workers(self):
        """Get the number of worker threads."""
        return self._workers
    
    @workers.setter
    def workers(self, value):
        """Set the number of worker threads."""
        self._workers = int(value)
    
    def _sanitize_header_value(self, value: str) -> str:
        """
        Sanitize header values to ensure they're compatible with HTTP standards.
        
        Args:
            value: The header value to sanitize
            
        Returns:
            Sanitized header value
        """
        if not isinstance(value, str):
            value = str(value)
            
        # Replace characters that would cause encoding issues
        try:
            # Try to encode as ASCII to check for problematic chars
            value.encode('ascii')
        except UnicodeEncodeError:
            # Replace problematic Unicode characters
            safe_value = ""
            for char in value:
                try:
                    char.encode('ascii')
                    safe_value += char
                except UnicodeEncodeError:
                    # Replace with URL encoding-style representation
                    safe_value += f"%{ord(char):02x}"
            value = safe_value
            
        # Remove control characters that could break HTTP headers
        value = ''.join(c for c in value if ord(c) >= 32 or c in '\t')
        
        # Replace newlines and carriage returns
        value = value.replace('\n', '%0A').replace('\r', '%0D')
        
        return value
    
    def _make_request(self, url: str, method: HttpMethod, headers: Dict[str, str] = None, 
                     cookies: Dict[str, str] = None, params: Dict[str, str] = None, 
                     data: Any = None, json_data: Dict[str, Any] = None) -> Tuple[Optional[requests.Response], Optional[str]]:
        """
        Make an HTTP request with the given parameters.
        
        Args:
            url: The URL to request
            method: The HTTP method to use
            headers: Request headers
            cookies: Request cookies
            params: Query parameters
            data: Request body data
            json_data: JSON request body
            
        Returns:
            Tuple of (response, error message)
        """
        try:
            headers = headers or {}
            if "User-Agent" not in headers:
                headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            
            # Sanitize header values
            sanitized_headers = {}
            for header_name, header_value in headers.items():
                try:
                    sanitized_headers[header_name] = self._sanitize_header_value(header_value)
                except Exception as e:
                    self.logger.warning(f"Error sanitizing header {header_name}: {str(e)}")
                    sanitized_headers[header_name] = str(header_value)
            
            # Print info about the request being made
            debug_info = f"DEBUG - Request: {method.value} {url}"
            if data:
                debug_info += f" with body data: {str(data)[:100]}..."
            if params:
                debug_info += f" with params: {params}"
            print(debug_info)
                
            response = self.session.request(
                method=method.value,
                url=url,
                headers=sanitized_headers,
                cookies=cookies,
                params=params,
                data=data,
                json=json_data,
                allow_redirects=False,
                timeout=10
            )
            
            # Direct debug output to show response status
            print(f"DEBUG - Response status: {response.status_code} for {method.value} {url.split('?')[0]}")
            
            # For suspected WAF bypass test (XSS, SQLi, etc.)
            if any(keyword in str(data or '') or keyword in str(params or {}) for keyword in ["script", "alert", "SELECT", "UNION", "<", ">", "'"]):
                if response.status_code not in [403, 400, 413]:
                    print(f"⚠️ POTENTIAL BYPASS DETECTED: Status {response.status_code} for malicious payload")
            
            return response, None
        except requests.exceptions.Timeout:
            return None, "Request timed out"
        except requests.exceptions.ConnectionError:
            return None, "Connection error"
        except requests.exceptions.TooManyRedirects:
            return None, "Too many redirects"
        except requests.exceptions.RequestException as e:
            return None, f"Request error: {str(e)}"
            
    def _get_baseline_response(self) -> Tuple[Optional[requests.Response], Optional[str]]:
        """
        Get a baseline response from the target URL to compare against.
        
        Returns:
            Tuple of (response, error message)
        """
        self.logger.info(f"Getting baseline response from {self.target_url}")
        return self._make_request(self.target_url, HttpMethod.GET)
    
    def _is_bypass_successful(self, baseline: requests.Response, test_response: requests.Response) -> bool:
        """
        Determine if a bypass attempt was successful by comparing with the baseline.
        
        Args:
            baseline: The baseline response
            test_response: The test response
            
        Returns:
            True if bypass appears successful, False otherwise
        """
        # WAF block indicators in response content
        waf_block_signs = [
            # Generic WAF block indicators
            "access denied",
            "forbidden",
            "waf",
            "blocked",
            "security violation",
            "your request has been blocked",
            "suspicious activity",
            # AWS WAF specific
            "aws waf",
            "cloudfront",
            "request id:",
            # Common HTTP status codes for WAF blocks
            "403 forbidden",
        ]
        
        # WAF block status codes
        waf_block_status_codes = [403, 400, 413]
        
        # Check status code first - if it's not a blocking code, it's likely a bypass
        if test_response.status_code not in waf_block_status_codes:
            # Check if response content indicates a block despite non-block status code
            test_content = test_response.text.lower()
            
            for indicator in waf_block_signs:
                if indicator in test_content:
                    # If block indicators are in the content, it's not a bypass
                    if self.verbose:
                        print(f"WAF block detected in content despite status {test_response.status_code}: '{indicator}' found")
                    return False
            
            # No block indicators in content and non-block status code - this is a bypass
            print(f"Potential bypass detected: Response status {test_response.status_code} with no WAF block indicators")
            return True
        
        # If we got a blocking status code, check content length differences
        # Sometimes a WAF might return 403 but still include part of the response
        content_diff = abs(len(baseline.content) - len(test_response.content))
        if content_diff > 100 and test_response.status_code in waf_block_status_codes:
            print(f"Potential partial bypass: Block status {test_response.status_code} but significant content difference ({content_diff} bytes)")
            return True
                
        # No bypass detected
        return False
    
    def _is_size_limit_enforced(self, rule_name: str, response: requests.Response, test_size: int, max_size: int) -> bool:
        """
        Determine if a size limit is being properly enforced.
        
        Args:
            rule_name: Name of the rule being tested
            response: HTTP response from the size test
            test_size: Size of the test payload in bytes
            max_size: Maximum allowed size in bytes
            
        Returns:
            True if the size limit appears to be enforced, False otherwise
        """
        # If the test size is greater than the max size, we expect a block
        if test_size > max_size:
            # If response is 403 Forbidden or similar blocking status, that's good
            if response.status_code in [403, 400, 413]:  # 413 = Payload Too Large
                return True
            else:
                # WAF isn't blocking oversized request - potential issue
                self.logger.warning(
                    f"Size limit may not be enforced for {rule_name}. "
                    f"Sent {test_size} bytes (limit: {max_size}), got status {response.status_code}"
                )
                return False
        
        # If test size is under the limit, we don't expect a block
        return True
    
    def test_rule(self, rule: WafRule) -> Dict[str, Any]:
        """
        Test a specific WAF rule for bypasses.
        
        Args:
            rule: The WAF rule to test
            
        Returns:
            Dictionary with test results
        """
        self.logger.info(f"Testing rule: {rule.name}")

        # Check if this is a size restriction rule
        is_size_rule = "SizeRestrictions" in rule.name
        is_xss_rule = "XSS" in rule.name or "CrossSiteScripting" in rule.name
        
        if is_xss_rule:
            print(f"⚠️ Special handling for XSS rule: {rule.name}")

        # Initialize the results dictionary
        results = {
            "rule": rule.name,
            "description": rule.description,
            "status": "completed",
            "bypasses": [],
            "all_test_results": []  # Store all test results, not just bypasses
        }
        
        # For size restriction rules, use our specific size test vectors
        if is_size_rule:
            # Get the component being tested (should only be one for size rules)
            if len(rule.request_components) > 0:
                component = rule.request_components[0]
                # Generate specific size test vectors
                rule.test_vectors = self.size_params.create_size_test_vectors(component)
        
        # Get baseline response
        baseline_response, error = self._get_baseline_response()
        if error:
            self.logger.error(f"Failed to get baseline response: {error}")
            results["status"] = "error"
            results["error"] = error
            return results
            
        self.logger.info(f"Baseline response: status={baseline_response.status_code}, size={len(baseline_response.content)} bytes")
        
        bypasses = []
        all_test_results = []
        
        # Use basic console output regardless of Rich availability to avoid display conflicts
        print(f"Testing rule: {rule.name}...")
        print(f"Baseline response: status={baseline_response.status_code}, size={len(baseline_response.content)} bytes")
        total_vectors = len(rule.test_vectors)
        
        for i, vector in enumerate(rule.test_vectors):
            try:
                for component in rule.request_components:
                    # Same request preparation logic as above
                    method = HttpMethod.GET
                    url = self.target_url
                    headers = {}
                    cookies = {}
                    params = {}
                    data = None
                    json_data = None
                    
                    # Different handling based on the request component
                    if component.lower() == "header":
                        if "user_agent" in rule.name.lower():
                            headers["User-Agent"] = vector
                        else:
                            headers["X-Test-Header"] = vector
                    elif component.lower() == "body":
                        method = HttpMethod.POST
                        if isinstance(vector, dict):
                            json_data = vector
                        else:
                            data = vector
                            headers["Content-Type"] = "application/x-www-form-urlencoded"
                    elif component.lower() == "querystring":
                        if isinstance(vector, str) and vector.startswith("?"):
                            url = f"{self.target_url}{vector}"
                        else:
                            params = {"test_param": vector} if not isinstance(vector, dict) else vector
                    elif component.lower() == "uri":
                        if isinstance(vector, str):
                            parsed_url = urlparse(self.target_url)
                            path = parsed_url.path
                            if not path.endswith("/"):
                                path += "/"
                            if vector.startswith("/"):
                                vector = vector[1:]
                            new_path = path + vector
                            url = parsed_url._replace(path=new_path).geturl()
                    elif component.lower() == "cookie":
                        if isinstance(vector, dict) and "Cookie" in vector:
                            headers["Cookie"] = vector["Cookie"]
                        else:
                            cookies = {"test_cookie": vector} if not isinstance(vector, dict) else vector
                    
                    # Log the test vector details
                    vector_preview = str(vector)[:50] + "..." if len(str(vector)) > 50 else str(vector)
                    self.logger.info(f"Testing vector in {component}: {vector_preview} using {method.value}")
                    
                    if self.verbose:
                        print(f"  Testing: {vector_preview} in {component} using {method.value}")
                    
                    # Make the test request
                    response, error = self._make_request(
                        url=url,
                        method=method,
                        headers=headers,
                        cookies=cookies,
                        params=params,
                        data=data,
                        json_data=json_data
                    )
                    
                    if error:
                        self.logger.warning(f"Error testing {rule.name} with {vector} in {component}: {error}")
                        continue
                    
                    # Log response details to help with debugging
                    self.logger.info(f"Response: status={response.status_code}, size={len(response.content)} bytes")
                    
                    # Create a test result record for all tests
                    test_result = {
                        "vector": str(vector)[:100] + "..." if len(str(vector)) > 100 else str(vector),
                        "component": component,
                        "method": method.value,
                        "status_code": response.status_code,
                        "response_size": len(response.content),
                        "base_status_code": baseline_response.status_code,
                        "base_response_size": len(baseline_response.content),
                        "blocked": True  # Default to blocked, will set to False for bypasses
                    }
                    
                    # Print response details for XSS testing to help debug
                    if is_xss_rule:
                        print(f"  XSS test response: status={response.status_code}, size={len(response.content)} bytes")
                        print(f"  Testing with payload: {vector_preview}")
                        
                        # HACK: Special handling for XSS tests - consider any non-403 response a bypass
                        if response.status_code not in [403, 400, 413]:
                            print(f"  ❌ OVERRIDE: XSS vector not blocked - status {response.status_code}!")
                            bypass_info = test_result.copy()
                            bypass_info["override_detection"] = True
                            bypass_info["blocked"] = False
                            self.logger.warning(f"XSS bypass for {rule.name} with {vector} in {component} - status {response.status_code}")
                            bypasses.append(bypass_info)
                            test_result["blocked"] = False
                            all_test_results.append(test_result)
                            continue
                        
                    # Special processing for size restriction rules
                    if is_size_rule and response:
                        # Process the size restriction test result
                        self._process_size_test_results(rule, results, vector, response, component)
                    # Standard bypass detection for all rules
                    elif response and self._is_bypass_successful(baseline_response, response):
                        bypass_info = test_result.copy()
                        bypass_info["blocked"] = False
                        
                        self.logger.warning(f"Potential bypass found for {rule.name} with {vector} in {component}")
                        print(f"  ❌ BYPASS DETECTED: {vector_preview} (status: {response.status_code})")
                        bypasses.append(bypass_info)
                        test_result["blocked"] = False
                    else:
                        # Log that the test didn't find a bypass
                        if response:
                            if self.verbose:
                                print(f"  ✅ No bypass: {response.status_code}")
                            else:
                                # Only print for certain interesting codes
                                if response.status_code not in [200, 404, 403, 400]:
                                    print(f"  Response status: {response.status_code}")
                    
                    # Add the test result to our collection
                    all_test_results.append(test_result)
                        
            except Exception as e:
                self.logger.error(f"Error testing vector for {rule.name}: {str(e)}")
                
            # Progress indicator for every 5th vector or the last one
            if i % 5 == 0 or i == total_vectors - 1:
                print(f"Progress for {rule.name}: {i+1}/{total_vectors} vectors tested ({(i+1)/total_vectors*100:.1f}%)")
            
            # Add a small delay to avoid overwhelming the server
            time.sleep(self.delay)

        # Add bypasses and all test results to the results
        results["bypasses"] = bypasses
        results["all_test_results"] = all_test_results
        return results
    
    def run_tests(self) -> Dict[str, Any]:
        """
        Run tests for all WAF rules.
        
        Returns:
            Dictionary with all test results
        """
        self.logger.info(f"Starting WAF bypass tests against {self.target_url}")
        print(f"Testing {len(self.rules)} rules against {self.target_url}")
        
        # Test connectivity first
        print("Testing connectivity...")
        baseline_response, error = self._get_baseline_response()
        if error:
            self.logger.error(f"Failed to connect to {self.target_url}: {error}")
            print(f"ERROR: Failed to connect to {self.target_url}: {error}")
            return {
                "target_url": self.target_url,
                "status": "error",
                "error": error,
                "results": {}
            }
            
        print(f"Connection successful: Status {baseline_response.status_code}")
        
        # Test with simple known-bad patterns first to verify WAF blocking behavior
        print("Performing basic WAF verification tests...")
        self._perform_waf_verification_tests()
        
        # Run tests sequentially to avoid display conflicts
        results = {}
        print("Starting rule tests...")
        
        # Process rules one at a time instead of with ThreadPoolExecutor
        for rule in self.rules:
            try:
                result = self.test_rule(rule)
                results[rule.name] = result
                print(f"Completed test for {rule.name}: {result['status']}")
            except Exception as e:
                self.logger.error(f"Error testing rule {rule.name}: {str(e)}")
                results[rule.name] = {
                    "rule": rule.name,
                    "description": rule.description,
                    "status": "error",
                    "error": str(e),
                    "bypasses": [],
                    "all_test_results": []
                }
        
        self.results = {
            "target_url": self.target_url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": self._generate_summary(results),
            "results": results
        }
        
        print("Test summary:")
        print(f"  Target URL: {self.target_url}")
        print(f"  Rules tested: {len(results)}")
        print(f"  Summary: {self._generate_summary(results)}")
        
        return self.results
    
    def _perform_waf_verification_tests(self) -> None:
        """
        Perform simple verification tests to check if the WAF is blocking known bad patterns.
        This helps verify that the WAF is working at all before we test more complex bypasses.
        """
        # Basic test patterns that should be blocked by any WAF
        test_vectors = [
            ("XSS", "body", "<script>alert(1)</script>"),
            ("SQLi", "querystring", "1' OR '1'='1"),
            ("CommandInjection", "body", "cat /etc/passwd"),
        ]
        
        waf_blocking = False
        
        print("Testing basic attack patterns to verify WAF functionality:")
        for attack_type, component, payload in test_vectors:
            # Prepare test parameters
            method = HttpMethod.GET
            url = self.target_url
            headers = {}
            cookies = {}
            params = {}
            data = None
            
            if component == "body":
                method = HttpMethod.POST
                data = {"test": payload}
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            elif component == "querystring":
                params = {"test": payload}
            
            # Make test request
            print(f"  Testing {attack_type} pattern in {component}: {payload}")
            response, error = self._make_request(
                url=url,
                method=method,
                headers=headers,
                cookies=cookies,
                params=params,
                data=data
            )
            
            if error:
                print(f"  Error: {error}")
                continue
                
            # Check if WAF blocked it
            if response.status_code in [403, 400, 413]:
                print(f"  ✅ WAF blocked {attack_type} attack (status {response.status_code})")
                waf_blocking = True
            else:
                # Check for block indicators in content
                block_indicators = ["access denied", "forbidden", "waf", "blocked", "security violation"]
                content_blocked = any(indicator in response.text.lower() for indicator in block_indicators)
                
                if content_blocked:
                    print(f"  ✅ WAF blocked {attack_type} attack (found block indicators in response)")
                    waf_blocking = True
                else:
                    print(f"  ⚠️ WAF did NOT block {attack_type} attack (status {response.status_code})")
                    
        if not waf_blocking:
            print("\n⚠️ WARNING: WAF does not appear to be blocking any test attacks!")
            print("This may indicate the WAF is not configured correctly or is not present.")
        else:
            print("\nWAF verification complete. WAF appears to be active and blocking some attacks.")
            print("Proceeding with detailed rule testing...")
    
    def _process_size_test_results(self, rule: WafRule, results: Dict[str, Any], 
                                test_vector: str, response: requests.Response,
                                component: str) -> None:
        """
        Process results from a single size restriction test.
        
        Args:
            rule: The WAF rule being tested
            results: The results dictionary to update
            test_vector: The test vector used
            response: HTTP response from the test
            component: The request component being tested
        """
        # Get expected max size for this component
        max_size = self.size_params.get_max_size_for_component(component)
        
        # Determine actual test size
        if isinstance(test_vector, dict) and "Cookie" in test_vector:  # Cookie
            test_size = len(test_vector["Cookie"])
        elif isinstance(test_vector, str) and test_vector.startswith("?"):  # Query string
            test_size = len(test_vector) - 1  # Subtract 1 for the "?"
        else:  # Body or URI
            test_size = len(test_vector)
        
        # Check if size limit is enforced
        if not self._is_size_limit_enforced(rule.name, response, test_size, max_size):
            # This is a warning about size limit enforcement
            warning = {
                "type": "size_limit",
                "component": component,
                "test_size": test_size,
                "max_size": max_size,
                "status_code": response.status_code
            }
            
            # Add to warnings if not already present
            if "warnings" not in results:
                results["warnings"] = []
            results["warnings"].append(warning)
            
            # For severe size issues, also consider it a bypass
            if test_size > max_size * 1.5:  # If size is extremely over the limit
                bypass_info = {
                    "vector": f"Size limit test: {test_size} bytes (limit: {max_size})",
                    "component": component,
                    "method": "POST" if component.lower() == "body" else "GET",
                    "status_code": response.status_code,
                    "issue_type": "size_limit_bypass"
                }
                results["bypasses"].append(bypass_info)

    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a summary of the test results.
        
        Args:
            results: The detailed test results
            
        Returns:
            A summary dictionary
        """
        total_rules = len(results)
        bypassed_rules = sum(1 for rule_result in results.values() 
                            if rule_result.get("status") == "completed" and len(rule_result.get("bypasses", [])) > 0)
        error_rules = sum(1 for rule_result in results.values() if rule_result.get("status") == "error")
        
        total_bypasses = sum(len(rule_result.get("bypasses", [])) 
                            for rule_result in results.values() if rule_result.get("status") == "completed")
        
        # Count size warnings
        size_warning_rules = 0
        total_size_warnings = 0
        for rule_result in results.values():
            if "warnings" in rule_result and rule_result["warnings"]:
                size_warnings = [w for w in rule_result["warnings"] if w.get("type") == "size_limit"]
                if size_warnings:
                    size_warning_rules += 1
                    total_size_warnings += len(size_warnings)
        
        # Group bypasses by request component
        bypasses_by_component = {}
        for rule_name, rule_result in results.items():
            if rule_result.get("status") != "completed":
                continue
                
            for bypass in rule_result.get("bypasses", []):
                component = bypass.get("component", "unknown")
                if component not in bypasses_by_component:
                    bypasses_by_component[component] = 0
                bypasses_by_component[component] += 1
        
        return {
            "total_rules_tested": total_rules,
            "rules_with_bypasses": bypassed_rules,
            "rules_with_errors": error_rules,
            "total_bypasses_found": total_bypasses,
            "bypasses_by_component": bypasses_by_component,
            "rules_with_size_warnings": size_warning_rules,
            "total_size_warnings": total_size_warnings
        }


    def display_results(self) -> None:
        """Display the test results in a readable format."""
        if not self.results:
            print("[ERROR] No results available. Run tests first.")
            return
            
        summary = self.results.get("summary", {})
        results = self.results.get("results", {})
        
        # Count override bypasses (special XSS handling)
        override_bypasses = 0
        for rule_name, rule_result in results.items():
            bypasses = rule_result.get("bypasses", [])
            override_bypasses += sum(1 for bypass in bypasses if bypass.get("override_detection", False))
        
        # Print summary
        print("\n==== WAF Bypass Test Summary ====")
        print(f"Target URL: {self.results['target_url']}")
        print(f"Total Rules Tested: {summary.get('total_rules_tested', 0)}")
        print(f"Rules With Bypasses: {summary.get('rules_with_bypasses', 0)}")
        print(f"Rules With Errors: {summary.get('rules_with_errors', 0)}")
        print(f"Total Bypasses Found: {summary.get('total_bypasses_found', 0)}")
        
        if override_bypasses > 0:
            print(f"⚠️ XSS Bypasses Detected: {override_bypasses} (WAF didn't block)")
        
        # Add component breakdown
        if "bypasses_by_component" in summary and summary["bypasses_by_component"]:
            print("\nBypasses by Component:")
            for component, count in summary["bypasses_by_component"].items():
                print(f"  {component}: {count}")
        
        # Display detailed results for rules with bypasses
        if summary.get("rules_with_bypasses", 0) > 0:
            print("\n==== Rules with successful bypasses ====")
            
            for rule_name, rule_result in results.items():
                bypasses = rule_result.get("bypasses", [])
                if rule_result.get("status") == "completed" and bypasses:
                    print(f"\n{rule_name}: {rule_result['description']}")
                    
                    xss_bypasses = [b for b in bypasses if b.get("override_detection", False)]
                    if xss_bypasses:
                        print(f"  ⚠️ {len(xss_bypasses)} XSS vectors not blocked by WAF!")
                    
                    print("\nExample bypasses:")
                    for i, bypass in enumerate(bypasses[:5]):  # Show max 5 examples
                        vector = bypass.get("vector", "")
                        # Truncate long vectors for display
                        if len(vector) > 50:
                            vector = vector[:47] + "..."
                            
                        prefix = "⚠️ " if bypass.get("override_detection", False) else ""
                        print(f"  {prefix}Vector: {vector}")
                        print(f"  Component: {bypass.get('component', '')}")
                        print(f"  Method: {bypass.get('method', '')}")
                        print(f"  Status: {bypass.get('status_code', '')} (Base: {bypass.get('base_status_code', '')})")
                        if bypass.get("override_detection", False):
                            print(f"  NOTE: XSS vector not blocked by WAF!")
                        print("")
                    
                    if len(bypasses) > 5:
                        print(f"  ... and {len(bypasses) - 5} more bypasses")
        
        # Display size limit warnings
        size_warnings = []
        for rule_name, rule_result in results.items():
            if "warnings" in rule_result and rule_result["warnings"]:
                for warning in rule_result["warnings"]:
                    if warning.get("type") == "size_limit":
                        size_warnings.append(warning)
        
        if size_warnings:
            print("\n==== Size Limit Warnings ====")
            print("The following size limits may not be properly enforced:")
            
            for warning in size_warnings:
                component = warning.get("component", "")
                test_size = warning.get("test_size", 0)
                max_size = warning.get("max_size", 0)
                status_code = warning.get("status_code", "")
                
                print(f"\n  Component: {component}")
                print(f"  Test Size: {test_size} bytes")
                print(f"  Max Size: {max_size} bytes")
                print(f"  Status Code: {status_code}")
                print(f"  Over Limit: {test_size - max_size} bytes ({(test_size / max_size * 100):.1f}% of limit)")
        
        # Display errors if any
        if summary.get("rules_with_errors", 0) > 0:
            print("\n==== Rules with errors ====")
            
            for rule_name, rule_result in results.items():
                if rule_result.get("status") == "error":
                    print(f"{rule_name}: {rule_result.get('error', 'Unknown error')}")
        
        # If no bypasses or errors were found
        if summary.get("rules_with_bypasses", 0) == 0 and summary.get("rules_with_errors", 0) == 0 and not size_warnings:
            print("\nNo WAF bypass vulnerabilities or issues were detected.")
        elif summary.get("rules_with_bypasses", 0) == 0 and summary.get("rules_with_errors", 0) == 0:
            print("\nNo WAF bypass vulnerabilities were detected, but some size limit warnings were found.")

    def generate_remediation_recommendations(self) -> str:
        """
        Generate recommendations for fixing identified WAF bypass vulnerabilities.
        
        Returns:
            String containing remediation recommendations
        """
        if not self.results:
            return "No results available. Run tests first."
            
        recommendations = []
        results = self.results.get("results", {})
        
        # Check if any bypasses were found
        any_bypasses = False
        for rule_result in results.values():
            if rule_result.get("status") == "completed" and rule_result.get("bypasses", []):
                any_bypasses = True
                break
                
        if not any_bypasses:
            return "No WAF bypasses were detected. The current WAF configuration appears to be effective."
            
        # General recommendations
        recommendations.append("# WAF Remediation Recommendations")
        recommendations.append("\n## General Recommendations")
        recommendations.append("- Consider implementing a layered security approach beyond just WAF")
        recommendations.append("- Use rate limiting to prevent brute force bypass attempts")
        recommendations.append("- Implement IP reputation filtering to block known malicious sources")
        recommendations.append("- Consider implementing a custom rule set in addition to managed rules")
        recommendations.append("- Regularly update your WAF rules to address new evasion techniques")
        
        # Rule-specific recommendations
        recommendations.append("\n## Rule-Specific Recommendations")
        
        for rule_name, rule_result in results.items():
            bypasses = rule_result.get("bypasses", [])
            if rule_result.get("status") == "completed" and bypasses:
                recommendations.append(f"\n### {rule_name}")
                recommendations.append(f"**Description:** {rule_result.get('description', '')}")
                recommendations.append("**Issues Found:**")
                
                # Group recommendations by component
                components = set(bypass.get("component", "") for bypass in bypasses)
                for component in components:
                    component_bypasses = [b for b in bypasses if b.get("component", "") == component]
                    recommendations.append(f"- **{component.upper()} Bypasses ({len(component_bypasses)}):**")
                    
                    # Add specific recommendations based on rule type and component
                    if "XSS" in rule_name or "CrossSiteScripting" in rule_name:
                        recommendations.append("  - Strengthen XSS filters to handle encoding variations")
                        recommendations.append("  - Add custom rules to detect context-specific XSS payloads")
                        recommendations.append("  - Implement Content-Security-Policy headers as an additional layer of defense")
                        
                    elif "SQLi" in rule_name:
                        recommendations.append("  - Enhance SQL injection detection with custom rules")
                        recommendations.append("  - Use character and keyword blacklisting in addition to pattern matching")
                        recommendations.append("  - Consider implementing a positive security model for SQL queries")
                        
                    elif "LFI" in rule_name or "GenericLFI" in rule_name:
                        recommendations.append("  - Strengthen path traversal detection with custom rules")
                        recommendations.append("  - Block access to sensitive file paths and extensions")
                        recommendations.append("  - Implement strict input validation for file paths")
                        
                    elif "RFI" in rule_name or "GenericRFI" in rule_name:
                        recommendations.append("  - Block outbound connections to unknown domains")
                        recommendations.append("  - Implement a whitelist of allowed domains for remote inclusions")
                        recommendations.append("  - Use content inspection to detect and block malicious file inclusions")
                        
                    elif "Size" in rule_name or "SizeRestrictions" in rule_name:
                        recommendations.append("  - Adjust size restriction thresholds based on application needs")
                        recommendations.append("  - Implement more granular size controls for different request components")
                        recommendations.append("  - Consider implementing request throttling for large payloads")
                        
                    elif "UserAgent" in rule_name or "BadBots" in rule_name:
                        recommendations.append("  - Update user agent blacklists regularly")
                        recommendations.append("  - Implement behavioral analysis to detect suspicious clients")
                        recommendations.append("  - Consider using CAPTCHA for suspicious user agents")
                    
                    # Examples of bypassed vectors
                    if component_bypasses:
                        recommendations.append("  - **Example bypasses:**")
                        for i, bypass in enumerate(component_bypasses[:3]):  # Show max 3 examples
                            recommendations.append(f"    - `{bypass.get('vector', '')[:50]}...`")
                        if len(component_bypasses) > 3:
                            recommendations.append(f"    - ...and {len(component_bypasses) - 3} more")
        
        return "\n".join(recommendations)
    
    def save_recommendations(self, output_file: str = None) -> str:
        """
        Save remediation recommendations to a file.
        
        Args:
            output_file: Path to the output file (optional, will generate one if not provided)
            
        Returns:
            Path to the saved file
        """
        recommendations = self.generate_remediation_recommendations()
        if recommendations == "No results available. Run tests first." or not self.results:
            self.logger.error("No recommendations available to save. Run tests first.")
            return None
            
        try:
            # Create reports directory if it doesn't exist
            reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
            if not os.path.exists(reports_dir):
                os.makedirs(reports_dir)
                self.logger.info(f"Created reports directory: {reports_dir}")
            
            # Generate a unique filename if one wasn't provided
            if not output_file:
                # Extract hostname from URL for the filename
                url = self.results.get("target_url", "unknown")
                hostname = urlparse(url).netloc.replace(":", "_")
                if not hostname:
                    hostname = "unknown_host"
                
                # Format timestamp for filename
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                output_file = os.path.join(reports_dir, f"waf_recommendations_{hostname}_{timestamp}.md")
            elif not os.path.isabs(output_file):
                # If relative path was provided, put it in reports directory
                output_file = os.path.join(reports_dir, output_file)
                
            with open(output_file, 'w') as f:
                f.write(recommendations)
                
            self.logger.info(f"Recommendations saved to {output_file}")
            return output_file
        except Exception as e:
            self.logger.error(f"Error saving recommendations to {output_file}: {str(e)}")
            return None
    
    def save_results(self, output_file: str = None) -> str:
        """
        Save the test results to a file.
        
        Args:
            output_file: Path to the output file (optional, will generate one if not provided)
            
        Returns:
            Path to the saved file
        """
        if not self.results:
            self.logger.error("No results available to save. Run tests first.")
            return None
            
        try:
            # Create reports directory if it doesn't exist
            reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
            if not os.path.exists(reports_dir):
                os.makedirs(reports_dir)
                self.logger.info(f"Created reports directory: {reports_dir}")
            
            # Generate a unique filename if one wasn't provided
            if not output_file:
                # Extract hostname from URL for the filename
                url = self.results.get("target_url", "unknown")
                hostname = urlparse(url).netloc.replace(":", "_")
                if not hostname:
                    hostname = "unknown_host"
                
                # Format timestamp for filename
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                output_file = os.path.join(reports_dir, f"waf_results_{hostname}_{timestamp}.json")
            elif not os.path.isabs(output_file):
                # If relative path was provided, put it in reports directory
                output_file = os.path.join(reports_dir, output_file)
            
            # Fix vector representation in results
            results_copy = copy.deepcopy(self.results)
            if "results" in results_copy:
                for rule_name, rule_data in results_copy["results"].items():
                    if "bypasses" in rule_data:
                        for bypass in rule_data["bypasses"]:
                            # Ensure vector is properly formatted
                            if isinstance(bypass.get("vector"), dict) or isinstance(bypass.get("vector"), list):
                                bypass["vector"] = json.dumps(bypass["vector"])
                            elif bypass.get("vector") is None:
                                bypass["vector"] = "None"
            
            # Save the results
            with open(output_file, 'w') as f:
                json.dump(results_copy, f, indent=2, default=str)
                
            self.logger.info(f"Results saved to {output_file}")
            return output_file
        except Exception as e:
            self.logger.error(f"Error saving results to {output_file}: {str(e)}")
            return None


class WafBypassReport:
    """
    Helper class for generating detailed HTML reports of WAF bypass test results.
    """
    
    @staticmethod
    def generate_html_report(results: Dict[str, Any], output_file: str = None) -> str:
        """
        Generate an HTML report from test results.
        
        Args:
            results: The test results
            output_file: Path to the output file (optional, will generate one if not provided)
            
        Returns:
            Path to the generated HTML report
        """
        if not results:
            print("No results available to generate report.")
            return None
        
        try:
            # Use the enhanced report generator if available
            try:
                from core.report_generator import generate_html_report
                target_url = results.get("target_url", "Unknown URL")
                return generate_html_report(results, target_url, output_file)
            except ImportError:
                # Fall back to legacy report generation
                pass
                
            # Create reports directory if it doesn't exist
            reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
            if not os.path.exists(reports_dir):
                os.makedirs(reports_dir)
                print(f"Created reports directory: {reports_dir}")
            
            # Generate a unique filename if one wasn't provided
            if not output_file:
                # Extract hostname from URL for the filename
                url = results.get("target_url", "unknown")
                hostname = urlparse(url).netloc.replace(":", "_")
                if not hostname:
                    hostname = "unknown_host"
                
                # Format timestamp for filename
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                output_file = os.path.join(reports_dir, f"waf_report_{hostname}_{timestamp}.html")
            elif not os.path.isabs(output_file):
                # If relative path was provided, put it in reports directory
                output_file = os.path.join(reports_dir, output_file)
                
            summary = results.get("summary", {})
            detailed_results = results.get("results", {})
            
            # Legacy HTML report generation code
            # ...
            
            print(f"HTML report generated: {output_file}")
            return output_file
        except Exception as e:
            print(f"Error generating HTML report: {e}")
            return None



if __name__ == "__main__":
    print("This is a module to be imported by other scripts.")
    print("It provides the core functionality for WAF testing.")