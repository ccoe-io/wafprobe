#!/usr/bin/env python3
"""
AWS WAF Tester

A comprehensive testing tool for AWS WAF rules and configurations.
This script tests AWS WAF rule sets against a target URL to identify
potential bypass vulnerabilities.

Usage:
    python aws_waf_tester.py https://example.com [options]
"""

import argparse
import json
import sys
import os
import time
from typing import List, Dict, Any, Optional
# from vectors.s3 import S3BucketVectors

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import core engine
from core.engine import WafBypassDetector, WafBypassReport, WafRule
from core.size_parameters import SizeTestParameters

# Import rule sets
from rules.aws_rules import (
    create_aws_managed_rules_common_rule_set,
    create_aws_managed_rules_admin_protection_rule_set,
    create_aws_managed_rules_known_bad_inputs_rule_set,
    create_aws_managed_rules_anonymized_ip_list,
    create_aws_managed_rules_all
)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="AWS WAF Tester - A comprehensive testing tool for AWS WAF rules",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "target_url",
        help="The target URL to test against"
    )
    
    parser.add_argument(
        "-r", "--ruleset",
        choices=["common", "admin", "badinputs", "anonip", "all"],
        default="common",
        help="AWS managed rule set to test"
    )
    
    parser.add_argument(
        "--rules",
        help="Comma-separated list of specific rule names to test (e.g., 'CrossSiteScripting_COOKIE,GenericLFI_BODY')"
    )
    
    parser.add_argument(
        "--category",
        choices=["xss", "sqli", "lfi", "rfi", "ssrf", "admin", "badbot", "size", "all"],
        default="all",
        help="Test only a specific category of rules"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output file for detailed JSON results"
    )
    
    parser.add_argument(
        "--html-report",
        action="store_true",
        help="Generate an HTML report"
    )
    
    parser.add_argument(
        "--recommendations",
        action="store_true",
        help="Generate remediation recommendations based on findings"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode with more detailed logging"
    )
    
    parser.add_argument(
        "--debug-rule-count",
        type=int,
        default=2,
        help="Number of rules to test in debug mode (use 0 for all rules)"
    )
    
    parser.add_argument(
        "--delay",
        type=float,
        default=0.1,
        help="Delay between requests in seconds to avoid overwhelming the server"
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds"
    )
    
    parser.add_argument(
        "--workers",
        type=int,
        default=5,
        help="Number of concurrent worker threads for testing"
    )
    
    parser.add_argument(
        "--max-vectors",
        type=int,
        default=0,
        help="Maximum number of test vectors per rule (0 for all vectors)"
    )

    # parser.add_argument(
    #     "--s3-bucket-file",
    #     help="File containing S3 bucket names to test (one per line)"
    # )

    # parser.add_argument(
    #     "--company-names",
    #     help="Comma-separated list of company names for S3 bucket enumeration"
    # )

    parser.add_argument(
        "--max-body-size",
        type=int,
        default=8192,  # 8KB
        help="Maximum allowed request body size in bytes"
    )

    parser.add_argument(
        "--max-query-size",
        type=int,
        default=4096,  # 4KB
        help="Maximum allowed query string size in bytes"
    )

    parser.add_argument(
        "--max-cookie-size",
        type=int,
        default=4096,  # 4KB
        help="Maximum allowed cookie size in bytes"
    )

    parser.add_argument(
        "--max-uri-size",
        type=int,
        default=2048,  # 2KB
        help="Maximum allowed URI path size in bytes"
    )

    parser.add_argument(
        "--size-threshold",
        type=float,
        default=1.5,
        help="Multiplier for size testing (e.g., 1.5 tests 150% of the limit)"
    )

    return parser.parse_args()


def get_rule_set(ruleset_name: str) -> List[WafRule]:
    """
    Get the appropriate rule set based on the provided name.
    
    Args:
        ruleset_name: Name of the rule set
        
    Returns:
        List of WafRule objects
    """
    if ruleset_name == "common":
        return create_aws_managed_rules_common_rule_set()
    elif ruleset_name == "admin":
        return create_aws_managed_rules_admin_protection_rule_set()
    elif ruleset_name == "badinputs":
        return create_aws_managed_rules_known_bad_inputs_rule_set()
    elif ruleset_name == "anonip":
        return create_aws_managed_rules_anonymized_ip_list()
    elif ruleset_name == "all":
        return create_aws_managed_rules_all()
    else:
        print(f"Unknown rule set: {ruleset_name}")
        sys.exit(1)


def filter_rules_by_category(rules: List[WafRule], category: str) -> List[WafRule]:
    """
    Filter rules by category.
    
    Args:
        rules: List of all rules
        category: Category to filter by
        
    Returns:
        Filtered list of rules
    """
    if category == "all":
        return rules
    
    category_filters = {
        "xss": "CrossSiteScripting",
        "sqli": "SQLi",
        "lfi": "GenericLFI",
        "rfi": "GenericRFI",
        "ssrf": "EC2MetaDataSSRF",
        "admin": "AdminProtection",
        "badbot": "BadBots",
        "size": "SizeRestrictions"
    }
    
    if category not in category_filters:
        print(f"Unknown category: {category}")
        sys.exit(1)
    
    filter_term = category_filters[category]
    
    filtered_rules = [rule for rule in rules if filter_term in rule.name]
    
    if not filtered_rules:
        print(f"No rules found for category: {category}")
        sys.exit(1)
    
    return filtered_rules


def filter_rules_by_name(rules: List[WafRule], rule_names: List[str]) -> List[WafRule]:
    """
    Filter rules by specific rule names.
    
    Args:
        rules: List of all rules
        rule_names: List of rule names to filter by
        
    Returns:
        Filtered list of rules
    """
    if not rule_names:
        return rules
    
    filtered_rules = [rule for rule in rules if rule.name in rule_names]
    
    if not filtered_rules:
        print(f"No matching rules found for: {', '.join(rule_names)}")
        sys.exit(1)
    
    return filtered_rules


def limit_test_vectors(rules: List[WafRule], max_vectors: int) -> List[WafRule]:
    """
    Limit the number of test vectors per rule.
    
    Args:
        rules: List of all rules
        max_vectors: Maximum number of test vectors per rule
        
    Returns:
        Rules with limited test vectors
    """
    if max_vectors <= 0:
        return rules
    
    for rule in rules:
        if len(rule.test_vectors) > max_vectors:
            print(f"Limiting '{rule.name}' from {len(rule.test_vectors)} to {max_vectors} test vectors")
            rule.test_vectors = rule.test_vectors[:max_vectors]
        
        # if hasattr(rule, 'name') and 'S3' in rule.name:
        #     print(f"Customizing S3 bucket vectors for rule: {rule.name}")
        #     rule.test_vectors = S3BucketVectors.all(args.s3_bucket_file, company_names)
    
    return rules


def run_tests(args) -> tuple:
    """
    Run the WAF bypass tests.
    
    Args:
        args: Command line arguments
        
    Returns:
        Tuple of (results dictionary, detector instance)
    """
    print(f"AWS WAF Tester - Testing {args.target_url}")
    print(f"Rule set: {args.ruleset}")
    
    # Get the appropriate rule set
    rules = get_rule_set(args.ruleset)
    print(f"Total rules in set: {len(rules)}")
    
    # Filter by category if specified
    rules = filter_rules_by_category(rules, args.category)
    print(f"Rules after category filter: {len(rules)}")
    
    # Filter by specific rule names if specified
    if args.rules:
        rule_names = [name.strip() for name in args.rules.split(",")]
        rules = filter_rules_by_name(rules, rule_names)
        print(f"Rules after name filter: {len(rules)}")
    
    # Limit test vectors if specified
    rules = limit_test_vectors(rules, args.max_vectors)
    
    # Apply debug mode limitations if specified
    if args.debug and args.debug_rule_count > 0 and args.debug_rule_count < len(rules):
        print(f"Debug mode: Limiting to first {args.debug_rule_count} rules for faster testing")
        rules = rules[:args.debug_rule_count]
    
    # Initialize the detector
    detector = WafBypassDetector(args.target_url, args.verbose)
    detector.rules = rules

    # Configure size parameters
    detector.size_params = SizeTestParameters(
        max_body_size=args.max_body_size,
        max_query_size=args.max_query_size,
        max_cookie_size=args.max_cookie_size,
        max_uri_size=args.max_uri_size,
        threshold_multiplier=args.size_threshold
    )
    
    print(f"Configured size limits: Body={args.max_body_size}B, Query={args.max_query_size}B, "
          f"Cookie={args.max_cookie_size}B, URI={args.max_uri_size}B")
    
    # Customize detector parameters based on arguments
    if args.delay != 0.1:
        print(f"Setting request delay to {args.delay} seconds")
        detector.delay = args.delay
    
    if args.timeout != 10:
        print(f"Setting request timeout to {args.timeout} seconds")
        detector.timeout = args.timeout
    
    if args.workers != 5:
        print(f"Setting worker threads to {args.workers}")
        detector.workers = args.workers
    
    # Run the tests
    print("\nStarting tests...")
    start_time = time.time()
    results = detector.run_tests()
    end_time = time.time()
    print(f"\nTesting completed in {end_time - start_time:.2f} seconds")
    
    # Display results
    detector.display_results()
    
    return results, detector


def save_results(results: Dict[str, Any], args, detector: WafBypassDetector) -> None:
    """
    Save test results and generate reports.
    
    Args:
        results: Test results
        args: Command line arguments
        detector: WAF bypass detector instance
    """
    # Save JSON results
    json_output = None
    if args.output:
        try:
            json_output = detector.save_results(args.output)
            print(f"\nResults saved to {json_output}")
        except Exception as e:
            print(f"Error saving results: {str(e)}")
    else:
        # Save with auto-generated filename
        json_output = detector.save_results()
        print(f"\nResults saved to {json_output}")
    
    # Generate HTML report if requested
    if args.html_report:
        try:
            # If json_output has a path, use it to create the HTML filename in the same location
            html_file = WafBypassReport.generate_html_report(results)
            print(f"HTML report generated at {html_file}")
        except Exception as e:
            print(f"Error generating HTML report: {str(e)}")
    
    # Generate remediation recommendations if requested
    if args.recommendations:
        try:
            rec_file = detector.save_recommendations()
            print(f"Recommendations saved to {rec_file}")
        except Exception as e:
            print(f"Error saving recommendations: {str(e)}")


def main():
    """Main function for the AWS WAF Tester."""
    # Parse arguments
    args = parse_arguments()
    
    # Run tests
    results, detector = run_tests(args)
    
    # Save results and generate reports
    save_results(results, args, detector)
    
    # Return success or failure based on findings
    summary = results.get("summary", {})
    total_bypasses = summary.get("total_bypasses_found", 0)
    
    if total_bypasses > 0:
        print(f"\n⚠️  Found {total_bypasses} potential WAF bypasses!")
        return 1
    else:
        print("\n✅ No WAF bypasses detected.")
        return 0


if __name__ == "__main__":
    sys.exit(main())