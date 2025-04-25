#!/usr/bin/env python3
"""
Multi-WAF Tester

A comprehensive testing tool for various WAF implementations and rule sets.
This script tests WAF rule sets against a target URL to identify
potential bypass vulnerabilities across different platforms and attack vectors.

Usage:
    python multi_waf_tester.py --config config.yaml
"""

import argparse
import json
import sys
import os
import time
import yaml
import logging
import importlib
import pkgutil
import inspect
from typing import List, Dict, Any, Optional, Union
from concurrent.futures import ThreadPoolExecutor

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import core engine
from core.engine import WafBypassDetector, WafBypassReport, WafRule
from core.size_parameters import SizeTestParameters

# Import discovery functions from rules package
from rules.discovery import (
    discover_rule_modules, 
    get_all_category_mappings,
    get_all_categories,
    get_module_for_category,
    get_categories_by_module,
    search_categories
)

# Process config for environment variables
from core.config_utils import process_config

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("multi_waf_tester")


def get_category_mappings_flat() -> Dict[str, str]:
    """
    Get a flattened version of category mappings suitable for the legacy code.
    
    Returns:
        Dictionary mapping category keywords to rule name patterns
    """
    all_mappings = get_all_category_mappings()
    
    # Convert from Dict[str, Tuple[str, str]] to Dict[str, str]
    flat_mappings = {}
    for key, (pattern, _) in all_mappings.items():
        flat_mappings[key] = pattern
        
    return flat_mappings


def parse_arguments():
    """Parse command line arguments."""
    # Discover available rule modules
    available_modules = discover_rule_modules()
    
    parser = argparse.ArgumentParser(
        description="Multi-WAF Tester - A comprehensive testing tool for various WAF implementations",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "--config",
        help="Path to the YAML configuration file"
    )
    
    parser.add_argument(
        "--target",
        help="Test only a specific target from the config file (by name or URL)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Override config and enable verbose output"
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Override config and enable debug mode"
    )
    
    # New options for listing rules
    list_group = parser.add_argument_group('List options')
    list_group.add_argument(
        "--list-modules",
        action="store_true",
        help="List all available rule modules"
    )
    
    list_group.add_argument(
        "--list-categories",
        action="store_true",
        help="List all available rule categories"
    )
    
    list_group.add_argument(
        "--list-rules",
        action="store_true",
        help="List all available rules"
    )
    
    list_group.add_argument(
        "--module",
        help="Specify module when listing rules or categories (e.g., 'aws_rules')",
        choices=available_modules if available_modules else None
    )
    
    # Add search functionality
    list_group.add_argument(
        "--search",
        help="Search for categories or rules containing the specified term"
    )
    
    return parser.parse_args()


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load the YAML configuration file.
    
    Args:
        config_path: Path to the YAML config file
        
    Returns:
        Dictionary containing the configuration
    """
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        if not config:
            logger.error(f"Config file {config_path} is empty or invalid")
            sys.exit(1)
        
        if 'targets' not in config or not config['targets']:
            logger.error(f"No targets defined in config file {config_path}")
            sys.exit(1)
        
        # Process the config for environment variables
        config = process_config(config)
        logger.info(f"Loaded and processed configuration from {config_path}")
        
        return config
    except Exception as e:
        logger.error(f"Error loading config file {config_path}: {str(e)}")
        sys.exit(1)


def load_rule_module(module_name: str) -> List[WafRule]:
    """
    Dynamically load a module containing WAF rules.
    
    Args:
        module_name: Name of the module to load (e.g., 'aws_rules')
        
    Returns:
        List of WafRule objects from the module
    """
    try:
        # Try to import from rules package
        module = importlib.import_module(f"rules.{module_name}")
        
        # Call get_rules() function to get the rules
        if hasattr(module, 'get_rules'):
            return module.get_rules()
        else:
            logger.error(f"Module {module_name} does not have get_rules() function")
            return []
    except ImportError as e:
        logger.error(f"Could not import module {module_name}: {str(e)}")
        return []


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
    
    return [rule for rule in rules if rule.name in rule_names]


def filter_rules_by_category(rules: List[WafRule], categories: List[str]) -> List[WafRule]:
    """
    Filter rules by category.
    
    Args:
        rules: List of all rules
        categories: List of categories to filter by
        
    Returns:
        Filtered list of rules
    """
    if not categories:
        return rules
    
    # Get category mappings dynamically
    category_mappings = get_category_mappings_flat()
    
    # Convert categories to patterns
    patterns = []
    for category in categories:
        category = category.lower()
        if category in category_mappings:
            patterns.append(category_mappings[category])
        else:
            # If not found, use the category name as is
            patterns.append(category)
    
    # Filter rules based on whether any pattern matches the rule name
    filtered_rules = []
    for rule in rules:
        for pattern in patterns:
            if pattern.lower() in rule.name.lower():
                filtered_rules.append(rule)
                break
    
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
            logger.info(f"Limiting '{rule.name}' from {len(rule.test_vectors)} to {max_vectors} test vectors")
            rule.test_vectors = rule.test_vectors[:max_vectors]
    
    return rules


def create_size_parameters(config: Dict[str, Any]) -> SizeTestParameters:
    """
    Create size parameters from config.
    
    Args:
        config: Dictionary containing size limit configuration
        
    Returns:
        SizeTestParameters object
    """
    return SizeTestParameters(
        max_body_size=config.get('max_body_size', 8192),
        max_query_size=config.get('max_query_size', 4096),
        max_cookie_size=config.get('max_cookie_size', 4096),
        max_uri_size=config.get('max_uri_size', 2048),
        threshold_multiplier=config.get('size_threshold', 1.5)
    )


def get_target_rules(target_config: Dict[str, Any]) -> List[WafRule]:
    """
    Get and filter rules for a specific target.
    
    Args:
        target_config: Target configuration dictionary
        
    Returns:
        List of filtered rules for the target
    """
    rules = []
    
    # Get rule configuration
    rule_config = target_config.get('rules', {})
    
    # Load rules from specified modules
    included_modules = rule_config.get('include', [])
    for module_name in included_modules:
        module_rules = load_rule_module(module_name)
        if module_rules:
            logger.info(f"Loaded {len(module_rules)} rules from module {module_name}")
            rules.extend(module_rules)
        else:
            logger.warning(f"No rules loaded from module {module_name}")
    
    # Apply filtering by rule names if specified
    rule_names = rule_config.get('rule_names', [])
    if rule_names:
        rules = filter_rules_by_name(rules, rule_names)
        logger.info(f"Filtered to {len(rules)} rules by name")
    
    # Apply filtering by categories if specified
    categories = rule_config.get('categories', [])
    if categories:
        rules = filter_rules_by_category(rules, categories)
        logger.info(f"Filtered to {len(rules)} rules by category")
    
    # Apply vector limiting if specified
    max_vectors = rule_config.get('max_vectors', 0)
    if max_vectors > 0:
        rules = limit_test_vectors(rules, max_vectors)
    
    return rules


def run_test_for_target(target_config: Dict[str, Any], global_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run WAF tests for a specific target.
    
    Args:
        target_config: Target configuration dictionary
        global_config: Global configuration dictionary
        
    Returns:
        Test results for the target
    """
    url = target_config['url']
    name = target_config.get('name', url)
    
    logger.info(f"Testing target: {name} ({url})")
    
    # Get rules for this target
    rules = get_target_rules(target_config)
    
    if not rules:
        logger.warning(f"No rules to test for target {name}")
        return {
            "target": name,
            "url": url,
            "error": "No rules to test",
            "results": {}
        }
    
    logger.info(f"Testing {len(rules)} rules against {name}")
    
    # Initialize detector with target URL
    detector = WafBypassDetector(url, global_config.get('verbose', False))
    detector.rules = rules
    
    # Set size parameters
    size_config = target_config.get('size_limits', {})
    detector.size_params = create_size_parameters(size_config)
    
    # Set request parameters
    request_config = target_config.get('request', {})
    detector.delay = request_config.get('delay', 0.1)
    detector.timeout = request_config.get('timeout', 10)
    
    # Set custom headers if specified
    custom_headers = request_config.get('headers', {})
    if custom_headers:
        detector.headers = custom_headers
    
    # Set worker count from global config
    detector.workers = global_config.get('workers', 5)
    
    # Run the tests
    logger.info(f"Starting tests for {name} with {len(rules)} rules")
    start_time = time.time()
    
    try:
        results = detector.run_tests()
        end_time = time.time()
        logger.info(f"Testing completed for {name} in {end_time - start_time:.2f} seconds")
        
        # Display results
        detector.display_results()
        
        # Create result output directory if specified
        output_dir = global_config.get('output_dir', './reports')
        os.makedirs(output_dir, exist_ok=True)
        
        # Save results to a JSON file
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        json_output = os.path.join(output_dir, f"waf_test_{name.replace(' ', '_')}_{timestamp}.json")
        with open(json_output, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {json_output}")
        
        # Generate HTML report if requested
        if global_config.get('html_report', False):
            html_file = os.path.join(output_dir, f"waf_test_{name.replace(' ', '_')}_{timestamp}.html")
            WafBypassReport.generate_html_report(results, html_file)
            logger.info(f"HTML report generated at {html_file}")
        
        # Generate recommendations if requested
        if global_config.get('recommendations', False):
            rec_file = os.path.join(output_dir, f"recommendations_{name.replace(' ', '_')}_{timestamp}.txt")
            with open(rec_file, 'w') as f:
                for rule_name, rule_results in results.get('rules', {}).items():
                    if rule_results.get('bypassed', False):
                        f.write(f"Rule: {rule_name}\n")
                        f.write("Recommendation: Review WAF configuration for this rule. The following vectors were able to bypass:\n")
                        for vector in rule_results.get('bypassed_vectors', []):
                            f.write(f"  - {vector}\n")
                        f.write("\n")
            logger.info(f"Recommendations saved to {rec_file}")
        
        return {
            "target": name,
            "url": url,
            "results": results,
            "output_files": {
                "json": json_output,
                "html": html_file if global_config.get('html_report', False) else None,
                "recommendations": rec_file if global_config.get('recommendations', False) else None
            }
        }
    
    except Exception as e:
        logger.error(f"Error testing {name}: {str(e)}")
        end_time = time.time()
        return {
            "target": name,
            "url": url,
            "error": str(e),
            "duration": end_time - start_time
        }


def list_available_modules():
    """List all available rule modules."""
    modules = discover_rule_modules()
    logger.info("Available rule modules:")
    for module in modules:
        # Try to import the module and get its description
        try:
            mod = importlib.import_module(f"rules.{module}")
            description = mod.__doc__.strip().split('\n')[0] if mod.__doc__ else "No description available"
            logger.info(f"  - {module}: {description}")
        except Exception:
            logger.info(f"  - {module}")


def list_available_categories():
    """
    List all available rule categories.
    """
    print("Available WAF Rule Categories:")
    print("=============================")
    
    # Get categories by module using our new discovery function
    module_categories = get_categories_by_module()
    
    args = parse_arguments()
    
    # If module is specified, only show categories for that module
    if args.module:
        if args.module in module_categories:
            categories = module_categories[args.module]
            module_display = args.module.replace('_rules', '').upper()
            print(f"\n{module_display} Categories:")
            for category, description in sorted(categories.items()):
                print(f"  - {category}: {description}")
        else:
            print(f"No categories found for module: {args.module}")
        return
    
    # Otherwise show all categories grouped by module
    for module_name, categories in sorted(module_categories.items()):
        module_display = module_name.replace('_rules', '').upper()
        print(f"\n{module_display} Categories:")
        for category, description in sorted(categories.items()):
            print(f"  - {category}: {description}")
    
    # Print search instructions
    print("\nUse --search to find specific categories (e.g., --search injection)")


def list_available_rules(module_name=None):
    """
    List all available rules.
    
    Args:
        module_name: Optional name of a specific module to list rules from
    """
    args = parse_arguments()
    search_term = args.search
    
    if search_term:
        print(f"Searching for rules containing '{search_term}':")
        print("=========================================" + "=" * len(search_term))
    else:
        print("Available WAF Rules:")
        print("==================")
    
    # If module is specified, only load rules from that module
    if module_name:
        try:
            module = importlib.import_module(f"rules.{module_name}")
            if hasattr(module, 'get_rules'):
                rules = module.get_rules()
                module_display = module_name.replace('_rules', '').upper()
                
                print(f"\n{module_display} Rules ({len(rules)}):")
                for rule in sorted(rules, key=lambda r: r.name):
                    if not search_term or search_term.lower() in rule.name.lower() or search_term.lower() in rule.description.lower():
                        print(f"  - {rule.name}: {rule.description}")
            else:
                print(f"Module {module_name} does not define any rules")
        except ImportError:
            print(f"Could not import module: rules.{module_name}")
        except Exception as e:
            print(f"Error processing module {module_name}: {e}")
        return
    
    # Otherwise loop through all modules
    rule_count = 0
    for module_name in discover_rule_modules():
        try:
            module = importlib.import_module(f"rules.{module_name}")
            if hasattr(module, 'get_rules'):
                rules = module.get_rules()
                module_display = module_name.replace('_rules', '').upper()
                
                # If searching, only include modules with matching rules
                matching_rules = [r for r in rules if not search_term or 
                                 search_term.lower() in r.name.lower() or 
                                 search_term.lower() in r.description.lower()]
                
                if matching_rules:
                    print(f"\n{module_display} Rules ({len(matching_rules)}/{len(rules)}):")
                    for rule in sorted(matching_rules, key=lambda r: r.name):
                        print(f"  - {rule.name}: {rule.description}")
                    rule_count += len(matching_rules)
            else:
                print(f"Module {module_name} does not define any rules")
        except ImportError:
            print(f"Could not import module: rules.{module_name}")
        except Exception as e:
            print(f"Error processing module {module_name}: {e}")
    
    if search_term:
        print(f"\nFound {rule_count} rules matching '{search_term}'")
    else:
        print(f"\nTotal rules available: {rule_count}")


def main():
    """Main function."""
    args = parse_arguments()
    
    # Handle informational options
    if args.list_modules:
        list_available_modules()
        sys.exit(0)
    
    if args.list_categories:
        list_available_categories()
        sys.exit(0)
    
    if args.list_rules:
        list_available_rules(args.module)
        sys.exit(0)
    
    if args.search and not args.list_rules and not args.list_categories:
        # Search both categories and rules by default
        print(f"Searching for '{args.search}' in categories and rules:")
        print("=" * 50)
        
        # Search categories
        print("\nMatching Categories:")
        results = search_categories(args.search)
        if results:
            for cat, (desc, module) in sorted(results.items()):
                module_display = module.replace('_rules', '').upper()
                print(f"  - [{module_display}] {cat}: {desc}")
        else:
            print("  No matching categories found")
        
        # Search rules
        print("\nMatching Rules:")
        list_available_rules(args.module)
        
        sys.exit(0)
    
    # Check if configuration file is provided
    if not args.config:
        print("Error: No configuration file specified.")
        print("Please provide a configuration file using --config")
        sys.exit(1)
    
    # Load configuration
    config = load_config(args.config)
    
    # Get global config
    global_config = config.get('global', {})
    
    # Override with command line arguments if specified
    if args.verbose:
        global_config['verbose'] = True
    
    if args.debug:
        global_config['debug'] = True
        logger.setLevel(logging.DEBUG)
    
    # Set up logging based on debug flag
    if global_config.get('debug', False):
        logger.setLevel(logging.DEBUG)
    
    # Get targets
    targets = config.get('targets', [])
    
    if args.target:
        # Filter to specific target if requested
        targets = [t for t in targets if t.get('name') == args.target or t.get('url') == args.target]
        if not targets:
            logger.error(f"Target '{args.target}' not found in config")
            sys.exit(1)
    
    logger.info(f"Found {len(targets)} targets to test")
    
    # Initialize results
    all_results = {
        "summary": {
            "total_targets": len(targets),
            "total_bypasses_found": 0,
            "total_rules_tested": 0
        },
        "targets": []
    }
    
    # Run tests for each target
    for target in targets:
        target_result = run_test_for_target(target, global_config)
        all_results["targets"].append(target_result)
        
        # Update totals
        results = target_result.get('results', {})
        bypasses = results.get('summary', {}).get('total_bypasses_found', 0)
        rules_tested = results.get('summary', {}).get('total_rules_tested', 0)
        
        all_results["summary"]["total_bypasses_found"] += bypasses
        all_results["summary"]["total_rules_tested"] += rules_tested
    
    # Output summary
    logger.info("\nTest Summary:")
    logger.info(f"Targets tested: {all_results['summary']['total_targets']}")
    logger.info(f"Total rules tested: {all_results['summary']['total_rules_tested']}")
    
    if all_results["summary"]["total_bypasses_found"] > 0:
        logger.warning(f"⚠️  Found {all_results['summary']['total_bypasses_found']} potential WAF bypasses across all targets!")
        return 1
    else:
        logger.info("✅ No WAF bypasses detected across all targets.")
        return 0


if __name__ == "__main__":
    sys.exit(main()) 