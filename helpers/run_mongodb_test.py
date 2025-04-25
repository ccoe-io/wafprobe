#!/usr/bin/env python3
"""
MongoDB/DocumentDB WAF Testing Script

This script provides a convenient way to run WAF tests specifically for 
MongoDB/DocumentDB implementations using the WAF testing framework.
"""

import argparse
import os
import sys
import yaml
import logging

# Add the parent directory to the sys.path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import from the multi_waf_tester module
from runners.multi_waf_tester import (
    run_test_for_target, 
    load_config, 
    parse_arguments,
    discover_rule_modules,
    get_category_mappings
)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("run_mongodb_test")

def get_mongodb_categories():
    """Get all MongoDB/DocumentDB related categories."""
    # Start with some default MongoDB categories
    mongodb_categories = {
        "basic": "Basic NoSQL injection patterns",
        "auth": "Authentication bypass techniques",
        "extraction": "Data extraction techniques",
        "js": "JavaScript injection techniques",
        "operators": "Operator abuse techniques",
        "command": "Command injection techniques",
        "bypass": "WAF bypass techniques",
        "all": "All MongoDB/DocumentDB categories"
    }
    
    # Try to get categories from documentdb_rules module
    try:
        import importlib
        module = importlib.import_module("rules.documentdb_rules")
        if hasattr(module, 'get_categories'):
            module_categories = module.get_categories()
            # Update with module categories, but keep 'all' at the end
            all_category = mongodb_categories.pop('all')
            mongodb_categories.update(module_categories)
            mongodb_categories['all'] = all_category
    except (ImportError, Exception) as e:
        logger.warning(f"Could not load categories from documentdb_rules: {str(e)}")
    
    return mongodb_categories

def parse_mongodb_arguments():
    """Parse command line arguments specific to MongoDB testing."""
    parser = argparse.ArgumentParser(
        description="MongoDB/DocumentDB WAF Testing Script",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "--config",
        default="mongodb_waf_config.yaml",
        help="Path to the MongoDB YAML configuration file"
    )
    
    parser.add_argument(
        "--url",
        help="Override target URL in the config file"
    )
    
    # Get MongoDB categories and use them for the choices
    mongodb_categories = get_mongodb_categories()
    
    parser.add_argument(
        "--category",
        choices=list(mongodb_categories.keys()),
        default="all",
        help="Specific category of MongoDB attack vectors to test"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode"
    )

    parser.add_argument(
        "--set-env",
        action="append",
        metavar="NAME=VALUE",
        help="Set environment variables for use in the configuration file (can be specified multiple times)"
    )

    # Add listing options like in multi_waf_tester.py
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
    
    # Get available modules 
    available_modules = discover_rule_modules()
    
    list_group.add_argument(
        "--module",
        help="Specify module when listing rules or categories (e.g., 'documentdb_rules')",
        choices=available_modules if available_modules else None
    )
    
    return parser.parse_args()

def get_category_mapping(category):
    """Map user-friendly category names to the actual category names in vectors."""
    # Get category mappings dynamically
    mappings = get_category_mappings()
    
    # MongoDB-specific mappings if not already in the global mappings
    mongodb_mappings = {
        "basic": ["nosql", "basic"],
        "auth": ["authbypass", "auth_bypass"],
        "extraction": ["extraction"],
        "js": ["js_injection", "javascript"],
        "operators": ["operator_abuse", "operators"],
        "command": ["command_injection", "command"],
        "bypass": ["waf_bypass", "bypass"],
        "all": []  # Empty means all categories
    }
    
    # Use the keys from mappings that correspond to the category
    if category in mongodb_mappings:
        # For each key in mongodb_mappings[category], find corresponding values in mappings
        result = []
        for key in mongodb_mappings[category]:
            if key in mappings:
                result.append(mappings[key])
            else:
                result.append(key)
        return result
    
    # If not found in our mappings, return an empty list (means all categories)
    return []

def set_environment_variables(env_vars):
    """
    Set environment variables from command line arguments.
    
    Args:
        env_vars: List of strings in the format NAME=VALUE
    """
    if not env_vars:
        return
    
    for env_var in env_vars:
        try:
            name, value = env_var.split('=', 1)
            os.environ[name] = value
            logger.debug(f"Set environment variable {name}={value}")
        except ValueError:
            logger.warning(f"Invalid environment variable format: {env_var}. Expected NAME=VALUE")

def list_modules():
    """List all available rule modules using multi_waf_tester."""
    from runners.multi_waf_tester import list_available_modules
    list_available_modules()

def list_categories():
    """List all available categories using multi_waf_tester."""
    from runners.multi_waf_tester import list_available_categories
    list_available_categories()

def list_rules(module=None):
    """List all available rules using multi_waf_tester."""
    from runners.multi_waf_tester import list_available_rules
    list_available_rules(module)

def main():
    """Main entry point for the MongoDB WAF testing script."""
    args = parse_mongodb_arguments()
    
    # Handle listing options first
    if args.list_modules:
        list_modules()
        return 0

    if args.list_categories:
        list_categories()
        return 0

    if args.list_rules:
        list_rules(args.module)
        return 0
    
    try:
        # Set any environment variables specified on the command line
        set_environment_variables(args.set_env)
        
        # Load configuration
        config = load_config(args.config)
        
        # Update configuration with command line arguments
        if args.verbose:
            config["global"]["verbose"] = True
        
        if args.debug:
            config["global"]["debug"] = True
        
        # If URL is provided, override the first target URL
        if args.url and config["targets"]:
            config["targets"][0]["url"] = args.url
        
        # If category is provided, update the include_categories for all targets
        if args.category != "all":
            categories = get_category_mapping(args.category)
            if categories:
                for target in config["targets"]:
                    if "rules" not in target:
                        target["rules"] = {}
                    target["rules"]["include_categories"] = categories
        
        # Run the tests for each target
        results = []
        for target_config in config["targets"]:
            logger.info(f"Testing target: {target_config['name']} ({target_config['url']})")
            
            # Run the test for this target
            target_result = run_test_for_target(target_config, config)
            results.append(target_result)
            
            # Log the results summary
            if target_result.get("bypasses"):
                logger.warning(f"Found {len(target_result['bypasses'])} bypasses for {target_config['name']}")
            else:
                logger.info(f"No bypasses found for {target_config['name']}")
        
        logger.info("Testing complete!")
        
        # Return success if no bypasses found, failure otherwise
        for result in results:
            if result.get("bypasses"):
                return 1
        
        return 0
        
    except Exception as e:
        logger.error(f"Error running MongoDB WAF tests: {str(e)}", exc_info=args.debug)
        return 1

if __name__ == "__main__":
    sys.exit(main()) 