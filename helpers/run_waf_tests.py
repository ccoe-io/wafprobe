#!/usr/bin/env python3
"""
WAF Testing Runner

This script provides a command-line interface for running WAF tests using
configuration files, making it easy for non-developers to use the tool.
"""

import os
import sys
import time
import argparse
import importlib
from typing import Any, Dict, List, Set

from core.config_loader import ConfigLoader
from core.engine import WafBypassDetector, WafRule, WafBypassReport

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run WAF bypass tests using a configuration file")
    parser.add_argument("-c", "--config", help="Path to the YAML configuration file")
    parser.add_argument("-t", "--target", help="Override target URL from configuration")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--list-rules", action="store_true", help="List available rules and exit")
    args = parser.parse_args()
    
    # Require config file only if not listing rules
    if not args.list_rules and not args.config:
        parser.error("the following arguments are required: -c/--config")
    
    return args

def load_rules(rule_names: Set[str], rule_filters: List[str] = None) -> List[WafRule]:
    """
    Load rule modules and instantiate WAF rules.
    
    Args:
        rule_names: Set of rule names to load (module names)
        rule_filters: Optional list of specific rule names to filter by
        
    Returns:
        List of WafRule instances
    """
    all_rules = []
    
    # Find the rules directory relative to the current script
    base_dir = os.path.dirname(os.path.abspath(__file__))
    rules_dir = os.path.join(base_dir, "rules")
    
    # Add rules directory to path for importing
    sys.path.insert(0, base_dir)
    
    # Load each rule module and get rules
    for module_name in rule_names:
        try:
            # Import the rule module
            full_module_name = f"rules.{module_name}"
            module = importlib.import_module(full_module_name)
            
            # Look for a get_rules function
            if hasattr(module, "get_rules"):
                module_rules = module.get_rules()
                if isinstance(module_rules, list):
                    all_rules.extend(module_rules)
                else:
                    all_rules.append(module_rules)
            else:
                print(f"Warning: Rule module {module_name} does not have a get_rules function")
        except ImportError as e:
            print(f"Error importing rule {module_name}: {e}")
        except Exception as e:
            print(f"Error loading rules from {module_name}: {e}")
    
    # If rule_filters is provided, filter rules by name
    if rule_filters:
        filtered_rules = []
        rule_filter_set = set(rule_filters)
        
        # Log the rules we're looking for
        print(f"Filtering for specific rules: {', '.join(rule_filter_set)}")
        
        for rule in all_rules:
            if rule.name in rule_filter_set:
                filtered_rules.append(rule)
                print(f"  ✓ Found rule: {rule.name}")
        
        if not filtered_rules:
            print("  ⚠️ No matching rules found. Available rules:")
            for rule in all_rules:
                print(f"    - {rule.name}")
        
        return filtered_rules
    
    return all_rules

def list_available_rules():
    """List all available rules and their descriptions."""
    # Find the rules directory relative to the current script
    base_dir = os.path.dirname(os.path.abspath(__file__))
    rules_dir = os.path.join(base_dir, "rules")
    
    # Add rules directory to path for importing
    sys.path.insert(0, base_dir)
    
    print("Available WAF test rules:")
    print("========================")
    
    # Check if rules directory exists
    if not os.path.exists(rules_dir):
        print("No rules directory found")
        return
    
    # Look for rule modules
    for file in sorted(os.listdir(rules_dir)):
        if file.endswith(".py") and not file.startswith("__"):
            rule_name = file[:-3]  # Remove .py extension
            try:
                # Import the rule module
                module_name = f"rules.{rule_name}"
                module = importlib.import_module(module_name)
                
                # Get module description
                description = getattr(module, "__doc__", "No description available").strip()
                
                # Look for a get_rules function to count rules
                rule_count = 0
                if hasattr(module, "get_rules"):
                    rules = module.get_rules()
                    if isinstance(rules, list):
                        rule_count = len(rules)
                    else:
                        rule_count = 1
                
                print(f"- {rule_name}: {description} ({rule_count} rules)")
                
                # List individual rules if verbose
                if hasattr(module, "get_rules"):
                    rules = module.get_rules()
                    if not isinstance(rules, list):
                        rules = [rules]
                    
                    for rule in rules:
                        # Get vector count
                        vector_count = len(rule.test_vectors) if hasattr(rule, "test_vectors") else "Unknown"
                        
                        # Get request components
                        components = ", ".join(rule.request_components) if hasattr(rule, "request_components") else "Unknown"
                        
                        print(f"  - {rule.name}: {rule.description}")
                        print(f"    Components: {components}")
                        print(f"    Test vectors: {vector_count}")
                        print()
            except ImportError as e:
                print(f"- {rule_name}: Error importing module: {e}")
            except Exception as e:
                print(f"- {rule_name}: Error: {e}")

def generate_reports(detector, output_options, target_name=None):
    """
    Generate reports based on the configuration.
    
    Args:
        detector: WafBypassDetector instance with results
        output_options: Output configuration options
        target_name: Optional name of the target for report naming
    """
    report_dir = output_options.get("report_dir")
    formats = output_options.get("formats", ["json"])
    
    # Create report directory if it doesn't exist and is specified
    if report_dir:
        # Make sure we're not creating a nested reports dir
        if report_dir.startswith("reports/"):
            full_report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), report_dir)
        else:
            full_report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports", report_dir)
        
        # Create all directories in the path
        os.makedirs(full_report_dir, exist_ok=True)
        
        # Update report_dir to the full path
        report_dir = full_report_dir
        
        print(f"Reports will be saved to: {report_dir}")
    
    # Create a sanitized target identifier for filenames (remove special chars)
    if target_name:
        sanitized_target = ''.join(c if c.isalnum() else '_' for c in target_name)
        sanitized_target = sanitized_target[:30]  # Limit length
    else:
        # Extract domain from URL if no name provided
        url = detector.target_url
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc.replace('.', '_')
            sanitized_target = domain[:30]
        except:
            sanitized_target = "target"
    
    # Generate timestamp
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    
    # Generate reports in each requested format
    for fmt in formats:
        if fmt == "json":
            # Save JSON results
            json_filename = f"results_{sanitized_target}_{timestamp}.json"
            json_file = os.path.join(report_dir, json_filename) if report_dir else None
            
            if json_file:
                try:
                    detector.save_results(json_file)
                    print(f"JSON report saved to: {json_file}")
                except Exception as e:
                    print(f"Error saving JSON report: {e}")
        
        elif fmt == "html":
            # Generate HTML report
            html_filename = f"waf_report_{sanitized_target}_{timestamp}.html"
            html_file = os.path.join(report_dir, html_filename) if report_dir else None
            
            if html_file:
                try:
                    # Ensure proper HTML report generation
                    from core.report_generator import generate_html_report
                    
                    # Use the more reliable generator instead of the WafBypassReport class
                    generate_html_report(detector.results, detector.target_url, html_file)
                    print(f"HTML report saved to: {html_file}")
                except ImportError:
                    # Fallback to original method
                    try:
                        WafBypassReport.generate_html_report(detector.results, html_file)
                        print(f"HTML report saved to: {html_file}")
                    except Exception as e:
                        print(f"Error generating HTML report: {e}")
                except Exception as e:
                    print(f"Error generating HTML report: {e}")
        
        elif fmt == "markdown":
            # Generate markdown recommendations
            md_filename = f"waf_recommendations_{sanitized_target}_{timestamp}.md"
            md_file = os.path.join(report_dir, md_filename) if report_dir else None
            
            if md_file:
                try:
                    detector.save_recommendations(md_file)
                    print(f"Markdown report saved to: {md_file}")
                except Exception as e:
                    print(f"Error saving markdown report: {e}")
        
        elif fmt == "text":
            # Display text results (already done by display_results)
            pass

def main():
    """Main entry point for the script."""
    # Parse command line arguments
    args = parse_arguments()
    
    # List available rules if requested
    if args.list_rules:
        list_available_rules()
        return
    
    try:
        # Load configuration
        print(f"Loading configuration from {args.config}")
        loader = ConfigLoader(args.config)
        config = loader.load()
        
        # Get configuration values
        target_urls = loader.get_target_urls()
        execution_options = loader.get_execution_options()
        output_options = loader.get_output_options()
        
        # Override target URL if specified
        if args.target:
            target_urls = [args.target]
            
        # Override verbose flag if specified
        if args.verbose:
            execution_options["verbose"] = True
        
        # Test each target
        for i, target_url in enumerate(target_urls):
            print(f"\nTesting target: {target_url}")
            
            # Get target name for report naming
            target_name = None
            try:
                targets_config = config.get("targets", [])
                if i < len(targets_config):
                    target_name = targets_config[i].get("name")
            except:
                pass
            
            # Get target-specific rules if multiple targets, otherwise use selected rules
            if args.target:
                # If a specific target was specified via command line, use global rules
                module_names = loader.get_selected_rules()
                rule_filters = loader.get_selected_rule_names()
            else:
                # Use target-specific rules
                module_names = loader.get_target_rules(i)
                rule_filters = loader.get_target_rule_names(i)
            
            # Load rules for this target
            print(f"Loading rules from {len(module_names)} module(s)...")
            rules = load_rules(module_names, rule_filters)
            print(f"Loaded {len(rules)} WAF test rules")
            
            # Create detector
            detector = WafBypassDetector(target_url, verbose=execution_options["verbose"])
            
            # Set execution options
            detector.timeout = execution_options["timeout"]
            detector.delay = execution_options["delay"]
            detector.workers = execution_options["workers"]
            
            # Set rules
            detector.rules = rules
            
            # Start time
            start_time = time.time()
            
            # Run tests
            detector.run_tests()
            
            # End time
            end_time = time.time()
            test_time = end_time - start_time
            
            # Display results
            detector.display_results()
            
            # Print execution time
            print(f"\nTesting completed in {test_time:.2f} seconds")
            
            # Generate reports
            generate_reports(detector, output_options, target_name)
    
    except KeyboardInterrupt:
        print("\nTesting interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 