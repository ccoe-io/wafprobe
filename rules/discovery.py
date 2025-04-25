#!/usr/bin/env python3
"""
WAF Rules Discovery Module

This module provides functions to discover and explore all available WAF rule 
categories and modules in the testing system. It centralizes access to rule 
categories across all rule modules (AWS, GraphQL, Kubernetes, DocumentDB, etc.)
"""

from typing import Dict, List, Set, Tuple
import importlib
import sys
import os
import glob
import re

# Add parent directory to path to allow imports from core module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# List of rule modules to import dynamically
RULE_MODULES = [
    "aws_rules",
    "graphql_rules",
    "kubernetes_rules",
    "documentdb_rules"
]

def discover_rule_modules() -> List[str]:
    """
    Dynamically discover all rule modules in the rules directory.
    
    Returns:
        List of module names (without the .py extension)
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    module_files = glob.glob(os.path.join(current_dir, "*.py"))
    
    modules = []
    for file_path in module_files:
        filename = os.path.basename(file_path)
        # Skip __init__.py, discovery.py, and any non-rules modules
        if (filename != "__init__.py" and 
            filename != "discovery.py" and
            "_rules.py" in filename):
            module_name = filename.replace(".py", "")
            modules.append(module_name)
    
    return modules

def get_all_category_mappings() -> Dict[str, Tuple[str, str]]:
    """
    Get all category mappings from all rule modules.
    
    Returns:
        Dictionary mapping category keywords to tuples of (rule pattern, module name)
    """
    all_mappings = {}
    rule_modules = discover_rule_modules()
    
    for module_name in rule_modules:
        try:
            module = importlib.import_module(f"rules.{module_name}")
            if hasattr(module, "get_category_mappings"):
                module_mappings = module.get_category_mappings()
                
                # Add module name to each mapping
                for key, pattern in module_mappings.items():
                    # If category already exists, append the new pattern
                    if key in all_mappings:
                        # Skip duplicate mappings
                        if all_mappings[key][0] == pattern:
                            continue
                        # Handle conflicts by creating slightly more specific keys
                        new_key = f"{key}_{module_name.replace('_rules', '')}"
                        all_mappings[new_key] = (pattern, module_name)
                    else:
                        all_mappings[key] = (pattern, module_name)
        except (ImportError, AttributeError) as e:
            # Skip modules that don't have category mappings
            print(f"Warning: Could not import mappings from {module_name}: {e}")
            
    return all_mappings

def get_all_categories() -> Dict[str, Tuple[str, str]]:
    """
    Get all categories from all rule modules.
    
    Returns:
        Dictionary mapping category names to tuples of (description, module name)
    """
    all_categories = {}
    rule_modules = discover_rule_modules()
    
    for module_name in rule_modules:
        try:
            module = importlib.import_module(f"rules.{module_name}")
            if hasattr(module, "get_categories"):
                module_categories = module.get_categories()
                
                # Add module name to each category
                for key, description in module_categories.items():
                    # If category already exists, append the new description
                    if key in all_categories:
                        # Skip duplicate descriptions
                        if all_categories[key][0] == description:
                            continue
                        # Handle conflicts by creating slightly more specific keys
                        new_key = f"{key}_{module_name.replace('_rules', '')}"
                        all_categories[new_key] = (description, module_name)
                    else:
                        all_categories[key] = (description, module_name)
        except (ImportError, AttributeError) as e:
            # Skip modules that don't have categories
            print(f"Warning: Could not import categories from {module_name}: {e}")
            
    return all_categories

def get_module_for_category(category: str) -> str:
    """
    Get the module name for a given category.
    
    Args:
        category: The category name to look up
        
    Returns:
        The module name that contains the category, or None if not found
    """
    all_categories = get_all_categories()
    
    # Check for direct match
    if category in all_categories:
        return all_categories[category][1]
    
    # Check for partial match
    for cat, (_, module) in all_categories.items():
        if category.lower() in cat.lower():
            return module
    
    return None

def get_categories_by_module() -> Dict[str, Dict[str, str]]:
    """
    Get all categories organized by module.
    
    Returns:
        Dictionary mapping module names to their category dictionaries
    """
    module_categories = {}
    rule_modules = discover_rule_modules()
    
    for module_name in rule_modules:
        try:
            module = importlib.import_module(f"rules.{module_name}")
            if hasattr(module, "get_categories"):
                module_categories[module_name] = module.get_categories()
        except (ImportError, AttributeError) as e:
            # Skip modules that don't have categories
            print(f"Warning: Could not import categories from {module_name}: {e}")
            
    return module_categories

def search_categories(search_term: str) -> Dict[str, Tuple[str, str]]:
    """
    Search all categories using a search term.
    
    Args:
        search_term: Term to search for in category names and descriptions
        
    Returns:
        Dictionary of matching categories with (description, module) tuples
    """
    all_categories = get_all_categories()
    results = {}
    
    # Create regex for more flexible matching
    pattern = re.compile(search_term, re.IGNORECASE)
    
    for category, (description, module) in all_categories.items():
        if (pattern.search(category) or pattern.search(description)):
            results[category] = (description, module)
            
    return results

if __name__ == "__main__":
    # If run directly, print all available categories
    print("Discovered rule modules:")
    for module in discover_rule_modules():
        print(f"  - {module}")
    
    all_categories = get_all_categories()
    print(f"\nTotal categories available: {len(all_categories)}")
    
    # Print categories by module
    module_categories = get_categories_by_module()
    for module, categories in module_categories.items():
        print(f"\n{module.replace('_rules', '').upper()} Categories:")
        for cat_name, description in categories.items():
            print(f"  - {cat_name}: {description}") 