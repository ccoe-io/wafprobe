"""
WAF Rules Package

This package contains rule definitions for various WAF testing scenarios,
organized by the type of service or application being tested.
"""

from rules.discovery import (
    discover_rule_modules,
    get_all_category_mappings,
    get_all_categories,
    get_module_for_category,
    get_categories_by_module,
    search_categories
)

# Import all rule modules for easier access
from rules.aws_rules import get_rules as get_aws_rules
from rules.graphql_rules import get_rules as get_graphql_rules
from rules.kubernetes_rules import get_rules as get_kubernetes_rules
from rules.documentdb_rules import get_rules as get_documentdb_rules

__all__ = [
    # Discovery functions
    'discover_rule_modules',
    'get_all_category_mappings',
    'get_all_categories',
    'get_module_for_category',
    'get_categories_by_module',
    'search_categories',
    
    # Rule getter functions
    'get_aws_rules',
    'get_graphql_rules',
    'get_kubernetes_rules',
    'get_documentdb_rules'
]
