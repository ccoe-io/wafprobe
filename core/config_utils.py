#!/usr/bin/env python3
"""
Configuration Utilities for WAF Testing

This module provides utility functions for processing configuration files
including environment variable substitution.
"""

import os
import re
import logging
from typing import Any, Dict, List, Union

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("config_utils")

# Regex pattern to match ${VAR_NAME} in strings
ENV_VAR_PATTERN = re.compile(r'\${([A-Za-z0-9_]+)}')

def substitute_env_vars(value: Any) -> Any:
    """
    Recursively substitute environment variables in configuration values.
    
    Supports the ${VAR_NAME} syntax for environment variable substitution.
    If the environment variable is not found, the original value is kept.
    
    Args:
        value: The value to process for environment variable substitution
        
    Returns:
        The value with environment variables substituted
    """
    if isinstance(value, str):
        # Process string values
        def replace_env_var(match):
            var_name = match.group(1)
            env_value = os.environ.get(var_name)
            if env_value is None:
                logger.warning(f"Environment variable '{var_name}' not found, using original value")
                return match.group(0)  # Return the original ${VAR_NAME}
            return env_value
        
        return ENV_VAR_PATTERN.sub(replace_env_var, value)
    
    elif isinstance(value, list):
        # Process list values recursively
        return [substitute_env_vars(item) for item in value]
    
    elif isinstance(value, dict):
        # Process dictionary values recursively
        return {k: substitute_env_vars(v) for k, v in value.items()}
    
    # For other types (int, bool, etc.), return as is
    return value

def process_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process a configuration dictionary, applying all transformations.
    
    Currently only handles environment variable substitution, but can be
    extended to handle other transformations.
    
    Args:
        config: The configuration dictionary to process
        
    Returns:
        The processed configuration dictionary
    """
    logger.debug("Processing configuration...")
    return substitute_env_vars(config) 