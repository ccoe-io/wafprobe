#!/usr/bin/env python3
"""
Test Environment Variable Substitution

This script demonstrates how environment variables can be used in WAF testing
configuration files.
"""

import os
import sys
import yaml
import logging

# Add the parent directory to the sys.path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import our config utilities
from core.config_utils import process_config

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("test_env_vars")

# Example configuration with environment variables
EXAMPLE_CONFIG = """
global:
  workers: 4
  verbose: ${DEBUG_MODE}
  report_dir: "${REPORT_DIR}"

targets:
  - url: "${API_URL}"
    name: "Test API"
    description: "Environment variable test target"
    
    request:
      headers:
        Authorization: "Bearer ${API_TOKEN}"
        Content-Type: "application/json"
      
      auth:
        username: "${DB_USERNAME}"
        password: "${DB_PASSWORD}"
"""

def main():
    """Test environment variable substitution in configuration."""
    # Set some environment variables for testing
    os.environ["DEBUG_MODE"] = "true"
    os.environ["REPORT_DIR"] = "./reports/env_var_test"
    os.environ["API_URL"] = "https://example.com/api"
    os.environ["API_TOKEN"] = "test-token-123"
    os.environ["DB_USERNAME"] = "testuser"
    os.environ["DB_PASSWORD"] = "testpass"
    
    # Parse the example configuration
    config = yaml.safe_load(EXAMPLE_CONFIG)
    
    # Show the original configuration
    logger.info("Original configuration:")
    logger.info(yaml.dump(config, default_flow_style=False))
    
    # Process the configuration with environment variable substitution
    processed_config = process_config(config)
    
    # Show the processed configuration
    logger.info("\nProcessed configuration with environment variables:")
    logger.info(yaml.dump(processed_config, default_flow_style=False))
    
    # Test with a missing environment variable
    logger.info("\nTesting with a missing environment variable:")
    test_config = yaml.safe_load('{"test": "${MISSING_VAR}"}')
    processed_test = process_config(test_config)
    logger.info(yaml.dump(processed_test, default_flow_style=False))
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 