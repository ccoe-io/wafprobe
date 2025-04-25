#!/usr/bin/env python3
"""
WAF Testing Configuration Loader

This module provides functionality to load and validate configuration files
for WAF testing, allowing users to specify targets, rules, and options in YAML.
"""

import os
import sys
import yaml
import logging
from typing import Any, Dict, List, Optional, Set

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("ConfigLoader")

class ConfigLoader:
    """
    Loads and validates configuration files for WAF testing.
    """
    
    def __init__(self, config_file: str):
        """
        Initialize the configuration loader.
        
        Args:
            config_file: Path to the configuration file
        """
        self.config_file = config_file
        self.config = {}
        self.available_rules = set()
        self._load_available_rules()
    
    def _load_available_rules(self) -> None:
        """
        Load information about available WAF rules from the rules directory.
        """
        # Find the rules directory relative to the current script
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        rules_dir = os.path.join(base_dir, "rules")
        
        if not os.path.exists(rules_dir):
            logger.warning(f"Rules directory not found: {rules_dir}")
            return
        
        # Search for Python rule files
        for file in os.listdir(rules_dir):
            if file.endswith(".py") and not file.startswith("__"):
                rule_name = file[:-3]  # Remove .py extension
                self.available_rules.add(rule_name)
        
        logger.info(f"Found {len(self.available_rules)} available rules")
    
    def load(self) -> Dict[str, Any]:
        """
        Load and validate the configuration.
        
        Returns:
            Validated configuration dictionary
        
        Raises:
            ValueError: If the configuration is invalid
        """
        try:
            with open(self.config_file, 'r') as f:
                self.config = yaml.safe_load(f)
                
            # Validate the configuration
            self._validate_config()
            
            return self.config
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {self.config_file}")
            raise
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML configuration: {e}")
            raise ValueError(f"Invalid YAML in configuration file: {e}")
    
    def _validate_config(self) -> None:
        """
        Validate the loaded configuration.
        
        Raises:
            ValueError: If the configuration is invalid
        """
        if not isinstance(self.config, dict):
            raise ValueError("Configuration must be a dictionary")
        
        # Check for required sections
        required_sections = ["targets", "execution"]
        for section in required_sections:
            if section not in self.config:
                raise ValueError(f"Configuration missing required section: {section}")
        
        # Validate targets
        self._validate_targets()
        
        # Validate execution options
        self._validate_execution()
        
        # Validate rules if specified
        if "rules" in self.config:
            self._validate_rules()
        
        # Validate output options if specified
        if "output" in self.config:
            self._validate_output()
    
    def _validate_targets(self) -> None:
        """
        Validate the targets section of the configuration.
        
        Raises:
            ValueError: If the targets configuration is invalid
        """
        targets = self.config.get("targets", [])
        
        if not isinstance(targets, list):
            raise ValueError("Targets must be a list")
        
        if not targets:
            raise ValueError("At least one target URL must be specified")
        
        for i, target in enumerate(targets):
            if not isinstance(target, dict):
                raise ValueError(f"Target #{i+1} must be a dictionary")
            
            if "url" not in target:
                raise ValueError(f"Target #{i+1} missing required 'url' field")
            
            if not isinstance(target["url"], str):
                raise ValueError(f"URL for target #{i+1} must be a string")
            
            # Check for valid URL format (basic validation)
            if not target["url"].startswith("http://") and not target["url"].startswith("https://"):
                raise ValueError(f"URL for target #{i+1} must start with http:// or https://")
            
            # Validate target-specific rules if present
            if "rules" in target:
                self._validate_rule_config(target["rules"], f"Target #{i+1}")
    
    def _validate_execution(self) -> None:
        """
        Validate the execution section of the configuration.
        
        Raises:
            ValueError: If the execution configuration is invalid
        """
        execution = self.config.get("execution", {})
        
        if not isinstance(execution, dict):
            raise ValueError("Execution configuration must be a dictionary")
        
        # Validate timeout
        if "timeout" in execution:
            if not isinstance(execution["timeout"], (int, float)):
                raise ValueError("Timeout must be a number")
            if execution["timeout"] <= 0:
                raise ValueError("Timeout must be positive")
        
        # Validate delay
        if "delay" in execution:
            if not isinstance(execution["delay"], (int, float)):
                raise ValueError("Delay must be a number")
            if execution["delay"] < 0:
                raise ValueError("Delay cannot be negative")
        
        # Validate workers
        if "workers" in execution:
            if not isinstance(execution["workers"], int):
                raise ValueError("Number of workers must be an integer")
            if execution["workers"] <= 0:
                raise ValueError("Number of workers must be positive")
        
        # Validate verbose flag
        if "verbose" in execution:
            if not isinstance(execution["verbose"], bool):
                raise ValueError("Verbose flag must be a boolean")
    
    def _validate_rules(self) -> None:
        """
        Validate the rules section of the configuration.
        
        Raises:
            ValueError: If the rules configuration is invalid
        """
        rules_config = self.config.get("rules", {})
        self._validate_rule_config(rules_config, "Global")
    
    def _validate_rule_config(self, rules_config: Dict[str, Any], context: str) -> None:
        """
        Validate a rules configuration section.
        
        Args:
            rules_config: The rules configuration dictionary
            context: Context description for error messages (e.g., "Global" or "Target #1")
            
        Raises:
            ValueError: If the rules configuration is invalid
        """
        if not isinstance(rules_config, dict):
            raise ValueError(f"{context} rules configuration must be a dictionary")
        
        # Validate include/exclude lists
        for list_type in ["include", "exclude"]:
            if list_type in rules_config:
                if not isinstance(rules_config[list_type], list):
                    raise ValueError(f"{context} rules {list_type} must be a list")
                
                # Check that specified rules exist
                for rule in rules_config[list_type]:
                    if rule not in self.available_rules and rule != "all":
                        logger.warning(f"Rule '{rule}' specified in {context} {list_type} list not found in available rules")
        
        # Validate rule_names list if present
        if "rule_names" in rules_config:
            if not isinstance(rules_config["rule_names"], list):
                raise ValueError(f"{context} rule_names must be a list")
            
            # We don't validate individual rule names because they depend on the loaded modules
        
        # Cannot have both include and exclude
        if "include" in rules_config and "exclude" in rules_config:
            raise ValueError(f"{context} rules cannot specify both include and exclude lists")
    
    def _validate_output(self) -> None:
        """
        Validate the output section of the configuration.
        
        Raises:
            ValueError: If the output configuration is invalid
        """
        output = self.config.get("output", {})
        
        if not isinstance(output, dict):
            raise ValueError("Output configuration must be a dictionary")
        
        # Validate report directory
        if "report_dir" in output:
            if not isinstance(output["report_dir"], str):
                raise ValueError("Report directory must be a string")
        
        # Validate report formats
        if "formats" in output:
            if not isinstance(output["formats"], list):
                raise ValueError("Report formats must be a list")
            
            valid_formats = ["json", "html", "text", "markdown"]
            for fmt in output["formats"]:
                if fmt not in valid_formats:
                    raise ValueError(f"Invalid report format: {fmt}. Valid formats are: {', '.join(valid_formats)}")
    
    def get_target_urls(self) -> List[str]:
        """
        Get the list of target URLs from the configuration.
        
        Returns:
            List of target URLs
        """
        if not self.config:
            raise ValueError("Configuration not loaded")
        
        targets = self.config.get("targets", [])
        return [target["url"] for target in targets]
    
    def get_target_rules(self, target_index: int) -> Set[str]:
        """
        Get the set of rules to run for a specific target.
        
        Args:
            target_index: Index of the target in the targets list
            
        Returns:
            Set of rule names to run for this target
        """
        if not self.config:
            raise ValueError("Configuration not loaded")
        
        targets = self.config.get("targets", [])
        if target_index >= len(targets):
            raise ValueError(f"Target index {target_index} out of range")
        
        target = targets[target_index]
        
        # If target has specific rules, use those
        if "rules" in target:
            return self._get_rules_from_config(target["rules"])
        
        # Otherwise use global rules
        return self.get_selected_rules()
    
    def get_selected_rules(self) -> Set[str]:
        """
        Get the set of rules to run based on global include/exclude lists.
        
        Returns:
            Set of rule names to run
        """
        if not self.config:
            raise ValueError("Configuration not loaded")
        
        rules_config = self.config.get("rules", {})
        return self._get_rules_from_config(rules_config)
    
    def _get_rules_from_config(self, rules_config: Dict[str, Any]) -> Set[str]:
        """
        Get the set of rules to run based on include/exclude lists.
        
        Args:
            rules_config: Rules configuration dictionary
            
        Returns:
            Set of rule names to run
        """
        # Default to all rules if not specified
        if not rules_config:
            return self.available_rules
        
        # Handle include list
        if "include" in rules_config:
            includes = set(rules_config["include"])
            if "all" in includes:
                return self.available_rules
            return includes.intersection(self.available_rules)
        
        # Handle exclude list
        if "exclude" in rules_config:
            excludes = set(rules_config["exclude"])
            if "all" in excludes:
                return set()
            return self.available_rules - excludes
        
        # Default to all rules
        return self.available_rules
    
    def get_execution_options(self) -> Dict[str, Any]:
        """
        Get execution options from the configuration.
        
        Returns:
            Dictionary of execution options
        """
        if not self.config:
            raise ValueError("Configuration not loaded")
        
        # Get execution options with defaults
        options = {
            "timeout": 10,
            "delay": 0.1,
            "workers": 5,
            "verbose": False
        }
        
        # Update with configured values
        options.update(self.config.get("execution", {}))
        
        return options
    
    def get_output_options(self) -> Dict[str, Any]:
        """
        Get output options from the configuration.
        
        Returns:
            Dictionary of output options
        """
        if not self.config:
            raise ValueError("Configuration not loaded")
        
        # Default output options
        options = {
            "report_dir": None,
            "formats": ["json"]
        }
        
        # Update with configured values
        options.update(self.config.get("output", {}))
        
        return options
    
    def get_selected_rule_names(self) -> List[str]:
        """
        Get the list of specific rule names (not modules) to run based on global configuration.
        
        Returns:
            List of specific rule names to run
        """
        if not self.config:
            raise ValueError("Configuration not loaded")
        
        rules_config = self.config.get("rules", {})
        return rules_config.get("rule_names", [])
    
    def get_target_rule_names(self, target_index: int) -> List[str]:
        """
        Get the list of specific rule names (not modules) to run for a specific target.
        
        Args:
            target_index: Index of the target in the targets list
            
        Returns:
            List of specific rule names to run for this target
        """
        if not self.config:
            raise ValueError("Configuration not loaded")
        
        targets = self.config.get("targets", [])
        if target_index >= len(targets):
            raise ValueError(f"Target index {target_index} out of range")
        
        target = targets[target_index]
        
        # If target has specific rules with rule_names, use those
        if "rules" in target and "rule_names" in target["rules"]:
            return target["rules"]["rule_names"]
        
        # Otherwise use global rule_names
        return self.get_selected_rule_names()


def load_config(config_file: str) -> Dict[str, Any]:
    """
    Load configuration from a YAML file.
    
    Args:
        config_file: Path to the configuration file
        
    Returns:
        Validated configuration dictionary
    """
    loader = ConfigLoader(config_file)
    return loader.load()


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) > 1:
        config_file = sys.argv[1]
        try:
            loader = ConfigLoader(config_file)
            config = loader.load()
            print("Configuration loaded successfully:")
            print(f"Targets: {loader.get_target_urls()}")
            print(f"Selected rules: {loader.get_selected_rules()}")
            print(f"Execution options: {loader.get_execution_options()}")
            print(f"Output options: {loader.get_output_options()}")
        except Exception as e:
            print(f"Error loading configuration: {e}")
    else:
        print("Usage: python config_loader.py <config_file>") 