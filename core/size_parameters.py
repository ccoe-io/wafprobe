#!/usr/bin/env python3
"""
Size Parameters Module

This module provides configuration parameters for size restriction testing.
It helps determine if WAF rules are properly enforcing size limits.
"""

class SizeTestParameters:
    """Configuration parameters for size restriction testing."""
    
    def __init__(self, 
                 max_body_size: int = 8192,      # 8KB default
                 max_query_size: int = 4096,     # 4KB default
                 max_cookie_size: int = 4096,    # 4KB default
                 max_uri_size: int = 2048,       # 2KB default
                 size_step: int = 1024,          # 1KB step
                 threshold_multiplier: float = 1.5):  # Test 1.5x the limit
        """
        Initialize size test parameters.
        
        Args:
            max_body_size: Maximum allowed body size in bytes
            max_query_size: Maximum allowed query string size in bytes
            max_cookie_size: Maximum allowed cookie size in bytes
            max_uri_size: Maximum allowed URI path size in bytes
            size_step: Size increment for testing in bytes
            threshold_multiplier: Multiple of max size to test (e.g., 1.5x the limit)
        """
        self.max_body_size = max_body_size
        self.max_query_size = max_query_size
        self.max_cookie_size = max_cookie_size
        self.max_uri_size = max_uri_size
        self.size_step = size_step
        self.threshold_multiplier = threshold_multiplier
    
    def get_max_size_for_component(self, component: str) -> int:
        """
        Get the maximum allowed size for a specific request component.
        
        Args:
            component: The request component (body, querystring, cookie, uri)
            
        Returns:
            Maximum allowed size in bytes
        """
        component = component.lower()
        if component == "body":
            return self.max_body_size
        elif component == "querystring":
            return self.max_query_size
        elif component == "cookie":
            return self.max_cookie_size
        elif component == "uri":
            return self.max_uri_size
        else:
            # Default to lowest size for unknown components
            return min(self.max_body_size, self.max_query_size, 
                      self.max_cookie_size, self.max_uri_size)
    
    def create_size_test_vectors(self, component: str) -> list:
        """
        Create size test vectors for a specific component.
        
        Args:
            component: The request component (body, querystring, cookie, uri)
            
        Returns:
            List of test vectors with various sizes
        """
        max_size = self.get_max_size_for_component(component)
        vectors = []
        
        # Test at various sizes relative to the limit
        sizes_to_test = [
            max_size // 2,              # Half the limit
            max_size - self.size_step,  # Just under the limit
            max_size,                   # At the limit
            max_size + self.size_step,  # Just over the limit
            int(max_size * self.threshold_multiplier)  # Well over the limit
        ]
        
        for size in sizes_to_test:
            # For querystring, prepend with "?" to make it a valid query
            if component.lower() == "querystring":
                vectors.append("?" + "A" * size)
            # For cookie, create a cookie dict
            elif component.lower() == "cookie":
                vectors.append({"Cookie": "test=" + "A" * size})
            # For other components, just create a string of the right length
            else:
                vectors.append("A" * size)
        
        return vectors