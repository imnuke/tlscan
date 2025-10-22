import os
import sys
import json
import asyncio
from langchain.chat_models import init_chat_model
from langchain_core.tools import tool
from langchain.agents import create_agent
from langchain_mcp_adapters.client import MultiServerMCPClient

DEEPSEEK_KEY = "sk-1bd3cd5c4a164b51ababb4529a68305d"
os.environ["DEEPSEEK_API_KEY"] = DEEPSEEK_KEY

CERTIFICATE_SECURITY_RULES = """
## Certificate Validation Security Rules with Verification & Exploitation

You are a security analyst examining a custom certificate validation function for vulnerabilities to MITM attacks.
Analyze the function systematically against these security rules. For each rule, provide:
1. PASS/FAIL status
2. Evidence from the pseudocode
3. Specific line numbers and function names
4. **VERIFICATION**: How to test this vulnerability
5. **EXPLOITATION**: Attack methods if rule fails
6. **IMPACT**: Security consequences

### CRITICAL SECURITY RULES (Must ALL pass to be secure):

**RULE 1: Signature Verification**
- PASS: Function verifies certificate signature using RSA (≥2048 bits) or ECDSA (≥256 bits)
- PASS: Uses secure hash algorithms (SHA-256, SHA-384, SHA-512)
- FAIL: Uses weak algorithms (MD5, SHA-1, RSA <2048 bits)
- FAIL: Skips signature verification entirely

**VERIFICATION**: Present self-signed or unsigned certificate
- Create fake certificate: `openssl req -x509 -newkey rsa:2048 -keyout fake.key -out fake.crt -days 365 -nodes`
- Test with modified certificate signature
- Use certificate with invalid signature

**EXPLOITATION**: Certificate forgery attacks
- Attacker creates fake certificates for any domain
- Impersonation of legitimate services
- Complete bypass of certificate authenticity

**IMPACT**: Complete MITM vulnerability - attacker can forge certificates for any domain

**RULE 2: Certificate Chain Validation**
- PASS: Validates full certificate chain to trusted root CA
- PASS: Checks intermediate certificates properly
- PASS: Enforces path length constraints
- FAIL: Only validates leaf certificate
- FAIL: Accepts self-signed certificates without proper validation

**VERIFICATION**: Present certificate without valid chain
- Create self-signed CA: `openssl req -x509 -new -key ca.key -out ca.crt -days 365`
- Generate leaf cert from untrusted CA
- Test with missing intermediate certificates

**EXPLOITATION**: Rogue CA attacks
- Attacker creates malicious root CA
- Issues certificates for any domain
- Certificate pinning bypass

**IMPACT**: Attacker can create trusted certificates for any domain using rogue CA

**RULE 3: Critical Extension Handling**
- PASS: Properly validates Key Usage extension
- PASS: Checks Basic Constraints for CA certificates
- PASS: Validates Subject Alternative Names (SAN)
- FAIL: Ignores critical extensions
- FAIL: Accepts certificates with incorrect key usage

**VERIFICATION**: Certificate with malicious extensions
- Create cert with basicConstraints:CA=TRUE on leaf certificate
- Generate cert with keyUsage allowing certificate signing
- Test certificate without proper SAN for target domain

**EXPLOITATION**: Certificate authority privilege escalation
- Leaf certificate used as CA to sign other certificates
- Unauthorized certificate issuance
- Domain validation bypass

**IMPACT**: Attacker can create certificate authority from compromised leaf certificate

**RULE 4: Revocation Checking**
- PASS: Implements CRL (Certificate Revocation List) checking
- PASS: Implements OCSP (Online Certificate Status Protocol) checking
- WARN: Has revocation checking but allows soft failures
- FAIL: No revocation checking implemented

**VERIFICATION**: Present revoked certificate
- Check against CRL: `openssl crl -in crl.pem -text -noout`
- Test OCSP response: `openssl ocsp -issuer ca.crt -cert cert.pem -url http://ocsp.example.com`
- Use known revoked certificate

**EXPLOITATION**: Use of compromised certificates
- Attacker uses stolen/compromised private keys
- Certificates remain accepted after revocation
- Long-term certificate abuse

**IMPACT**: Compromised certificates remain trusted indefinitely

**RULE 5: Trust Store Management**
- PASS: Uses properly configured root certificate store
- PASS: Validates against known trusted CAs only
- FAIL: Accepts any certificate without trust validation
- FAIL: Uses hardcoded or weak trust anchors

**VERIFICATION**: Present certificate from untrusted CA
- Create custom root CA not in system trust store
- Test with certificate from unknown CA
- Check if application accepts any root certificate

**EXPLOITATION**: Rogue certificate authority
- Attacker creates fake root CA
- All certificates from fake CA are trusted
- Complete trust model bypass

**IMPACT**: Any certificate from attacker-controlled CA will be trusted

**RULE 6: Time-based Validation**
- PASS: Checks certificate validity period (notBefore/notAfter)
- PASS: Uses secure time source
- FAIL: Ignores certificate expiration
- FAIL: Uses system time without validation

**VERIFICATION**: Present expired/future certificate
- Create expired certificate: `openssl req -x509 -not_after 20200101000000Z`
- Test with certificate valid in future only
- Use certificate with notBefore > current time

**EXPLOITATION**: Replay attacks with old certificates
- Use of expired certificates with known compromised keys
- Time-based attacks on certificate validation
- Certificate validity period bypass

**IMPACT**: Compromised old certificates remain usable indefinitely

**RULE 7: Hostname Verification**
- PASS: Validates certificate subject matches expected hostname
- PASS: Properly handles wildcard certificates
- PASS: Checks Subject Alternative Names (SAN)
- FAIL: Skips hostname verification
- FAIL: Improper wildcard handling allowing subdomain attacks

**VERIFICATION**: Present certificate for wrong domain
- Create certificate for attacker.com, use for victim.com
- Test wildcard certificate abuse: *.evil.com used for victim.evil.com
- Generate certificate without SAN for target domain

**EXPLOITATION**: Domain spoofing attacks
- Certificate for attacker-controlled domain accepted for any domain
- DNS hijacking amplification
- Subdomain takeover attacks

**IMPACT**: Any valid certificate can be used to impersonate any domain

**RULE 8: Error Handling**
- PASS: Fails securely on validation errors
- PASS: Proper error propagation without information leakage
- FAIL: Continues on validation failures
- FAIL: Improper error handling that could be exploited

**VERIFICATION**: Trigger validation errors
- Send malformed certificates
- Cause network timeouts during validation
- Test with corrupted certificate data

**EXPLOITATION**: Information leakage and bypass
- Error messages reveal internal certificate validation logic
- Validation failures ignored, allowing invalid certificates
- Timing attacks on certificate validation

**IMPACT**: Validation bypass through error conditions, information disclosure

### ANALYSIS METHODOLOGY:

1. Start by getting the pseudocode of the main certificate validation function
2. Identify all cryptographic operations and validation steps
3. For each helper function called, retrieve its pseudocode using IDA Pro tools
4. Check each security rule systematically
5. Look for common vulnerability patterns:
   - Return value checks being ignored
   - Weak cryptographic constants
   - Missing validation steps
   - Improper error handling

### REQUIRED TOOLS USAGE:
- Use `decompile_function` to get pseudocode of target function
- Use `get_xrefs_to` to find where validation functions are called
- Use `get_function_by_name` for analyzing helper functions
- Add comments with `set_comment` to mark your findings

### ENHANCED OUTPUT FORMAT:
For each rule, provide:
```
RULE X: [Rule Name]
Status: PASS/FAIL/WARN
Evidence: [Specific pseudocode lines and explanation]
Function: [Function name and line numbers]
Verification: [How to test this vulnerability]
Exploitation: [Attack methods if rule fails]
Impact: [Security consequences]
```

### ADDITIONAL ANALYSIS SECTIONS:
After rule-by-rule analysis, provide:

**VULNERABILITY VERIFICATION PLAN:**
- Step-by-step testing approach for identified vulnerabilities
- Specific commands and tools needed
- Expected results for each test

**ATTACK SCENARIOS:**
- Realistic exploitation scenarios combining multiple vulnerabilities
- MITM attack chains possible with this implementation
- Required attacker capabilities and positioning

**PROOF-OF-CONCEPT COMMANDS:**
- OpenSSL commands to create malicious certificates
- curl/wget commands to test certificate validation
- Network testing approaches

**REMEDIATION GUIDANCE:**
- Specific code changes needed for each failed rule
- Best practices for secure certificate validation
- Recommended libraries and approaches

Final Assessment: SECURE/VULNERABLE/NEEDS_REVIEW
Risk Level: LOW/MEDIUM/HIGH/CRITICAL
"""

async def main():
    if len(sys.argv) < 2:
        print("Usage: python demo.py <function_name>")
        print("Example: python demo.py verify_certificate")
        sys.exit(1)

    function_name = sys.argv[1]

    try:
        client = MultiServerMCPClient(
            {
                "idapro": {
                    "transport": "sse",
                    "url": "http://localhost:8745/sse"
                }
            }
        )

        tools = await client.get_tools()
        print(f"Successfully loaded {len(tools)} tools from MCP server")
    except Exception as e:
        print(f"Failed to connect to MCP server: {e}")
        print("Using fallback tools instead...")
        tools = []

    agent = create_agent(
        model="deepseek-chat",
        tools=tools,
        prompt=CERTIFICATE_SECURITY_RULES
    )

    analysis_request = f"""
    Analyze the certificate validation function '{function_name}' for security vulnerabilities that could allow MITM attacks.

    IMPORTANT: For each failed rule, provide specific verification and exploitation methods.

    Follow these steps:
    1. Get the pseudocode for function '{function_name}' using the decompile_function tool
    2. Analyze the function against each of the 8 security rules systematically
    3. For each rule, provide: Status, Evidence, Function reference, Verification method, Exploitation approach, Impact
    4. For any helper functions called, retrieve their pseudocode and analyze them too if necessary
    5. Provide comprehensive additional sections: Vulnerability Verification Plan, Attack Scenarios, Proof-of-Concept Commands, Remediation Guidance
    6. Give a final security assessment with specific testing recommendations

    Focus on practical verification methods and realistic attack scenarios. Be specific with OpenSSL commands and testing approaches.

    Start your analysis now.
    """

    out = await agent.ainvoke({
        "messages": [{"role": "user", "content": analysis_request}],
    })

    print(json.dumps(out, indent=2, default=str))

if __name__ == "__main__":
    asyncio.run(main())
