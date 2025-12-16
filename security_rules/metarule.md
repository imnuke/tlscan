# SSL/TLS Security Meta-Rules

This document defines implementation-agnostic security requirements for TLS client implementations, derived from IETF RFC specifications. These meta-rules establish the abstract security requirements that library-specific detection rules should enforce.

## RFC Selection Methodology

### Inclusion Criteria

1. **Scope**: RFC defines requirements for TLS **client** implementations (not server-only or application-specific)
2. **Normative Language**: RFC contains MUST/SHOULD/MAY requirements per RFC 2119
3. **Currency**: RFC is current (not obsoleted or superseded)
4. **Relevance**: RFC addresses core TLS client security aspects:
   - Connection establishment (TLS usage, protocol version)
   - Authentication (certificate verification, identity verification)
   - Confidentiality/Integrity (cipher suites, cryptographic strength)
   - Trust management (revocation, pinning)

### Exclusion Criteria

1. **Application-Layer**: RFCs specific to application protocols (HTTP, SMTP, etc.)
2. **Server-Only**: RFCs defining only server-side requirements
3. **Obsoleted/Superseded**: RFCs replaced by newer versions
4. **Extensions/Mechanisms**: Optional TLS extensions not addressing core security

### RFC Authority Hierarchy

1. **BCP (Best Current Practice)**: RFC 9325, RFC 8996 (BCP 195)
2. **Standards Track**: RFC 8446, RFC 5280, RFC 9525
3. **Informational**: Only when no Standards Track alternative exists

---

## Terminology

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174].

### Definitions (RFC 2119)

**MUST**: "This word, or the terms 'REQUIRED' or 'SHALL', mean that the definition is an absolute requirement of the specification."

**MUST NOT**: "This phrase, or the phrase 'SHALL NOT', mean that the definition is an absolute prohibition of the specification."

**SHOULD**: "This word, or the adjective 'RECOMMENDED', mean that there may exist valid reasons in particular circumstances to ignore a particular item, but the full implications must be understood and carefully weighed before choosing a different course."

**SHOULD NOT**: "This phrase, or the phrase 'NOT RECOMMENDED' mean that there may exist valid reasons in particular circumstances when the particular behavior is acceptable or even useful, but the full implications should be understood and the case carefully weighed."

**MAY**: "This word, or the adjective 'OPTIONAL', mean that an item is truly optional. One vendor may choose to include the item because a particular marketplace requires it or because the vendor feels that it enhances the product while another vendor may omit the same item."

---

## MUST Requirements

### M1: TLS Usage

**Priority**: MUST

**RFC Sources**: RFC 9325 Section 3.1, RFC 8446 Section 1

**Requirement**: TLS clients MUST use the TLS protocol for security-sensitive communications. TLS usage MUST NOT be conditional on factors that could be manipulated by an attacker.

**Evidence**:
- RFC 8446 §1: "TLS allows client/server applications to communicate over the Internet in a way that is designed to prevent eavesdropping, tampering, and message forgery."
- RFC 9325 §3.1: "Implementations MUST NOT negotiate SSL version 2" / "MUST NOT negotiate SSL version 3"

**Violations**:
- Establishing plaintext connections for security-sensitive data
- Conditional TLS usage that defaults to disabled
- Plaintext fallback on TLS negotiation failure (downgrade attacks)
- Opportunistic TLS without mandatory upgrade enforcement

**Rationale**: TLS provides confidentiality, integrity, and authentication. Without TLS, data is vulnerable to eavesdropping, modification, and impersonation attacks.

---

### M2: Protocol Version

**Priority**: MUST

**RFC Sources**: RFC 8996, RFC 9325 Section 3.1.1

**Requirement**: TLS clients MUST enforce minimum protocol version requirements:
- MUST NOT negotiate SSL 2.0, SSL 3.0, TLS 1.0, or TLS 1.1
- MUST support TLS 1.2
- SHOULD support and prefer TLS 1.3

**Evidence**:
- RFC 8996: "Implementations MUST NOT negotiate TLS version 1.0" / "Implementations MUST NOT negotiate TLS version 1.1"
- RFC 9325 §3.1.1: "Implementations MUST support TLS 1.2" / "Implementations SHOULD support TLS 1.3 and, if implemented, MUST prefer to negotiate TLS 1.3 over earlier versions of TLS"

**Violations**:
- Allowing negotiation of SSL 2.0, SSL 3.0, TLS 1.0, or TLS 1.1
- Not setting a minimum protocol version
- Protocol downgrade on negotiation failure

**Rationale**: Older protocol versions contain known cryptographic weaknesses. SSL 2.0/3.0 and TLS 1.0/1.1 are vulnerable to POODLE, BEAST, and various attacks. These protocols were formally deprecated by IETF in RFC 8996 (March 2021).

---

### M3: Server Certificate Verification

**Priority**: MUST

**RFC Sources**: RFC 5280 Section 6.1.3

**Requirement**: TLS clients MUST verify the server certificate. Verification MUST include:
1. **Signature validity**: The certificate signature can be verified using the issuer's public key
2. **Validity period**: The certificate validity period includes the current time
3. **Chain integrity**: Certificate chain traces to a trusted root CA
4. **Extensions**: Basic constraints and key usage extensions are valid

**Evidence**:
- RFC 5280 §6.1.3: "The certificate MUST satisfy each of the following: (1) The signature on the certificate can be verified using working_public_key_algorithm, the working_public_key, and the working_public_key_parameters. (2) The certificate validity period includes the current time. (3) At the current time, the certificate is not revoked."

**Violations**:
- Disabling certificate verification
- Ignoring certificate expiration
- Accepting self-signed certificates without explicit trust configuration
- Continuing connection after verification failure
- Using empty or invalid CA certificate stores

**Rationale**: Certificate verification is the foundation of TLS authentication. It ensures the server possesses a certificate issued by a trusted authority.

---

### M4: Server Identity Verification

**Priority**: MUST

**RFC Sources**: RFC 9525 Sections 5-6 (supersedes RFC 6125)

**Requirement**: TLS clients MUST verify server identity by matching the certificate against the intended server:
- MUST check subjectAltName extension (dNSName, iPAddress, etc.)
- MUST NOT use Common Name (CN) for identity verification
- Wildcard matching: only complete leftmost label, single asterisk only

**Evidence**:
- RFC 9525: "The certificate MUST include at least one identifier"
- RFC 9525: "The Common Name RDN MUST NOT be used to identify a service"
- RFC 9525: "If a reference identifier produces a domain name, the client MUST match the DNS name"
- RFC 9525: "The wildcard character '*' MUST be the complete content of the left-most label"

**Violations**:
- Skipping hostname verification after certificate chain validation
- Accepting certificates for unrelated hostnames
- Using Common Name for identity matching
- Improper wildcard matching across domain levels

**Rationale**: Identity verification prevents MITM attacks where an attacker presents a valid certificate for a different domain. A certificate valid for `attacker.com` must not be accepted for connections to `victim.com`.

**Note**: RFC 9525 (November 2023) obsoletes RFC 6125. Key change: Common Name MUST NOT be used.

---

### M5: Cipher Suite Selection

**Priority**: MUST

**RFC Sources**: RFC 9325 Sections 4.1-4.3

**Requirement**: TLS clients MUST enforce cipher suite restrictions:

**MUST NOT negotiate**:
- NULL encryption cipher suites
- RC4 cipher suites
- Cipher suites offering less than 112 bits of security
- Anonymous key exchange cipher suites

**SHOULD NOT negotiate**:
- Cipher suites offering less than 128 bits of security
- Static RSA key exchange (no forward secrecy)
- Static DH/ECDH cipher suites
- CBC mode without encrypt_then_mac extension

**MUST support**:
- Cipher suites offering forward secrecy (ECDHE/DHE)

**Evidence**:
- RFC 9325 §4.1: "Implementations MUST NOT negotiate cipher suites offering less than 112 bits of security"
- RFC 9325 §4.1: "Implementations MUST NOT negotiate cipher suites that use NULL encryption"
- RFC 9325 §4.1: "Implementations MUST NOT negotiate RC4 cipher suites"
- RFC 9325 §4.1: "Implementations MUST support and prefer cipher suites offering forward secrecy"

**Violations**:
- Allowing NULL, RC4, or EXPORT cipher suites
- Not restricting cipher suite selection
- Preferring weak ciphers over strong alternatives
- Not supporting forward secrecy

**Rationale**: Cipher suite selection determines the cryptographic algorithms protecting the connection. Weak cipher suites can be exploited even with secure protocol versions. Forward secrecy protects past communications if long-term keys are compromised.

---

## SHOULD Requirements

### S1: Certificate Revocation Checking

**Priority**: SHOULD

**RFC Sources**: RFC 5280 Section 6.3, RFC 6960, RFC 9325 Section 7.5

**Requirement**: TLS clients SHOULD verify certificate revocation status. Mechanisms include:
- Certificate Revocation Lists (CRL)
- Online Certificate Status Protocol (OCSP)
- OCSP Stapling (preferred)

When revocation information indicates a certificate is revoked, the client MUST reject the connection.

**Evidence**:
- RFC 5280 §6.3: Defines CRL validation procedures
- RFC 9325 §7.5: "Implementations MUST implement a strategy to distrust revoked certificates"
- RFC 6960: Defines OCSP protocol

**Violations**:
- Not performing any revocation checking
- Ignoring revoked status and continuing connection
- No fallback mechanism when revocation information unavailable

**Rationale**: Certificates may be revoked before expiration due to key compromise or CA errors. Without revocation checking, clients may accept compromised certificates.

**Note**: Specific mechanism is not mandated. OCSP was made optional by CA/Browser Forum (July 2023). This is SHOULD rather than MUST because enforcement varies and soft-fail behavior is common.

---

### S2: Cryptographic Strength

**Priority**: SHOULD

**RFC Sources**: RFC 9325 Section 4.5

**Requirement**: TLS clients SHOULD verify cryptographic strength of certificates:

**Signature algorithms**:
- MUST NOT accept: MD5, SHA-1
- SHOULD accept: SHA-256, SHA-384, SHA-512

**Key sizes**:
- RSA: Minimum 2048 bits
- ECDSA/ECDH: Minimum 224 bits
- DH parameters: Minimum 2048 bits

**Evidence**:
- RFC 9325 §4.5: "Servers MUST authenticate using certificates with at least a 2048-bit modulus for the public key"
- RFC 9325 §4.5: "SHA-1 or MD5 MUST NOT be used"
- RFC 9325 §4.5: "Curves of less than 224 bits MUST NOT be used"
- RFC 9325 §4.5: "DH key lengths of at least 2048 bits are REQUIRED"

**Violations**:
- Accepting certificates signed with MD5 or SHA-1
- Accepting RSA keys smaller than 2048 bits
- Accepting weak elliptic curves (< 224 bits)

**Rationale**: Weak signature algorithms are vulnerable to collision attacks. Insufficient key sizes can be broken by brute force. Modern security requires SHA-256+ signatures and adequate key sizes.

**Note**: Priority is SHOULD because enforcement primarily affects certificate issuance, and legacy certificates may use weaker algorithms.

---

### S3: Entropy/RNG Initialization

**Priority**: SHOULD

**RFC Sources**: RFC 4086 (Randomness Requirements for Security)

**Requirement**: TLS implementations SHOULD ensure proper initialization of cryptographic random number generators:
- MUST seed CSPRNG from adequate entropy sources before key generation
- SHOULD NOT use deterministic or weak entropy sources (time, PID alone)
- Embedded systems MUST provide external entropy or hardware RNG

**Evidence**:
- RFC 4086 §3: "Choosing random quantities to foil a resourceful and motivated adversary is surprisingly difficult"
- RFC 4086 §5.1: "By far the best sources of randomness are hardware-based"
- RFC 8446 §C.1: "TLS requires a cryptographically secure pseudorandom number generator (CSPRNG)"

**Violations**:
- Not initializing RNG before TLS operations
- Using predictable entropy sources (e.g., time-only seeding, fixed seeds)
- Missing entropy collection on embedded systems without /dev/random or /dev/urandom
- Using deprecated or weak RNG functions (e.g., `rand()`, `srand()`)

**Rationale**: Weak RNG compromises all cryptographic operations: key generation, nonce generation, session IDs, and random padding. This is especially critical for embedded/IoT systems where traditional entropy sources (hardware interrupts, disk timing, user input) may not exist.

**Note**: Priority is SHOULD because proper RNG initialization is typically handled by the underlying library when adequate system entropy is available. Explicit handling is primarily needed for embedded systems without /dev/random or hardware RNG.

---

## MAY Requirements

### O1: Certificate Pinning

**Priority**: MAY

**RFC Sources**: RFC 7469 (concept; deprecated for HTTP browsers)

**Requirement**: For high-security applications, TLS clients MAY implement certificate or public key pinning:
- Public key pinning (SPKI hash)
- Certificate pinning (full certificate hash)
- CA pinning (restrict to specific issuers)

Implementations SHOULD include backup pins to prevent lockout.

**Evidence**:
- RFC 7469 §1: "allows web host operators to instruct user agents to remember ('pin') the hosts' cryptographic identities over a period of time"

**Violations**:
- Pinning without backup pins (lockout risk)
- Overly broad pins providing no meaningful restriction

**Rationale**: Certificate pinning provides defense-in-depth against CA compromise or mis-issuance. Even with a valid CA-issued certificate, pinning rejects certificates not matching expected values.

**Note**: RFC 7469 (HPKP) was deprecated by browsers in 2017-2018 due to operational risks. No replacement RFC exists. Certificate Transparency (RFC 9162) is an alternative approach for browsers. The pinning concept remains valid and commonly used for native applications, mobile apps, and embedded systems.

---

## References

### Primary RFCs

| RFC | Title | Year | Status |
|-----|-------|------|--------|
| RFC 2119 | Key words for use in RFCs to Indicate Requirement Levels | 1997 | BCP 14 |
| RFC 8174 | Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words | 2017 | BCP 14 |
| RFC 9325 | Recommendations for Secure Use of TLS and DTLS | 2022 | BCP 195 |
| RFC 8996 | Deprecating TLS 1.0 and TLS 1.1 | 2021 | BCP 195 |
| RFC 4086 | Randomness Requirements for Security | 2005 | BCP 106 |
| RFC 8446 | The Transport Layer Security (TLS) Protocol Version 1.3 | 2018 | Standards Track |
| RFC 5280 | Internet X.509 PKI Certificate and CRL Profile | 2008 | Standards Track |
| RFC 9525 | Service Identity in TLS | 2023 | Standards Track |
| RFC 6960 | X.509 Internet PKI Online Certificate Status Protocol - OCSP | 2013 | Standards Track |
| RFC 7469 | Public Key Pinning Extension for HTTP | 2015 | Standards Track (Deprecated) |

### Superseded RFCs (Not Used)

| RFC | Title | Status | Replacement |
|-----|-------|--------|-------------|
| RFC 2818 | HTTP Over TLS | Obsoleted | RFC 9110 |
| RFC 5246 | TLS 1.2 | Obsoleted | RFC 8446 |
| RFC 7525 | TLS Recommendations | Superseded | RFC 9325 |
| RFC 6125 | Hostname Verification | Obsoleted | RFC 9525 |
| RFC 6962 | Certificate Transparency v1 | Obsoleted | RFC 9162 |
