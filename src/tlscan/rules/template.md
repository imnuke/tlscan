# Library-Specific Rule Template

This document serves as a template for creating new library-specific SSL/TLS security rule files. Follow this structure to maintain consistency across all rule definitions.

---

## File Structure Overview

Each library-specific rule file should contain these sections in order:

1. **Title and Introduction** - Library name and reference to `metarule.md`
2. **Meta-Rule Mapping Table** - Maps library rules to meta-rules
3. **Version Detection Hints** (optional) - Patterns to identify library versions
4. **Individual Rules (R1, R2, ...)** - Detailed rule definitions
5. **Library-Specific Rules (LS1, LS2, ...)** (optional) - Rules not mapped to meta-rules
6. **Result Determination Summary** - Quick reference for outcomes

---

## Template

### Title and Introduction

```markdown
# [Library Name] SSL/TLS Security Rules

This document defines library-specific security rules for [Library Name]-based
TLS client implementations. Each rule references the corresponding meta-rule(s)
from `metarule.md`.
```

---

### Meta-Rule Mapping Table

```markdown
## Meta-Rule Mapping

| Rule | Meta-Rule(s) | Priority | Description |
|------|--------------|----------|-------------|
| R1 | M1 | MUST | TLS Usage Detection |
| R2 | M3 | MUST | Certificate Chain Verification |
| R3 | M4 | MUST | Hostname Verification |
| R4 | M2 | MUST | Protocol Version Enforcement |
| R5 | M5 | SHOULD | Cipher Suite Selection |
| R6 | S1 | SHOULD | Certificate Revocation Checking |
| R7 | S3 | SHOULD | Entropy/RNG Initialization |
| R8 | O1 | MAY | Certificate Pinning |

**Notes**:
- [Document any meta-rules that are N/A for this library and why]
- [Document any combined rules that implement multiple meta-rules]
```

**Guidance**:
- List rules in order: MUST first, then SHOULD, then MAY
- Use "N/A" note for inapplicable meta-rules (e.g., "S3 is N/A - relies on SSL backend")
- Combined rules: If one function/option controls multiple meta-rules, create a single rule referencing both (e.g., "R2 | M3, M4 | MUST | Certificate & Hostname Verification")

---

### Version Detection Hints (Optional)

```markdown
## Version Detection Hints

| Pattern | Indicates |
|---------|-----------|
| `[function_name]()` | [Library] [version]+ |
| `[constant_name]` | [Library] [version]+ |
| `[deprecated_function]()` | Older code (pre-[version]) |

**Default Behavior History** (if version-dependent):
| [Library] Version | Default | Security |
|-------------------|---------|----------|
| < X.Y.Z | [value] | INSECURE |
| ≥ X.Y.Z | [value] | SECURE |
```

**Guidance**:
- Include patterns that help identify library versions in compiled binaries
- Document when defaults changed between versions
- Note deprecated functions/options

---

### Individual Rule Template

```markdown
---

## R[N]: [Rule Name]

**Meta-Rule(s)**: M[X], M[Y]  |  **Priority**: MUST/SHOULD/MAY

**What to Verify**: [One sentence describing the security check]

**Implementation**:
- `[function/option]`: [What it does]
- `[function/option]`: [What it does]
- Default behavior: [Secure/Insecure/Version-dependent]

**Binary Analysis**:
| Function/Option | Code/Value | Purpose |
|-----------------|------------|---------|
| `[name]` | [numeric code if applicable] | [description] |

**Default Behavior** (include if version-dependent):
| Version | Default | Security |
|---------|---------|----------|
| < X.Y | [value] | INSECURE |
| ≥ X.Y | [value] | SECURE |

### Alternative Verification Patterns (if applicable)

When the "standard" secure configuration is not used, document alternative
patterns that are still secure:

**[Alternative Pattern Name]**:
When `[insecure mode]` is used, verification can still be secure if:
1. `[function1]` is called and checked for [condition]
2. `[function2]` is called and checked for [condition]

**Correct Implementation**:
\`\`\`c
// Code example showing the complete secure pattern
\`\`\`

**Incorrect Implementation (Vulnerability)**:
\`\`\`c
// Code example showing common mistakes
\`\`\`

### Known Bugs and Quirks (if applicable)

Document counterintuitive behaviors from library documentation:

**[Bug/Quirk Name]**: `[function]` [description of unexpected behavior].
This is documented in [man page section / issue tracker] but commonly overlooked.

### Custom Callback Requirements (if applicable)

If a custom verification callback is provided:

**Secure Callback Requirements**:
1. MUST check `[parameter]` for [condition]
2. MUST return [value] on failure
3. [Other requirements]

**Insecure Callback Patterns**:
\`\`\`c
// Examples of callbacks that bypass security
\`\`\`

### Legacy API Patterns (if applicable)

For [library] versions prior to [version], applications must use:

**Legacy API Functions**:
| Function | Purpose |
|----------|---------|
| `[old_function]` | [What it does] |

**Common Vulnerabilities in Legacy Code**:
1. [Vulnerability 1]
2. [Vulnerability 2]

**Detection Patterns**:
- `[code pattern]` → SATISFIED/UNSATISFIED ([reason])
- `[code pattern]` → CONDITIONAL ([reason])

**Vulnerability Indicators** (optional):
- [Common mistake or insecure pattern]
- [Common mistake or insecure pattern]

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| [Explicit secure configuration] | SATISFIED | [Why it's secure] |
| [Default when secure] | SATISFIED | [Why default is secure] |
| [Explicit insecure configuration] | UNSATISFIED | [Why it's insecure] |
| [Alternative pattern with all checks] | SATISFIED | Manual verification complete |
| [Alternative pattern missing checks] | UNSATISFIED | [Which check is missing] |
| [Value from variable/config] | CONDITIONAL | Trace variable |
| [Version-dependent default] | UNDETERMINED | Depends on [library] version (not traceable) |
| [Cannot determine] | UNDETERMINED | [Why undetermined] |
```

---

### Library-Specific Rules (LS) Template

For rules that don't map to meta-rules but are important for the specific library:

```markdown
---

## LS[N]: [Rule Name]

**Meta-Rule(s)**: N/A (library-specific)  |  **Priority**: SHOULD/CRITICAL

**What to Verify**: [Description of library-specific check]

**Implementation**:
- [Library-specific details]

**Detection Patterns**:
- [Patterns specific to this library]

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
```

**Common LS Rules**:
- Configuration file analysis (wget, curl)
- PHP-specific vulnerability patterns
- Framework-specific patterns (Guzzle, Symfony, etc.)
- Script analysis patterns

---

### Result Determination Summary

```markdown
---

## Result Determination Summary

| Priority | Scenario | Result |
|----------|----------|--------|
| MUST | Option explicitly set to secure value | SATISFIED |
| MUST | Option NOT set, default is secure | SATISFIED |
| MUST | Option explicitly set to insecure value | UNSATISFIED |
| MUST | Option NOT set, default is version-dependent | UNDETERMINED |
| MUST | Option set to runtime variable | CONDITIONAL |
| SHOULD | Feature enabled | SATISFIED |
| SHOULD | Feature explicitly disabled | UNSATISFIED |
| SHOULD | Feature not configured | UNDETERMINED |
| MAY | Feature implemented | SATISFIED |
| MAY | Feature not implemented | UNDETERMINED |
```

---

## Guidance Notes

### When to Use Combined Rules

Create a single rule implementing multiple meta-rules when:

1. **Single option controls multiple checks**:
   - curl `--insecure` disables both M3 (cert verification) and M4 (hostname verification)
   - GnuTLS priority strings control both M2 (protocol version) and M5 (cipher suites)

2. **Format**: Reference all applicable meta-rules in the mapping:
   ```markdown
   | R2 | M3, M4 | MUST | Certificate & Hostname Verification (Combined) |
   ```

3. **Document rationale**: Explain why checks are combined in the rule description

### When to Add Library-Specific Rules (LS)

Add LS rules for:

1. **Configuration file analysis** - wgetrc, .curlrc, php.ini
2. **Language/framework patterns** - PHP vulnerabilities, Guzzle options
3. **Script analysis patterns** - Shell script curl/wget usage
4. **Platform-specific behavior** - Windows vs Linux defaults

### Handling Version-Dependent Defaults

1. **Document version history** in a table showing when defaults changed
2. **Mark as UNDETERMINED** when relying on default that varies by version (not traceable)
3. **Mark as CONDITIONAL** only when a traceable code variable controls the behavior
4. **SATISFIED only** when explicitly set to secure value (version-independent)
5. **Include version detection hints** for informational purposes
6. **Document version requirements** in the evidence field

### When Meta-Rules Are N/A

Common reasons for N/A:

| Meta-Rule | Common N/A Reason |
|-----------|-------------------|
| S3 (Entropy/RNG) | Relies on underlying SSL backend (curl, PHP) |
| S1 (Revocation) | Not supported by tool (wget) |
| O1 (Pinning) | Not supported by tool (wget) |

Document N/A rules in the Notes section of the Meta-Rule Mapping table.

### Binary vs Source Analysis

**Binary Analysis** sections should include:
- Numeric option codes (especially for libcurl: 64, 81, 32)
- Constant values (SSL_VERIFY_NONE = 0, SSL_VERIFY_PEER = 1)
- Function names as they appear in symbol tables

**Source/Script Analysis** sections should include:
- Command-line flags (--insecure, --tlsv1.2)
- Configuration file syntax
- Environment variables

### When to Document Alternative Verification Patterns

Document alternative patterns when:

1. **Disabled mode can be made secure**: If a "verification disabled" mode can still be secure with additional manual checks, document the complete sequence required
2. **Multiple valid approaches exist**: When there are several correct ways to implement a security check
3. **Manual verification is common**: When applications frequently implement manual verification instead of using built-in modes

**What to Include**:
- Complete function call sequence required for secure implementation
- Code examples showing correct vs incorrect patterns
- Common mistakes that appear correct but are vulnerable

### When to Document Known Bugs and Quirks

Document bugs/quirks when:

1. **Function behavior is counterintuitive**: Document if a function's actual behavior differs from what developers typically expect
2. **Edge cases affect security**: Document edge cases like "returns success even without a certificate"
3. **Documentation mentions BUGS or NOTES**: Check library man pages and official documentation for known issues

**Where to Find This Information**:
- Library man pages (especially BUGS, NOTES, CAVEATS sections)
- Official library documentation
- Security advisories
- Common vulnerability patterns in CVE databases

### When to Document Legacy API Patterns

Document legacy patterns when:

1. **Modern API was introduced recently**: If the secure API is only available in recent versions
2. **Legacy code is common**: If older patterns are still frequently found in production code
3. **Manual implementation is error-prone**: If the legacy approach requires manual steps that are commonly implemented incorrectly

**What to Include**:
- Version when modern API was introduced
- Legacy functions and their usage
- Common vulnerabilities in legacy implementations (e.g., incorrect wildcard matching, missing SAN checks)

### When to Document Custom Callback Requirements

Document callback requirements when:

1. **Library supports custom verification callbacks**: Many SSL libraries allow custom callback functions
2. **Callbacks can bypass security**: If an improperly implemented callback can disable verification
3. **Multiple parameters must be checked**: If secure callbacks must validate multiple conditions

**What to Include**:
- Parameters that MUST be checked
- Return values for success vs failure
- Examples of insecure callbacks (e.g., always returning success)

---

## Example: Minimal Rule File

```markdown
# ExampleSSL SSL/TLS Security Rules

This document defines library-specific security rules for ExampleSSL-based
TLS client implementations. Each rule references the corresponding meta-rule(s)
from `metarule.md`.

## Meta-Rule Mapping

| Rule | Meta-Rule(s) | Priority | Description |
|------|--------------|----------|-------------|
| R1 | M1 | MUST | TLS Usage Detection |
| R2 | M3 | MUST | Certificate Verification |
| R3 | M4 | MUST | Hostname Verification |

**Notes**:
- S3 (Entropy/RNG) is N/A - relies on system entropy

---

## R1: TLS Usage Detection

**Meta-Rule(s)**: M1  |  **Priority**: MUST

**What to Verify**: Confirm TLS is used for connections.

**Implementation**:
- `example_ssl_connect()`: Establishes TLS connection
- Default: No TLS unless explicitly called

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `example_ssl_connect()` called | SATISFIED | TLS enabled |
| Plain socket without SSL wrapper | UNSATISFIED | No TLS |

---

## Result Determination Summary

| Priority | Scenario | Result |
|----------|----------|--------|
| MUST | Option explicitly secure | SATISFIED |
| MUST | Option explicitly insecure | UNSATISFIED |
```
