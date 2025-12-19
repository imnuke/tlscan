"""Build prompts for rule generation."""

from pathlib import Path
from typing import Optional


def build_prompt(
    library_name: str,
    documentation: Optional[str] = None,
    rules_dir: Optional[Path] = None,
    doc_url: Optional[str] = None,
) -> str:
    """
    Build a comprehensive prompt for generating library-specific SSL/TLS rules.

    Args:
        library_name: Name of the SSL/TLS library
        documentation: Library documentation text to analyze (mutually exclusive with doc_url)
        rules_dir: Path to security_rules directory (default: auto-detect)
        doc_url: URL to documentation for Claude to fetch (mutually exclusive with documentation)

    Returns:
        Complete prompt string for Claude Code
    """
    if rules_dir is None:
        rules_dir = Path(__file__).parent.parent / "security_rules"

    # Load reference documents
    metarules = ""
    template = ""

    metarules_path = rules_dir / "metarule.md"
    template_path = rules_dir / "template.md"

    if metarules_path.exists():
        metarules = metarules_path.read_text()

    if template_path.exists():
        template = template_path.read_text()

    # Build documentation section based on source
    if doc_url:
        doc_section = f"""## Library Documentation

Fetch and analyze the documentation from this URL to extract security-relevant information:

URL: {doc_url}

Use your web fetch capability to retrieve the documentation content."""
    else:
        doc_section = f"""## Library Documentation

Analyze this documentation to extract security-relevant information:

{documentation}"""

    prompt = f"""Generate SSL/TLS security rules for {library_name}.

Your task is to create a complete library-specific rule file following the template structure.

## Meta-Rules Reference

These are the abstract security requirements your rules must implement:

{metarules}

---

## Template to Follow

Follow this structure for the rule file:

{template}

---

{doc_section}

---

## Critical Instructions

When generating rules, you MUST:

1. **Document ALL alternative verification patterns**
   - If a "disabled" mode can still be secure with manual checks, document the complete sequence
   - Example: Verification disabled + manual certificate check + manual result check = secure

2. **Check documentation for BUGS, NOTES, CAVEATS sections**
   - Document any counterintuitive behaviors
   - Example: Function returns "OK" even when no certificate provided

3. **Include legacy API patterns for older library versions**
   - What functions did older code use before modern APIs?
   - What are common vulnerabilities in legacy implementations?

4. **Document what makes custom callbacks secure vs insecure**
   - What parameters must be checked?
   - What return values indicate success/failure?
   - Show examples of insecure callbacks

5. **Be specific about return value semantics**
   - How to check for success vs failure?
   - Are there additional status flags to check?

6. **Include version-dependent behavior**
   - When did defaults change between versions?
   - Which version introduced secure defaults?

Write the complete rule file to: output.md
"""

    return prompt
