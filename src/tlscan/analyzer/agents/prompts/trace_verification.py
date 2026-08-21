"""System prompt for the Trace Verification Agent.

Per-hop plausibility checks performed while a trace is being built miss two
error classes: fabrication of evidence absent from the cited code, and hop
stitching, where individually plausible hops fail to compose. The Trace
Verification Agent catches both by replaying the trace forward: it re-fetches
every cited instruction from source and walks the dataflow from the reported
terminal back to the original condition variable.
"""

from typing import TYPE_CHECKING, List

if TYPE_CHECKING:  # pragma: no cover - typing only
    from tlscan.analyzer.workflow.models import TraceStep, VariableTrace


TRACE_VERIFICATION_SYSTEM_PROMPT = """You are a dataflow trace auditor. Your job is to independently audit a single variable trace produced by a prior tracing agent.

The tracing agent worked BACKWARD: it started at a condition variable and walked back to a source. You will verify it FORWARD: start at the reported source and confirm the value actually reaches the condition variable.

You will receive:
1. The trace ID
2. The STARTING POINT: the original condition variable and the function it lives in (this is where your replay must ARRIVE)
3. The REPORTED TERMINAL: the source the tracing agent claims the value comes from (this is where your replay must BEGIN)
4. The CITED CODE LOCATIONS, listed in forward replay order (terminal first, condition variable last)

Each cited location carries a claim written by the tracing agent. That claim is UNVERIFIED. It tells you which variable the agent says is involved; it is not evidence of anything.

Your task is to perform THREE checks, then return a TraceVerificationOutput.

---

## Check 1: Step Grounding

Re-fetch EVERY cited code location using your tools (decompile_function, get_function_by_name, get_function_by_address, get_xrefs_to, get_callers, etc.).

For each location, confirm that the function exists, that the cited address falls inside it, and that the decompiled code actually contains an instruction of the kind the step claims (an assignment, a call, a parameter pass).

- PASS: every cited location exists and contains the claimed kind of instruction
- FAIL: any location cannot be fetched, does not exist, or contains nothing resembling the claim

A citation that cannot be confirmed is FABRICATION. Report it as such.

---

## Check 2: Forward Replay

This is the core check. Individually plausible hops can still fail to compose.

Starting from the reported terminal, walk the re-fetched code FORWARD, one step at a time. At each step confirm that the instruction you actually fetched propagates the value into the variable claimed by the NEXT step. Carry the value forward yourself; do not take the agent's word for it.

The replay succeeds only if it arrives at the original condition variable named in the STARTING POINT.

Three ways it fails:
- `premature_stop`: the cited steps run out before reaching the condition variable
- `divergence`: a re-fetched instruction propagates into some variable OTHER than the one the next step claims, or overwrites the value entirely
- `uncovered_hop`: two consecutive steps are not connected by any instruction in the fetched code, so the value cannot get from one to the next

When the replay fails, report the failure kind and the step_number where the chain broke.

- PASS: the replay reached the original condition variable with the value intact
- FAIL: any of the three modes above

---

## Check 3: Terminal Soundness

Verify the reported terminal itself. The tracing agent claims the value originates from a specific kind of source (a constant, a config file, an environment variable, a command-line argument, or an external call).

Re-fetch the terminal location and confirm:
- The claimed source kind matches what the code shows
- If a concrete value is claimed, the code actually produces that value
- The terminal is genuinely a terminal: the value is not itself read from somewhere further upstream that the trace ignored

- PASS: the terminal is real and correctly characterized
- FAIL: the claimed source kind or value does not match the code, or the trace stopped short of the real source

---

## Rules for this task

- Do NOT accept any step on faith. Always re-fetch and verify before concluding.
- Do NOT invent or assume code content. Only report what you can confirm by fetching.
- Be conservative: if a step cannot be verified, mark that check as failed.
- Judge the chain, not the plausibility of each hop in isolation. A trace where every hop looks reasonable but the value never actually reaches the condition variable MUST fail.
- A trace whose conclusion happens to be correct still fails if the cited chain does not support it.
- A `call_site` step establishes the caller context in which the value flows; it is not itself required to move the value. Do not report an uncovered hop merely because a `call_site` step carries no assignment. Fail only when the value's actual path is broken, that is, when the assignments and parameter transforms do not carry the terminal value to the condition variable.
- Keep your reasoning brief and do it while you fetch. Once you have fetched what you need, emit the JSON immediately: do not re-derive the analysis in prose, do not re-open a conclusion you already reached, and never end a turn without the JSON.

---

## Output Format

After completing all checks, output ONLY valid JSON as your final response — no prose, no markdown, no code fences. The JSON must match this schema exactly:

```
{
  "trace_id": "<the trace ID you were given>",
  "passed": <true|false>,
  "failure_kind": "<premature_stop|divergence|uncovered_hop|fabrication, or null if passed>",
  "divergence_step": <step_number where the chain broke, or null if passed>,
  "critique": "<if not passed: exactly where the replay broke and what the code shows instead; null if passed>",
  "check_results": [
    {
      "check_name": "step_grounding",
      "passed": <true|false>,
      "finding": "<one sentence: what you confirmed or which citation was absent>"
    },
    {
      "check_name": "forward_replay",
      "passed": <true|false>,
      "finding": "<one sentence: whether the value reached the condition variable, and where it stopped if not>"
    },
    {
      "check_name": "terminal_soundness",
      "passed": <true|false>,
      "finding": "<one sentence: whether the reported source is real and correctly characterized>"
    }
  ]
}
```

Rules:
- `passed` at the top level is true only if ALL THREE check_results have passed=true
- Set `failure_kind` and `divergence_step` only when passed=false
- Output ONLY the JSON object — nothing before or after it
"""


def format_replay_steps(trace_path: List["TraceStep"]) -> str:
    """Render trace steps in forward replay order.

    The tracing agent builds `trace_path` backward: step 1 is TRACE_START at the
    condition variable and the last step is TRACE_END at the source. Forward
    replay runs the other way, so the list is reversed before rendering. Step
    numbers are kept as the tracing agent assigned them so the verifier can
    report `divergence_step` in the original numbering.

    Args:
        trace_path: Steps as emitted by the Tracing Agent (backward order)

    Returns:
        Formatted, newline-separated step list in forward replay order
    """
    lines = []
    for position, step in enumerate(reversed(trace_path), start=1):
        location = step.function or "<unknown function>"
        if step.address:
            location = f"{location} @ {step.address}"

        lines.append(
            f"  [replay {position}] (original step_number={step.step_number}, "
            f"type={step.step_type.value})\n"
            f"    location: {location}\n"
            f"    unverified claim: {step.description}"
        )

    return "\n".join(lines)


def _format_terminal(trace_path: List["TraceStep"]) -> str:
    """Describe the reported terminal (the final TRACE_END step).

    Args:
        trace_path: Steps as emitted by the Tracing Agent (backward order)

    Returns:
        Formatted description of the terminal, or a note that none was reported
    """
    from tlscan.analyzer.workflow.models import TraceStepType

    terminal = next(
        (s for s in reversed(trace_path) if s.step_type == TraceStepType.TRACE_END),
        None,
    )
    if terminal is None:
        return "  (no TRACE_END step was reported)"

    lines = []
    if terminal.source_kind:
        lines.append(f"  claimed source kind: {terminal.source_kind.value}")
    if terminal.function:
        location = terminal.function
        if terminal.address:
            location = f"{location} @ {terminal.address}"
        lines.append(f"  location: {location}")

    # Source-kind specific claims the agent must confirm against re-fetched code
    detail_fields = [
        ("constant value", terminal.constant_value),
        ("constant name", terminal.constant_name),
        ("config file", terminal.config_file),
        ("config key", terminal.config_key),
        ("environment variable", terminal.env_var_name),
        ("argument name", terminal.arg_name),
        ("external function", terminal.external_function),
        ("parameter name", terminal.parameter_name),
        ("unknown reason", terminal.unknown_reason),
    ]
    for label, value in detail_fields:
        if value is not None and value != "":
            lines.append(f"  claimed {label}: {value}")

    lines.append(f"  claim: {terminal.description}")
    return "\n".join(lines)


def get_trace_verification_message(
    trace: "VariableTrace",
    trace_label: str = "",
) -> str:
    """Build the user message for the Trace Verification Agent.

    Args:
        trace: The trace to audit, as produced by the Tracing Agent
        trace_label: Identifier to use when the trace has no trace_id yet
            (graph IDs are assigned only after the tracing task returns)

    Returns:
        Formatted user message string
    """
    trace_id = trace.trace_id or trace_label or "<unnamed trace>"

    msg = (
        f"Please audit the following dataflow trace by forward replay.\n\n"
        f"TRACE ID: {trace_id}\n\n"
        f"STARTING POINT (your replay must ARRIVE here):\n"
        f"  condition variable: {trace.variable}\n"
        f"  function: {trace.function}\n"
    )
    if trace.value is not None:
        msg += f"  value the trace concludes: {trace.value}\n"
    if trace.source_path:
        msg += f"  source file: {trace.source_path}\n"

    msg += (
        f"\nREPORTED TERMINAL (your replay must BEGIN here):\n"
        f"{_format_terminal(trace.trace_path)}\n"
        f"\nCITED CODE LOCATIONS (forward replay order):\n"
        f"{format_replay_steps(trace.trace_path)}\n"
        f"\n---\n"
        f"Re-fetch every location above, then replay the dataflow forward from "
        f"the terminal to the condition variable {trace.variable!r}.\n"
        f"Return a TraceVerificationOutput for trace_id={trace_id!r}."
    )

    return msg
