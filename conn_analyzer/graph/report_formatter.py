"""Rich-based report formatting for security analysis.

This module provides Rich widget-based formatting for the security analysis
report, replacing markdown text generation with structured Rich panels, tables,
and other widgets for better visual hierarchy and readability.
"""

from typing import Dict, Any, List
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from conn_analyzer.graph.models import (
    RuleResult,
    RuleResultStatus,
    TraceResolvingStatus,
    RuleCondition,
    VariableTrace,
    VariableTraceGroup,
    ExternalTraceGroup,
    RuleTraceLink,
    TraceContinuation,
    ContinuationType,
    TraceType,
    TraceStep,
    TraceStepType,
    SourceKind,
)


# ============================================================================
# Helper Functions
# ============================================================================

def format_status_badge(status: RuleResultStatus) -> str:
    """Format status with color markup for Rich."""
    badges = {
        RuleResultStatus.PASS: "[green]✅ PASS[/green]",
        RuleResultStatus.FAIL: "[red]❌ FAIL[/red]",
        RuleResultStatus.CONDITIONAL: "[yellow]⚠️ CONDITIONAL[/yellow]",
        RuleResultStatus.UNDETERMINED: "[dim]❓ UNDETERMINED[/dim]",
    }
    return badges.get(status, f"[white]{status.value.upper()}[/white]")


def format_trace_resolution_badge(status: TraceResolvingStatus) -> str:
    """Format trace resolution status with color markup."""
    badges = {
        TraceResolvingStatus.PENDING: "[yellow]⏳ PENDING[/yellow]",
        TraceResolvingStatus.RESOLVED: "[green]✓ RESOLVED[/green]",
        TraceResolvingStatus.CANNOT_RESOLVE: "[red]⊘ CANNOT_RESOLVE[/red]",
    }
    return badges.get(status, f"[white]{status.value.upper()}[/white]")


def format_source_kind_badge(source_kind: str) -> str:
    """Format source kind with emoji badge."""
    badges = {
        "constant": "🔢",
        "config_file": "📄",
        "environment_variable": "🌐",
        "command_line_arg": "⌨️",
        "external_call": "🔗",
        "unknown": "❓",
    }
    return badges.get(source_kind, "•")


def get_border_color(status: RuleResultStatus) -> str:
    """Get border color based on rule status."""
    colors = {
        RuleResultStatus.PASS: "green",
        RuleResultStatus.FAIL: "red",
        RuleResultStatus.CONDITIONAL: "yellow",
        RuleResultStatus.UNDETERMINED: "dim",
    }
    return colors.get(status, "white")


def escape_rich_markup(text: str) -> str:
    """Escape Rich markup characters in text."""
    # Rich uses square brackets for markup
    return text.replace("[", "\\[").replace("]", "\\]")


# ============================================================================
# Main Display Function
# ============================================================================

def format_and_display_report(console: Console, report_data: Dict[str, Any]) -> None:
    """Display security analysis report using Rich widgets.

    Args:
        console: Rich Console instance for output
        report_data: Structured report data from synthesis_node
    """
    # 1. Display summary statistics
    display_summary(console, report_data["summary_stats"])
    console.print()

    # 2. Display analysis context
    display_context(console, report_data["context"])
    console.print()

    # 3. Display security rules analysis
    console.print(Panel.fit(
        "[bold cyan]🔐 Security Rules Analysis[/bold cyan]",
        border_style="cyan"
    ))
    console.print()

    rules = report_data["rules"]
    trace_groups = report_data.get("trace_groups", {})
    external_traces = report_data.get("external_traces", {})
    # NEW unified trace graph
    traces = report_data.get("traces", {})
    rule_trace_links = report_data.get("rule_trace_links", {})

    for rule_id, rule in rules.items():
        rule_panel = create_rule_panel(
            rule, trace_groups, external_traces,
            traces=traces, rule_trace_links=rule_trace_links
        )
        console.print(rule_panel)
        console.print()  # Spacing between rules

    # 4. Display startup scripts (if any)
    scripts = report_data.get("scripts", [])
    if scripts:
        display_scripts(console, scripts)
        console.print()


# ============================================================================
# Summary Section
# ============================================================================

def display_summary(console: Console, stats: Dict[str, int]) -> None:
    """Display summary statistics table."""
    table = Table(
        show_header=True,
        header_style="bold cyan",
        box=box.SIMPLE_HEAVY,
        padding=(0, 1)
    )

    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Count", justify="right", style="bold")

    # Add rows with color coding
    table.add_row("Total Rules", str(stats.get("total", 0)))
    table.add_row("[green]✅ Passed[/green]", f"[green]{stats.get('pass', 0)}[/green]")
    table.add_row("[red]❌ Failed[/red]", f"[red]{stats.get('fail', 0)}[/red]")
    table.add_row("[yellow]⚠️ Conditional[/yellow]", f"[yellow]{stats.get('conditional', 0)}[/yellow]")
    table.add_row("[dim]❓ Undetermined[/dim]", f"[dim]{stats.get('undetermined', 0)}[/dim]")
    table.add_row("Variables Traced", str(stats.get("trace_count", 0)))
    table.add_row("Cross-Binary Traces", str(stats.get("cross_binary_count", 0)))

    console.print(Panel(
        table,
        title="[bold]📊 Analysis Summary[/bold]",
        border_style="cyan",
        padding=(1, 2)
    ))


# ============================================================================
# Context Section
# ============================================================================

def display_context(console: Console, context: Dict[str, Any]) -> None:
    """Display analysis context information."""
    lines = []

    # Binary path
    binary_path = escape_rich_markup(context.get("binary_path", "N/A"))
    lines.append(f"[bold]Binary:[/bold] `{binary_path}`")

    # Client type
    client_type = context.get("client_type", "N/A")
    lines.append(f"[bold]Client Type:[/bold] {client_type}")

    # Firmware path
    firmware_path = context.get("firmware_path")
    if firmware_path:
        firmware_path = escape_rich_markup(firmware_path)
        lines.append(f"[bold]Firmware Path:[/bold] {firmware_path}")
    else:
        lines.append("[bold]Firmware Path:[/bold] Not provided")

    # Timestamp
    from datetime import datetime
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    lines.append(f"[bold]Generated:[/bold] {timestamp}")

    # Summary
    summary = context.get("summary", "")
    if summary:
        lines.append("")
        lines.append("[bold]Summary:[/bold]")
        lines.append(f"[dim]{summary}[/dim]")

    content = "\n".join(lines)

    console.print(Panel(
        content,
        title="[bold]📋 Analysis Context[/bold]",
        border_style="cyan",
        padding=(1, 2)
    ))


# ============================================================================
# Rule Panel Creation (using trace groups)
# ============================================================================

def create_rule_panel(
    rule: RuleResult,
    trace_groups: Dict[str, VariableTraceGroup],
    external_traces: Dict[str, ExternalTraceGroup] = None,
    traces: Dict[str, VariableTrace] = None,
    rule_trace_links: Dict[str, RuleTraceLink] = None,
) -> Panel:
    """Create a Rich Panel for a single security rule using trace groups.

    Args:
        rule: RuleResult with status, evidence, and conditions
        trace_groups: Dictionary mapping condition keys to VariableTraceGroup (OLD format)
        external_traces: Dictionary of shared cross-binary analysis results (OLD format)
        traces: Dict of all traces by ID (NEW unified format)
        rule_trace_links: Dict of rule-to-trace links (NEW unified format)

    Returns:
        Rich Panel with formatted rule information
    """
    if external_traces is None:
        external_traces = {}
    if traces is None:
        traces = {}
    if rule_trace_links is None:
        rule_trace_links = {}

    renderables = []

    # Status
    status_text = f"[bold]Status:[/bold] {format_status_badge(rule.result)}"
    renderables.append(Text.from_markup(status_text))
    renderables.append(Text(""))  # Empty line

    # Evidence
    evidence_text = f"[bold]Evidence:[/bold]\n[dim]{rule.evidence}[/dim]"
    renderables.append(Text.from_markup(evidence_text))

    # Conditions (if conditional)
    if rule.result == RuleResultStatus.CONDITIONAL and rule.conditions:
        renderables.append(Text(""))  # Empty line
        renderables.append(Text.from_markup("[bold]Conditions:[/bold]"))
        renderables.append(Text(""))  # Empty line

        for cond in rule.conditions:
            # Prefer new unified format if available
            condition_key = f"{cond.function}:{cond.variable}"
            if traces and rule_trace_links and condition_key in rule_trace_links:
                cond_panel = create_condition_panel_from_graph(cond, traces, rule_trace_links)
            else:
                # Fall back to old format
                cond_panel = create_condition_panel(cond, trace_groups, external_traces)
            renderables.append(cond_panel)

    # Use Group to combine text and panels
    content = Group(*renderables)

    # Get border color based on status
    border_color = get_border_color(rule.result)
    title = f"[bold]{rule.rule_name}[/bold] {format_status_badge(rule.result)}"

    return Panel(
        content,
        title=title,
        border_style=border_color,
        padding=(1, 2),
        expand=False
    )


def create_condition_panel(
    condition: RuleCondition,
    trace_groups: Dict[str, VariableTraceGroup],
    external_traces: Dict[str, ExternalTraceGroup] = None
) -> Panel:
    """Create a nested panel for a single condition using trace groups.

    Args:
        condition: RuleCondition with variable, function, and security mapping
        trace_groups: Dictionary of trace groups
        external_traces: Dictionary of shared cross-binary analysis results

    Returns:
        Rich Panel with condition details and hierarchical traces
    """
    if external_traces is None:
        external_traces = {}

    lines = []

    # Condition header
    var = escape_rich_markup(condition.variable)
    func = escape_rich_markup(condition.function)
    lines.append(f"[bold]Variable:[/bold] `{var}` in `{func}`")
    lines.append("")

    # Look up trace group
    condition_key = f"{condition.function}:{condition.variable}"
    trace_group = trace_groups.get(condition_key)

    if not trace_group:
        lines.append("[yellow]⚠️ No trace group available for this variable[/yellow]")
    else:
        # Overall resolution status
        overall_badge = format_trace_resolution_badge(trace_group.overall_status)
        lines.append(f"[bold]Overall Status:[/bold] {overall_badge}")

        if trace_group.resolution_summary:
            summary = escape_rich_markup(trace_group.resolution_summary)
            lines.append(f"[bold]Summary:[/bold] {summary}")

        # Resolution outcomes
        if trace_group.resolution_outcomes:
            lines.append("")
            lines.append("[bold]Resolution Outcomes:[/bold]")
            for outcome in trace_group.resolution_outcomes:
                escaped_outcome = escape_rich_markup(outcome)
                emoji = "✅" if "pass" in outcome.lower() else "❌" if "fail" in outcome.lower() else "•"
                lines.append(f"  {emoji} {escaped_outcome}")

        lines.append("")

        # Main binary traces
        if trace_group.main_traces:
            lines.append("[bold]Main Binary Traces:[/bold]")
            for i, trace in enumerate(trace_group.main_traces, 1):
                trace_text = format_trace_brief(trace, prefix="  ")
                lines.append(trace_text)
                if i < len(trace_group.main_traces):
                    lines.append("")

        # Collect all continuations: direct + from external_refs
        all_continuations = list(trace_group.continuations)

        # Look up external_refs and add their continuations
        for ext_ref in trace_group.external_refs:
            if ext_ref in external_traces:
                ext_group = external_traces[ext_ref]
                for cont in ext_group.continuations:
                    # Avoid duplicates (same source_path and type)
                    is_duplicate = any(
                        c.source_path == cont.source_path and c.type == cont.type
                        for c in all_continuations
                    )
                    if not is_duplicate:
                        all_continuations.append(cont)

        # Continuations (cross-binary, config, etc.)
        if all_continuations:
            lines.append("")
            lines.append("[bold]Cross-Analysis Results:[/bold]")
            for continuation in all_continuations:
                cont_text = format_continuation(continuation, prefix="  ")
                lines.append(cont_text)

    content = "\n".join(lines)

    return Panel(
        content,
        border_style="dim",
        padding=(1, 2),
        expand=True
    )


def format_trace_brief(trace: VariableTrace, prefix: str = "") -> str:
    """Format a variable trace briefly.

    Args:
        trace: VariableTrace with trace path
        prefix: Indentation prefix

    Returns:
        Formatted trace string with Rich markup
    """
    lines = []

    # Get source info from final step
    last_step = trace.trace_path[-1] if trace.trace_path else None
    source_kind = None
    if last_step and last_step.step_type == TraceStepType.TRACE_END:
        source_kind = last_step.source_kind

    source_kind_str = source_kind.value if source_kind else "unknown"
    badge = format_source_kind_badge(source_kind_str)

    # Source and value
    source_name = escape_rich_markup(source_kind_str)
    lines.append(f"{prefix}{badge} [bold]Source:[/bold] {source_name}")

    # Show key details based on source kind
    if last_step and source_kind:
        if source_kind == SourceKind.CONSTANT:
            val = escape_rich_markup(str(last_step.constant_value or "unknown"))
            if last_step.constant_name:
                name = escape_rich_markup(last_step.constant_name)
                lines.append(f"{prefix}   Value: `{name}` = `{val}`")
            else:
                lines.append(f"{prefix}   Value: `{val}`")

        elif source_kind == SourceKind.CONFIG_FILE:
            cfg = escape_rich_markup(last_step.config_file or "unknown")
            lines.append(f"{prefix}   Config: `{cfg}`")
            if last_step.config_key:
                key = escape_rich_markup(last_step.config_key)
                lines.append(f"{prefix}   Key: `{key}`")

        elif source_kind == SourceKind.EXTERNAL_CALL:
            func = escape_rich_markup(last_step.external_function or "unknown")
            param = escape_rich_markup(last_step.parameter_name or "unknown")
            lines.append(f"{prefix}   External: `{func}` parameter `{param}`")

        elif source_kind == SourceKind.COMMAND_LINE_ARG:
            if last_step.arg_name:
                arg = escape_rich_markup(last_step.arg_name)
                lines.append(f"{prefix}   Argument: `{arg}`")

    # Resolution status for this trace
    if trace.resolving_status:
        res_badge = format_trace_resolution_badge(trace.resolving_status)
        lines.append(f"{prefix}   Resolution: {res_badge}")

        if trace.outcome:
            emoji = "✅" if "pass" in trace.outcome.lower() else "❌"
            lines.append(f"{prefix}   Outcome: {emoji} {trace.outcome}")
        elif trace.resolution_reason:
            reason = escape_rich_markup(trace.resolution_reason)
            lines.append(f"{prefix}   Reason: {reason}")

    return "\n".join(lines)


def format_continuation(continuation: TraceContinuation, prefix: str = "") -> str:
    """Format a trace continuation (cross-binary, config, etc.).

    Args:
        continuation: TraceContinuation with traces and resolution
        prefix: Indentation prefix

    Returns:
        Formatted continuation string with Rich markup
    """
    lines = []

    # Continuation type badge
    type_badges = {
        ContinuationType.CROSS_BINARY: "📁",
        ContinuationType.CONFIG_FILE: "📄",
        ContinuationType.SCRIPT: "📜",
        ContinuationType.ENVIRONMENT: "🌐",
    }
    type_badge = type_badges.get(continuation.type, "•")
    type_name = continuation.type.value.replace("_", " ").title()

    source_path = escape_rich_markup(continuation.source_path)
    lines.append(f"{prefix}{type_badge} [bold]{type_name}:[/bold] `{source_path}`")

    # Resolved value
    if continuation.resolved_value:
        val = escape_rich_markup(continuation.resolved_value)
        source_kind_str = continuation.resolved_source_kind.value if continuation.resolved_source_kind else "unknown"
        source_badge = format_source_kind_badge(source_kind_str)
        lines.append(f"{prefix}   {source_badge} [green]Resolved:[/green] `{val}`")

    # Config values
    if continuation.config_values:
        for key, value in continuation.config_values.items():
            k = escape_rich_markup(key)
            v = escape_rich_markup(value)
            lines.append(f"{prefix}   📄 Config value: `{k}` = `{v}`")

    # Traces within this continuation
    if continuation.traces:
        for trace in continuation.traces:
            last_step = trace.trace_path[-1] if trace.trace_path else None
            source_kind = None
            if last_step and last_step.step_type == TraceStepType.TRACE_END:
                source_kind = last_step.source_kind

            source_kind_str = source_kind.value if source_kind else "unknown"
            badge = format_source_kind_badge(source_kind_str)

            # Brief trace info
            if source_kind == SourceKind.CONSTANT and last_step:
                val = escape_rich_markup(str(last_step.constant_value or "?"))
                lines.append(f"{prefix}   {badge} Constant: `{val}`")
            elif source_kind == SourceKind.CONFIG_FILE and last_step:
                cfg = escape_rich_markup(last_step.config_file or "?")
                lines.append(f"{prefix}   {badge} From config: `{cfg}`")
            else:
                lines.append(f"{prefix}   {badge} Source: {source_kind_str}")

    # Sub-continuations (for multi-level chains)
    if continuation.sub_continuations:
        for sub_cont in continuation.sub_continuations:
            sub_text = format_continuation(sub_cont, prefix=prefix + "  ")
            lines.append(sub_text)

    return "\n".join(lines)


# ============================================================================
# Unified Trace Graph Formatting (NEW)
# ============================================================================

def format_trace_type_badge(trace_type: TraceType) -> str:
    """Format trace type with emoji badge."""
    type_badges = {
        TraceType.MAIN_BINARY: "🔍",
        TraceType.CROSS_BINARY: "📁",
        TraceType.CONFIG_FILE: "📄",
        TraceType.SCRIPT: "📜",
        TraceType.ENVIRONMENT: "🌐",
    }
    return type_badges.get(trace_type, "•")


def format_trace_from_graph(
    trace: VariableTrace,
    traces: Dict[str, VariableTrace],
    prefix: str = "",
    visited: set = None,
) -> str:
    """Format a single trace and its children from the unified trace graph.

    Args:
        trace: VariableTrace to format
        traces: All traces dict (for following child links)
        prefix: Indentation prefix
        visited: Set of visited trace IDs to prevent cycles

    Returns:
        Formatted trace string with Rich markup
    """
    if visited is None:
        visited = set()

    # Prevent infinite loops
    if trace.trace_id in visited:
        return f"{prefix}[dim](cycle detected)[/dim]"
    visited.add(trace.trace_id)

    lines = []

    # Trace type badge and source
    type_badge = format_trace_type_badge(trace.trace_type)
    type_name = trace.trace_type.value.replace("_", " ").title()
    source_path = escape_rich_markup(trace.source_path or "main binary")

    lines.append(f"{prefix}{type_badge} [bold]{type_name}:[/bold] `{source_path}`")

    # Function and variable
    func = escape_rich_markup(trace.function)
    var = escape_rich_markup(trace.variable)
    lines.append(f"{prefix}   Function: `{func}`, Variable: `{var}`")

    # Value if resolved
    if trace.value:
        val = escape_rich_markup(trace.value)
        lines.append(f"{prefix}   [green]Value:[/green] `{val}`")

    # Resolution status
    res_badge = format_trace_resolution_badge(trace.resolving_status)
    lines.append(f"{prefix}   Status: {res_badge}")

    if trace.outcome:
        emoji = "✅" if "pass" in trace.outcome.lower() else "❌"
        outcome = escape_rich_markup(trace.outcome)
        lines.append(f"{prefix}   Outcome: {emoji} {outcome}")

    # Recursively format children
    if trace.child_trace_ids:
        for child_id in trace.child_trace_ids:
            child_trace = traces.get(child_id)
            if child_trace:
                lines.append("")
                child_text = format_trace_from_graph(
                    child_trace, traces, prefix=prefix + "  ", visited=visited
                )
                lines.append(child_text)

    return "\n".join(lines)


def create_condition_panel_from_graph(
    condition: RuleCondition,
    traces: Dict[str, VariableTrace],
    rule_trace_links: Dict[str, RuleTraceLink],
) -> Panel:
    """Create a condition panel using the unified trace graph.

    Args:
        condition: RuleCondition with variable, function, and security mapping
        traces: Dict of all traces by ID
        rule_trace_links: Dict of rule-to-trace links

    Returns:
        Rich Panel with condition details and trace tree
    """
    lines = []

    # Condition header
    var = escape_rich_markup(condition.variable)
    func = escape_rich_markup(condition.function)
    lines.append(f"[bold]Variable:[/bold] `{var}` in `{func}`")
    lines.append("")

    # Look up rule trace link
    condition_key = f"{condition.function}:{condition.variable}"
    link = rule_trace_links.get(condition_key)

    if not link or not link.root_trace_ids:
        lines.append("[yellow]⚠️ No trace data available for this variable[/yellow]")
    else:
        # Overall resolution status
        overall_badge = format_trace_resolution_badge(link.overall_status)
        lines.append(f"[bold]Overall Status:[/bold] {overall_badge}")

        if link.resolution_summary:
            summary = escape_rich_markup(link.resolution_summary)
            lines.append(f"[bold]Summary:[/bold] {summary}")

        # Resolution outcomes
        if link.resolution_outcomes:
            lines.append("")
            lines.append("[bold]Resolution Outcomes:[/bold]")
            for outcome in link.resolution_outcomes:
                escaped_outcome = escape_rich_markup(outcome)
                emoji = "✅" if "pass" in outcome.lower() else "❌" if "fail" in outcome.lower() else "•"
                lines.append(f"  {emoji} {escaped_outcome}")

        lines.append("")

        # Format trace tree from root traces
        lines.append("[bold]Trace Graph:[/bold]")
        for root_id in link.root_trace_ids:
            root_trace = traces.get(root_id)
            if root_trace:
                trace_text = format_trace_from_graph(root_trace, traces, prefix="  ")
                lines.append(trace_text)
                lines.append("")

    content = "\n".join(lines)

    return Panel(
        content,
        border_style="dim",
        padding=(1, 2),
        expand=True
    )


# ============================================================================
# Scripts Section
# ============================================================================

def display_scripts(console: Console, scripts: List[str]) -> None:
    """Display startup scripts findings."""
    lines = []
    lines.append("[yellow]⚠️ Manual Review Required[/yellow]")
    lines.append("")
    lines.append("[dim]Automated CLI argument extraction is not yet implemented.[/dim]")
    lines.append("[dim]Please manually inspect these scripts to determine parameter values.[/dim]")
    lines.append("")
    lines.append("[bold]Scripts invoking the analyzed binary:[/bold]")
    lines.append("")

    # Create table for scripts
    table = Table(show_header=True, box=box.SIMPLE)
    table.add_column("#", justify="right", style="cyan")
    table.add_column("Script Path", style="yellow")

    for i, script in enumerate(scripts, 1):
        escaped_script = escape_rich_markup(script)
        table.add_row(str(i), f"`{escaped_script}`")

    lines.append(str(table))

    content = "\n".join(lines)

    console.print(Panel(
        content,
        title="[bold]📜 Startup Scripts Found[/bold]",
        border_style="yellow",
        padding=(1, 2)
    ))
