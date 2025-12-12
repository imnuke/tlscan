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
    RuleTraceLink,
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
    traces = report_data.get("traces", {})
    rule_trace_links = report_data.get("rule_trace_links", {})

    for rule_id, rule in rules.items():
        rule_panel = create_rule_panel(rule, traces, rule_trace_links)
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
# Rule Panel Creation
# ============================================================================

def create_rule_panel(
    rule: RuleResult,
    traces: Dict[str, VariableTrace],
    rule_trace_links: Dict[str, RuleTraceLink],
) -> Panel:
    """Create a Rich Panel for a single security rule using unified trace graph.

    Args:
        rule: RuleResult with status, evidence, and conditions
        traces: Dict of all traces by ID
        rule_trace_links: Dict of rule-to-trace links

    Returns:
        Rich Panel with formatted rule information
    """
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
            cond_panel = create_condition_panel_from_graph(cond, traces, rule_trace_links)
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


# ============================================================================
# Unified Trace Graph Formatting
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


def format_trace_step(step: TraceStep, prefix: str = "") -> str:
    """Format a single trace step with Rich markup.

    Args:
        step: TraceStep to format
        prefix: Indentation prefix

    Returns:
        Formatted step string
    """
    # Step type badges
    type_badges = {
        TraceStepType.TRACE_START: "🔷",
        TraceStepType.CALL_SITE: "📍",
        TraceStepType.PARAMETER_TRANSFORM: "🔄",
        TraceStepType.VARIABLE_ASSIGNMENT: "📝",
        TraceStepType.TRACE_END: "🏁",
    }
    badge = type_badges.get(step.step_type, "•")

    # Build step description
    parts = [f"{prefix}{badge} [dim]Step {step.step_number}:[/dim]"]

    # Add function and address if available
    if step.function:
        func = escape_rich_markup(step.function)
        if step.address:
            parts.append(f"`{func}` @ {step.address}")
        else:
            parts.append(f"`{func}`")

    # Add description
    desc = escape_rich_markup(step.description)
    parts.append(f"- {desc}")

    # For TRACE_END, show source_kind details
    if step.step_type == TraceStepType.TRACE_END and step.source_kind:
        source_badge = format_source_kind_badge(step.source_kind.value)
        parts.append(f"[{source_badge}]")

        if step.constant_value:
            parts.append(f"= `{step.constant_value}`")
        elif step.external_function:
            ext_func = escape_rich_markup(step.external_function)
            param = escape_rich_markup(step.parameter_name or "?")
            parts.append(f"→ `{ext_func}:{param}`")

    return " ".join(parts)


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

    # Display trace_path steps
    if trace.trace_path:
        lines.append(f"{prefix}   [bold]Trace Path:[/bold]")
        for step in trace.trace_path:
            step_text = format_trace_step(step, prefix=prefix + "     ")
            lines.append(step_text)

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
