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
    RuleResolvingStatus,
    RuleCondition,
    VariableTrace,
    ConstantDetails,
    ConfigFileDetails,
    FunctionParameterDetails,
    EnvironmentVariableDetails,
    CommandLineArgDetails,
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


def format_resolution_badge(status: RuleResolvingStatus) -> str:
    """Format resolution status with color markup."""
    badges = {
        RuleResolvingStatus.RESOLVED: "[green]✓ RESOLVED[/green]",
        RuleResolvingStatus.UNRESOLVED: "[red]✗ UNRESOLVED[/red]",
        RuleResolvingStatus.CANNOT_RESOLVE: "[dim]⊘ CANNOT_RESOLVE[/dim]",
    }
    return badges.get(status, f"[white]{status.value.upper()}[/white]")


def format_source_type_badge(source_type: str) -> str:
    """Format source type with emoji badge."""
    badges = {
        "constant": "🔢",
        "config_file": "📄",
        "environment_variable": "🌐",
        "command_line_arg": "⌨️",
        "function_parameter_from_external_call": "🔗",
        "unknown": "❓",
    }
    return badges.get(source_type, "•")


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
    traces = report_data["traces"]["main"]

    for rule_id, rule in rules.items():
        rule_panel = create_rule_panel(rule, traces)
        console.print(rule_panel)
        console.print()  # Spacing between rules

    # 4. Display cross-binary analysis (if any)
    cross_binary = report_data["traces"].get("cross_binary", {})
    if cross_binary:
        display_cross_binary(console, cross_binary)
        console.print()

    # 5. Display startup scripts (if any)
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

def create_rule_panel(rule: RuleResult, traces: Dict[str, List[VariableTrace]]) -> Panel:
    """Create a Rich Panel for a single security rule.

    Args:
        rule: RuleResult with status, evidence, and conditions
        traces: Dictionary mapping "function:variable" keys to trace lists

    Returns:
        Rich Panel with formatted rule information
    """
    renderables = []

    # Status
    status_text = f"[bold]Status:[/bold] {format_status_badge(rule.result)}"
    if rule.result == RuleResultStatus.CONDITIONAL:
        status_text += f"\n[bold]Resolution:[/bold] {format_resolution_badge(rule.resolving_status)}"

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
            # Create nested panel for each condition
            cond_panel = create_condition_panel(cond, traces)
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
# Condition Panel Creation
# ============================================================================

def create_condition_panel(
    condition: RuleCondition,
    traces: Dict[str, List[VariableTrace]]
) -> Panel:
    """Create a nested panel for a single condition.

    Args:
        condition: RuleCondition with variable, function, and security mapping
        traces: Dictionary of trace results

    Returns:
        Rich Panel with condition details
    """
    lines = []

    # Condition header
    var = escape_rich_markup(condition.variable)
    func = escape_rich_markup(condition.function)
    lines.append(f"[bold]Variable:[/bold] `{var}` in `{func}`")
    lines.append("")

    # Look up traces
    composite_key = f"{condition.function}:{condition.variable}"
    trace_list = traces.get(composite_key, [])

    if not trace_list:
        lines.append("[yellow]⚠️ No trace available for this variable[/yellow]")
    elif len(trace_list) == 1:
        # Single source
        trace_text = format_trace(trace_list[0], condition)
        lines.append(trace_text)
    else:
        # Multiple sources
        lines.append(f"[yellow]⚠️ Variable computed from {len(trace_list)} sources:[/yellow]")
        lines.append("")

        for i, trace in enumerate(trace_list, 1):
            lines.append(f"[bold]Source {i}:[/bold]")
            trace_text = format_trace(trace, condition, indent=True)
            lines.append(trace_text)
            if i < len(trace_list):
                lines.append("")  # Space between sources

    content = "\n".join(lines)

    return Panel(
        content,
        border_style="dim",
        padding=(1, 2),
        expand=False
    )


# ============================================================================
# Trace Formatting
# ============================================================================

def format_trace(
    trace: VariableTrace,
    condition: RuleCondition,
    indent: bool = False
) -> str:
    """Format a single variable trace.

    Args:
        trace: VariableTrace with source, value, and trace path
        condition: RuleCondition with security mapping
        indent: Whether to add extra indentation

    Returns:
        Formatted trace string with Rich markup
    """
    lines = []
    prefix = "  " if indent else ""

    # Source badge and type
    badge = format_source_type_badge(trace.source.value)
    source_name = escape_rich_markup(trace.source.value)
    lines.append(f"{prefix}{badge} [bold]Source:[/bold] {source_name}")
    lines.append(f"{prefix}")

    # Details based on source type
    lines.append(f"{prefix}[bold]Details:[/bold]")

    if isinstance(trace.source_details, ConstantDetails):
        const_val = escape_rich_markup(str(trace.source_details.constant_value))
        if trace.source_details.constant_name:
            const_name = escape_rich_markup(trace.source_details.constant_name)
            lines.append(f"{prefix}  • Constant `{const_name}` = `{const_val}`")
        else:
            lines.append(f"{prefix}  • Constant value: `{const_val}`")

    elif isinstance(trace.source_details, ConfigFileDetails):
        config_file = trace.source_details.config_file or "unknown"
        config_file = escape_rich_markup(config_file)
        lines.append(f"{prefix}  • Config file: `{config_file}`")
        if trace.source_details.config_key:
            key = escape_rich_markup(trace.source_details.config_key)
            lines.append(f"{prefix}  • Config key: `{key}`")

    elif isinstance(trace.source_details, FunctionParameterDetails):
        func = escape_rich_markup(trace.source_details.external_function or "unknown")
        param = escape_rich_markup(trace.source_details.parameter_name or "unknown")
        lines.append(f"{prefix}  • External call to `{func}`")
        lines.append(f"{prefix}  • Parameter: `{param}`")

    elif isinstance(trace.source_details, EnvironmentVariableDetails):
        env_var = escape_rich_markup(trace.source_details.env_var_name)
        lines.append(f"{prefix}  • Environment variable: `{env_var}`")

    elif isinstance(trace.source_details, CommandLineArgDetails):
        if trace.source_details.arg_name:
            arg = escape_rich_markup(trace.source_details.arg_name)
            lines.append(f"{prefix}  • Command-line argument: `{arg}`")
        else:
            lines.append(f"{prefix}  • Command-line argument")

    # Value
    if trace.value:
        val = escape_rich_markup(trace.value)
        lines.append(f"{prefix}  • [bold]Value:[/bold] `{val}`")

        # Outcome (if value maps to security outcome)
        if trace.value in condition.security_mapping:
            outcome = condition.security_mapping[trace.value]
            emoji = "✅" if "pass" in outcome.lower() else "❌"
            lines.append(f"{prefix}  • [bold]Outcome:[/bold] {emoji} {outcome}")

    # Trace path
    lines.append(f"{prefix}")
    lines.append(f"{prefix}[bold]Trace Path:[/bold]")

    trace_lines = trace.trace_path.split('\n')
    for line in trace_lines:
        if line.strip():
            # Escape any Rich markup in trace content
            escaped_line = escape_rich_markup(line)
            lines.append(f"{prefix}  {escaped_line}")

    return "\n".join(lines)


# ============================================================================
# Cross-Binary Section
# ============================================================================

def display_cross_binary(console: Console, cross_binary: Dict[str, Dict[str, List[VariableTrace]]]) -> None:
    """Display cross-binary analysis findings."""
    console.print(Panel.fit(
        "[bold cyan]🔄 Cross-Binary Analysis[/bold cyan]",
        border_style="cyan"
    ))
    console.print()

    for binary_path, traces in cross_binary.items():
        # Group traces by function
        traces_by_function = {}
        for trace_key, traces_list in traces.items():
            for trace in traces_list:
                if trace.function not in traces_by_function:
                    traces_by_function[trace.function] = []
                traces_by_function[trace.function].append(trace)

        # Create panel for this binary
        lines = []
        for function, function_traces in traces_by_function.items():
            lines.append(f"[bold]Function:[/bold] `{escape_rich_markup(function)}`")
            lines.append("")

            for trace in function_traces:
                # Variable name
                var = escape_rich_markup(trace.variable)
                lines.append(f"  • [bold]Variable:[/bold] `{var}`")

                # Source type
                badge = format_source_type_badge(trace.source.value)
                source = escape_rich_markup(trace.source.value)
                lines.append(f"    [bold]Source:[/bold] {badge} {source}")

                # Show brief details
                if isinstance(trace.source_details, ConstantDetails):
                    val = escape_rich_markup(str(trace.source_details.constant_value))
                    lines.append(f"    [bold]Value:[/bold] `{val}`")
                elif isinstance(trace.source_details, ConfigFileDetails):
                    if trace.source_details.config_file:
                        cfg = escape_rich_markup(trace.source_details.config_file)
                        lines.append(f"    [bold]Config:[/bold] `{cfg}`")

                # Trace preview (abbreviated)
                if trace.trace_path:
                    preview = trace.trace_path[:100]
                    if len(trace.trace_path) > 100:
                        preview += "..."
                    preview = escape_rich_markup(preview)
                    lines.append(f"    [dim]Trace: {preview}[/dim]")

                lines.append("")

        content = "\n".join(lines)
        escaped_path = escape_rich_markup(binary_path)

        console.print(Panel(
            content,
            title=f"[bold]Binary:[/bold] `{escaped_path}`",
            border_style="cyan",
            padding=(1, 2)
        ))
        console.print()


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
