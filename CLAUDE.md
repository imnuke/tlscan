# conn-alanyzer Project Memory

## Overview
AI-powered **SSL/TLS security analyzer** for firmware binaries. Combines IDA Pro static analysis with multi-agent LLM system to detect SSL/TLS vulnerabilities and trace security-critical configuration values across firmware.

## Architecture

**Multi-Agent LangGraph Workflow** (4 phases):
```
SSL Analysis � Dataflow Analysis � Firmware Exploration � Synthesis
```

1. **SSL Analysis**: Checks binary against security rules (PASS/FAIL/CONDITIONAL/UNDETERMINED)
2. **Dataflow Analysis**: Traces variables to find concrete values (constants, config files, env vars)
3. **Firmware Exploration**: Searches for related binaries and config files across firmware
4. **Synthesis**: Generates final security report with evidence

## Tech Stack
- **Python 3.13** with `uv` package manager
- **LangChain/LangGraph**: Multi-agent orchestration with state machine workflow
- **IDA Pro MCP**: Binary analysis via Model Context Protocol (ports 8800-8900)
- **Pydantic Models**: Structured agent outputs (not free-form text)
- **LLM Providers**: DeepSeek, OpenAI, Anthropic (configured in `llm_config.yaml`)

## Key Components

### `/conn_analyzer/`
- **`main.py`**: Main orchestrator - initializes LLM, loads rules, creates workflow
- **`cli.py`**: CLI argument parsing
- **`config_loader.py`**: Loads LLM API keys from `llm_config.yaml`

### `/conn_analyzer/agents/`
- **`factory.py`**: Creates specialized agents with structured Pydantic output
  - SSL Agent: Analyzes security rules
  - Dataflow Agent: Traces variable values
  - Firmware Agent: Searches firmware filesystem
- **`prompts/`**: System prompts for each agent type

### `/conn_analyzer/graph/`
- **`workflow.py`**: LangGraph state machine construction
- **`nodes.py`**: Workflow nodes (SSL analysis, dataflow, routing logic)
- **`state.py`**: `AnalysisState` TypedDict with all workflow state
- **`models.py`**: Pydantic models (`SSLAnalysisOutput`, `RuleResult`, `VariableTrace`, etc.)

### `/conn_analyzer/static_analysis/`
- **`engine.py`**: Manages IDA Pro MCP servers for multiple binaries
  - Thread-safe multi-binary support
  - Session caching and port allocation
- **`firmware_tools.py`**: Filesystem search using `fd` and `ripgrep`

### `/conn_analyzer/ida_integration/`
- **`server.py`**: Headless IDA server lifecycle management
- **`port_manager.py`**: Dynamic port allocation with lock files

### `/security_rules/`
Security rule definitions (Markdown):
- `rule_openssl.md`, `rule_curl.md`, `rule_libcurl.md`, `rule_gnutls.md`, etc.

## Entry Point

**CLI**: `conn_analyzer_new.py`

```bash
uv run conn_analyzer_new.py \
   --model deepseek:deepseek-chat \
   -r openssl \
   --firmware-path /home/peng/MyWorkspace/firmwares/mydataset/Asustor/AS3204T_4.3.3_RKD2 initramfs_extract/xz.uncompressed_extract/usr/lib/libupsclient.so.6.0.0
```

**Arguments**:
- `binary_path`: Binary to analyze (required)
- `-m, --model`: LLM model (e.g., `deepseek-chat`, `anthropic:claude-sonnet-4-5`)
- `-f, --firmware-path`: Firmware root (enables cross-binary analysis)
- `-r, --rules`: Security rule set (default: `openssl`)

## Important Patterns

### Enum Values
- **Always lowercase** (e.g., `pass`, `fail`, `conditional`, `undetermined`)
- Recent fix: Parsing errors from uppercase enum values

### Task Routing
- `DataflowTask.source_type` determines routing:
  - `CONSTANT` � Final result (stop)
  - `CONFIG_FILE` � Create config fetch task
  - `FUNCTION_PARAMETER` � Create cross-binary task
  - Others � Continue dataflow

### Agent Output
- **Structured only** - agents return Pydantic models via `with_structured_output()`
- **Sequential tool calling** - prevents MCP timeout issues
- **Stopping conditions** - dataflow traces stop at constants, config files, or max depth

### IDA Pro Integration
- MCP server started per binary: `uv run --directory /path/to/ida-pro-mcp idalib-mcp --host localhost --port <PORT> <BINARY>`
- Tools available: `decompile_function`, `get_callers`, `get_xrefs_to`, etc.
- Port locks in `/tmp/conn_analyzer/port_locks/`

## State Management

**`AnalysisState`** (TypedDict in `graph/state.py`):
- **Context**: `binary_path`, `security_rules`, `firmware_path`
- **SSL Results**: `rule_result` (Dict[str, RuleResult]), `applicable`, `client_type`
- **Tasks**: `pending_dataflow_tasks`, `pending_cross_binary_tasks`
- **Results**: `variable_traces`, `cross_binary_traces`, `external_values`
- **Output**: `final_report`, `errors`
- **Control**: `current_phase`, `depth` (recursion tracking)

## Development Notes

- Uses **v2 architecture** with modular design
- Recent focus on prompt refinement and task routing logic
- Firmware tools use `fd` and `rg` for fast searching
- Configuration in `llm_config.yaml` (gitignored - contains API keys)
