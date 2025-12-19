# tlscan Project Memory

## Overview
AI-powered **SSL/TLS security analyzer** for firmware binaries and scripts. Combines IDA Pro static analysis with multi-agent LLM system to detect SSL/TLS vulnerabilities and trace security-critical configuration values across firmware.

## Architecture

**Multi-Agent LangGraph Workflow**:
```
Checkpoint Router → SSL Analysis → Dataflow Analysis → Firmware Exploration → Synthesis
```

1. **Checkpoint Router**: Intelligent entry point for resuming from any workflow checkpoint
2. **SSL Analysis**: Checks binary against security rules (PASS/FAIL/CONDITIONAL/UNDETERMINED)
3. **Dataflow Analysis**: Traces variables to find concrete values (constants, config files, env vars)
4. **Firmware Exploration**: Searches for related binaries and config files across firmware
5. **Synthesis**: Generates final security report with evidence

**Checkpoint System**: State persistence with resumability via LangGraph's `AsyncSqliteSaver`. Each run is a "thread" with automatic state snapshots after every workflow node.

## Tech Stack
- **Python 3.13** with `uv` package manager
- **LangChain/LangGraph**: Multi-agent orchestration with state machine workflow
- **IDA Pro MCP**: Binary analysis via Model Context Protocol (ports 8800-8900)
- **Pydantic Models**: Structured agent outputs (not free-form text)
- **Rich**: Terminal UI with panels, tables, and color-coded output
- **LLM Providers**: DeepSeek, OpenAI, Anthropic (configured in `llm_config.yaml`)

## Project Structure

```
tlscan/
├── pyproject.toml
├── llm_config.yaml           # LLM API keys (gitignored)
├── src/
│   └── tlscan/               # Main package
│       ├── config/           # Configuration
│       │   ├── settings.py   # Code constants
│       │   └── loader.py     # Load llm_config.yaml
│       ├── analyzer/         # Core multi-agent analyzer
│       │   ├── main.py
│       │   ├── cli.py
│       │   ├── cache.py
│       │   ├── workflow/     # LangGraph workflow
│       │   │   ├── graph.py, nodes.py, state.py
│       │   │   ├── models.py, routing.py, formatter.py
│       │   ├── agents/       # LLM agents
│       │   │   ├── factory.py
│       │   │   ├── core/{context,execution,middleware}.py
│       │   │   └── prompts/{ssl,dataflow,firmware}.py
│       │   ├── static_engine/  # Binary analysis
│       │   │   ├── engine.py, firmware.py, scripts.py
│       │   │   └── ida/{server,ports}.py
│       │   ├── persistence/  # Checkpointing
│       │   │   └── checkpoints.py
│       │   └── utils/        # Utilities
│       │       ├── binary.py, files.py
│       │       ├── formatting.py, logging.py
│       ├── scanner/          # Network client scanner
│       │   ├── cli.py, detector.py
│       │   ├── version.py, indicators.py
│       ├── rulegen/          # Rule generator
│       │   ├── cli.py, builder.py
│       └── rules/            # Security rules (bundled)
│           ├── metarule.md, template.md
│           ├── openssl.md, curl.md, libcurl.md
│           ├── gnutls.md, mbedtls.md, wget.md
├── tests/
└── docs/paper/               # Academic paper materials
```

## Key Components

### `/src/tlscan/config/`
- **`settings.py`**: Configuration constants (token thresholds, IDA settings, paths)
- **`loader.py`**: Loads LLM API keys from `llm_config.yaml`

### `/src/tlscan/analyzer/`
- **`main.py`**: Main orchestrator - initializes LLM, loads rules, creates workflow
- **`cli.py`**: CLI argument parsing
- **`cache.py`**: Firmware cache management

### `/src/tlscan/analyzer/workflow/`
- **`graph.py`**: LangGraph state machine construction with checkpoint router entry point
- **`nodes.py`**: Workflow nodes (SSL analysis, dataflow, routing logic)
- **`state.py`**: `AnalysisState` TypedDict with all workflow state
- **`models.py`**: Pydantic models (`SSLAnalysisOutput`, `RuleResult`, `VariableTrace`, etc.)
- **`routing.py`**: Routing logic for conditional workflow branches
- **`formatter.py`**: Rich widget-based report display with color-coded status badges

### `/src/tlscan/analyzer/agents/`
- **`factory.py`**: Creates specialized agents with structured Pydantic output
  - SSL Agent: Analyzes security rules
  - Dataflow Agent: Traces variable values
  - Firmware Agent: Searches firmware filesystem
- **`core/`**: Execution infrastructure (context management, middleware)
- **`prompts/`**: System prompts for each agent type

### `/src/tlscan/analyzer/static_engine/`
- **`engine.py`**: Manages IDA Pro MCP servers for multiple binaries
- **`firmware.py`**: Filesystem search using `fd` and `ripgrep`
- **`scripts.py`**: Analysis tools for shell/PHP/Python scripts
- **`ida/server.py`**: Headless IDA server lifecycle management
- **`ida/ports.py`**: Dynamic port allocation with lock files

### `/src/tlscan/analyzer/utils/`
- **`binary.py`**: File type detection (ELF, shell, PHP, Python scripts)
- **`files.py`**: Path resolution and rule loading
- **`logging.py`**: State change logging with unified diff display
- **`formatting.py`**: Token counting and duration formatting

### `/src/tlscan/analyzer/persistence/`
- **`checkpoints.py`**: State persistence and thread management
  - CheckpointManager: Thread/checkpoint lifecycle with metadata storage
  - AsyncSqliteSaver: LangGraph's automatic checkpointing

### `/src/tlscan/scanner/`
Network client scanner for detecting SSL/TLS library usage:
- **`cli.py`**: CLI entry point (`tlscan-detect`)
- **`detector.py`**: Library detection and scoring logic
- **`version.py`**: Library version extraction from ELF binaries
- **`indicators.py`**: Library indicator sets (symbols, strings)

### `/src/tlscan/rulegen/`
Security rule generator:
- **`cli.py`**: CLI entry point (`tlscan-rulegen`)
- **`builder.py`**: Prompt building for rule generation

### `/src/tlscan/rules/`
Security rule definitions (Markdown), bundled with package:
- `metarule.md`: RFC-grounded security requirements (MUST/SHOULD/MAY)
- Library-specific rules: `openssl.md`, `curl.md`, `libcurl.md`, `gnutls.md`, `mbedtls.md`, `wget.md`, `socket.md`, `php_curl.md`

### `/docs/paper/`
Academic paper materials for top security conference submission.

## Entry Points & CLI

**Three CLI commands**:
- `tlscan` → Core analyzer (`tlscan.analyzer.cli:main`)
- `tlscan-detect` → Network client scanner (`tlscan.scanner.cli:main`)
- `tlscan-rulegen` → Rule generator (`tlscan.rulegen.cli:main`)

### Basic Analysis
```bash
tlscan \
   --model deepseek:deepseek-chat \
   -r openssl \
   --firmware-path /path/to/firmware \
   /path/to/binary.so
```

### Checkpoint & Resumption Flags
- `--save-checkpoints`: Enable automatic state persistence
- `--resume THREAD_ID`: Resume from thread's latest checkpoint
- `--fork-from-checkpoint CHECKPOINT_ID`: Fork from specific checkpoint (fresh execution)
- `--list-threads`: Show all analysis threads
- `--list-checkpoints THREAD_ID`: Show checkpoints in thread
- `--clean-threads --max-age DAYS`: Delete threads older than N days (default: 7)

### Scanner Usage
```bash
tlscan-detect /path/to/firmware
tlscan-detect /path/to/firmware --libraries openssl libcurl
tlscan-detect /path/to/firmware --json > results.jsonl
tlscan-detect /path/to/firmware --save-cache
```

**Arguments**:
- `binary_path`: Binary to analyze (optional for --list-threads/--clean-threads)
- `-m, --model`: LLM model (e.g., `deepseek:deepseek-chat`, `anthropic:claude-sonnet-4-5`)
- `-f, --firmware-path`: Firmware root (enables cross-binary analysis)
- `-r, --rules`: Security rule set (`openssl`, `curl`, `libcurl`, `gnutls`, `mbedtls`, `php_curl`, `wget`, `socket`)

## Important Patterns

### Enum Values
- **Always lowercase** (e.g., `pass`, `fail`, `conditional`, `undetermined`)
- Recent fix: Parsing errors from uppercase enum values

### Task Routing
- `DataflowTask.source_type` determines routing:
  - `CONSTANT` → Final result (stop)
  - `CONFIG_FILE` → Create config fetch task
  - `FUNCTION_PARAMETER` → Create cross-binary task
  - Others → Continue dataflow

**Concurrent Processing**:
- Firmware node processes ALL pending task types in single execution
- Pattern: Accumulation (not if/elif) prevents task starvation
- Types: Caller discovery, script discovery, config fetch
- Error isolation: Each type wrapped in try/except

### Checkpoint Router
- **Entry Point**: Workflow starts at `checkpoint_router_node` (not SSL analysis)
- **Smart Routing**: Examines state to determine correct starting node
  - No results yet → SSL analysis
  - SSL complete + pending dataflow → Dataflow analysis
  - Dataflow complete + pending config/firmware → Firmware exploration
  - All tasks done → Synthesis
- **State Field**: `_next_node` stores routing decision
- **Use Case**: Enables resuming from any checkpoint without replay

### Agent Output
- **Structured only** - agents return Pydantic models via `with_structured_output()`
- **Sequential tool calling** - prevents MCP timeout issues
- **Stopping conditions** - dataflow traces stop at constants, config files, or max depth

### IDA Pro Integration
- MCP server started per binary with **temp copy** for concurrent analysis
- Temp binaries stored in `/tmp/tlscan/binaries/{session_id}/`
- **Startup timeout**: 5 minutes (increased from 15 seconds)
- Tools available: `decompile_function`, `get_callers`, `get_xrefs_to`, etc.
- Port locks in `/tmp/tlscan/port_locks/`

### Script Analysis
- **File Type Detection**: `binary.detect_file_type()` identifies ELF, shell, PHP, Python
- **Tool Selection**: Scripts use `scripts.py` instead of IDA MCP
- **Script Tools**: `get_script_content()`, `get_lines()`, `search_pattern()`, `find_command_usage()`
- **Trace Type**: Script findings stored as `TraceType.SCRIPT`

## State Management

**`AnalysisState`** (TypedDict in `workflow/state.py`):
- **Context**: `binary_path`, `main_binary_path`, `security_rules`, `firmware_path`
- **SSL Results**: `rule_result` (Dict[str, RuleResult]), `applicable`, `client_type`
- **Tasks**: `pending_dataflow_tasks`, `pending_config_fetch_tasks`
- **Trace Graph**: `traces` (Dict[str, VariableTrace]), `rule_trace_links` (Dict[str, RuleTraceLink])
- **Statistics**: `statistics` (AnalysisStatistics with agent metrics)
- **Output**: `final_report`, `report_data`, `errors`
- **Control**: `current_phase`, `_next_node` (checkpoint router output)

### Unified Trace Graph Architecture

Traces form a directed acyclic graph (DAG) linking rule conditions to resolved values:

- **TraceType**: `MAIN_BINARY`, `CROSS_BINARY`, `CONFIG_FILE`, `SCRIPT`, `ENVIRONMENT`
- **VariableTrace**: Graph node with parent/child links and resolution status
- **RuleTraceLink**: Maps rule conditions to their root traces
- **Deduplication**: Content-based hashing prevents duplicate analysis
- **Graph Helpers**: `add_trace_to_graph()`, `resolve_trace_tree()`, `update_trace_statuses()`

## Checkpointing & Resumability

### Overview
Analysis state is automatically persisted after each workflow node execution using LangGraph's `AsyncSqliteSaver`. Each run is a "thread" with unique ID and metadata.

### Storage Structure
```
.state_snapshots/
├── checkpoints.db          # SQLite database (state snapshots)
└── metadata/
    └── {thread_id}.json    # Thread configuration & timestamps
```

### Thread Management

**Thread ID Format**: `{binary_name}_{YYYYMMDD}_{HHMMSS}_{short_hash}`

**Metadata Fields**:
- `binary_path`, `security_rules`, `model`, `firmware_path`
- `created_at`, `updated_at`
- `checkpoint_count`

### Implementation Pattern

**Async Initialization** (required):
```python
checkpoint_manager = CheckpointManager()
await checkpoint_manager.initialize()  # Must call in async context
checkpointer = checkpoint_manager.get_checkpointer()

# Workflow execution
compiled_graph = graph.compile(checkpointer=checkpointer)
result = await compiled_graph.ainvoke(
    initial_state,
    config={"configurable": {"thread_id": thread_id}}
)

# Cleanup
await checkpoint_manager.close()  # Close aiosqlite connection
```

## Report Display & Statistics

### Rich Widget-Based Reports
Report formatter (`workflow/formatter.py`) uses Rich library for visual output:
- **Status Badges**: Color-coded (PASS green, FAIL red, CONDITIONAL yellow)
- **Trace Type Icons**: main_binary, cross_binary, config_file, script
- **Panels**: Nested panels for rules, conditions, and trace trees
- **Tables**: Agent performance metrics and summary statistics

### Statistics Tracking

**AgentStatistics** (per agent):
- `total_tokens`, `thinking_tokens`, `tool_result_tokens`
- `tool_call_count`, `total_time_seconds`, `invocation_count`

**AnalysisStatistics** (overall):
- Per-agent stats: `ssl_agent`, `dataflow_agent`, `firmware_agent`
- Dependency counts: `config_dependency_count`, `script_dependency_count`, `cross_binary_dependency_count`
- Totals: `total_tokens`, `total_time_seconds`, `total_tool_calls`

## Meta-Rules (RFC-Grounded Requirements)

`src/tlscan/rules/metarule.md` defines implementation-agnostic SSL/TLS security requirements:

**MUST Requirements** (violations = FAIL):
- **M1**: TLS usage for security-sensitive communications (RFC 9325)
- **M2**: Protocol version TLS 1.2+ (RFC 8996 prohibits SSL/TLS 1.0/1.1)
- **M3**: Server certificate verification (RFC 5280)
- **M4**: Server identity verification via subjectAltName (RFC 9525)
- **M5**: Cipher suite selection with forward secrecy (RFC 9325)

**SHOULD Requirements** (violations = CONDITIONAL):
- **S1**: Certificate revocation checking (RFC 5280, RFC 6960)
- **S2**: Cryptographic strength (SHA-256+, RSA 2048+ bits) (RFC 9325)

**MAY Requirements** (optional enhancements):
- **O1**: Certificate pinning (RFC 7469, deprecated for browsers)

Library-specific rules reference these meta-rules for consistency.

## Commit Scopes

Use these scopes for conventional commit messages:

| Scope | Description | Examples |
|-------|-------------|----------|
| `workflow` | Workflow, nodes, state, routing, models | `feat(workflow): add synthesis node` |
| `agents` | Agent factory, prompts, LLM interactions | `fix(agents): handle timeout in ssl agent` |
| `state` | State management, AnalysisState fields | `refactor(state): simplify task tracking` |
| `persistence` | Checkpointing, thread management | `feat(persistence): add fork support` |
| `static-engine` | IDA Pro integration, MCP server, static analysis | `fix(static-engine): handle port conflicts` |
| `scanner` | Network client scanner | `feat(scanner): add version detection` |
| `rulegen` | Rule generator | `fix(rulegen): improve prompt builder` |
| `cli` | Command-line interface, argument parsing | `feat(cli): add --list-threads flag` |
| `rules` | Security rule definitions | `docs(rules): update openssl rule` |
| `config` | Configuration loading, llm_config | `fix(config): validate api keys` |
| `paper` | Academic paper materials (figures, writing) | `docs(paper): add threat model figure` |
| `logging` | Logging, output formatting, reporting | `refactor(logging): improve state diffs` |

**Guidelines**:
- Use the most specific scope that applies
- Omit scope for cross-cutting changes affecting multiple areas
- When in doubt, use the directory name of the primary file changed

## Development Notes

- Uses **src/ layout** with modern Python packaging
- Checkpoint system enables resumable analysis with state persistence in `.state_snapshots/`
- Fork-from-checkpoint: Load state, create new thread, run with fresh LLM calls
- Thread = complete analysis run with all checkpoints and metadata
- Firmware tools use `fd` and `rg` for fast searching
- Configuration in `llm_config.yaml` (gitignored - contains API keys)
- Rules are bundled with package, override via `SSLENS_RULES_DIR` environment variable
- **After implementation**: Always present a commit message in Conventional Commits format (see Commit Messages section)
- When using TodoWrite for multi-step tasks, the final step should be preparing the commit message
