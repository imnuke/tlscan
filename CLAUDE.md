# conn-alanyzer Project Memory

## Overview
AI-powered **SSL/TLS security analyzer** for firmware binaries. Combines IDA Pro static analysis with multi-agent LLM system to detect SSL/TLS vulnerabilities and trace security-critical configuration values across firmware.

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
- **`workflow.py`**: LangGraph state machine construction with checkpoint router entry point
- **`nodes.py`**: Workflow nodes (SSL analysis, dataflow, routing logic)
- **`state.py`**: `AnalysisState` TypedDict with all workflow state
- **`models.py`**: Pydantic models (`SSLAnalysisOutput`, `RuleResult`, `VariableTrace`, etc.)
- **`routing.py`**: Routing logic for conditional workflow branches

### `/conn_analyzer/static_analysis/`
- **`engine.py`**: Manages IDA Pro MCP servers for multiple binaries
  - Thread-safe multi-binary support
  - Session caching and port allocation
- **`firmware_tools.py`**: Filesystem search using `fd` and `ripgrep`

### `/conn_analyzer/ida_integration/`
- **`server.py`**: Headless IDA server lifecycle management
- **`port_manager.py`**: Dynamic port allocation with lock files

### `/conn_analyzer/persistence/`
- **`checkpointing.py`**: State persistence and thread management
  - CheckpointManager: Thread/checkpoint lifecycle with metadata storage
  - AsyncSqliteSaver: LangGraph's automatic checkpointing
  - Age-based cleanup utilities
  - Storage: `.state_snapshots/checkpoints.db` (SQLite)
  - Metadata: `.state_snapshots/metadata/{thread_id}.json`

### `/security_rules/`
Security rule definitions (Markdown):
- `rule_openssl.md`, `rule_curl.md`, `rule_libcurl.md`, `rule_gnutls.md`, etc.

## Entry Point & CLI

**Main Entry**: `conn_analyzer_new.py` → `conn_analyzer/cli.py`

### Basic Analysis
```bash
uv run conn_analyzer_new.py \
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

### Example: Resume & Fork Workflow
```bash
# Run with checkpointing enabled
uv run conn_analyzer_new.py binary.so -m deepseek:deepseek-chat --save-checkpoints

# List available threads
uv run conn_analyzer_new.py --list-threads

# List checkpoints in specific thread
uv run conn_analyzer_new.py --list-checkpoints libssl_20241203_143052

# Fork from checkpoint (creates new thread, fresh LLM calls)
uv run conn_analyzer_new.py \
  --resume libssl_20241203_143052 \
  --fork-from-checkpoint 550e8400-e29b-41d4-a716-446655440000

# Cleanup old threads
uv run conn_analyzer_new.py --clean-threads --max-age 7
```

**Arguments**:
- `binary_path`: Binary to analyze (optional for --list-threads/--clean-threads)
- `-m, --model`: LLM model (e.g., `deepseek:deepseek-chat`, `anthropic:claude-sonnet-4-5`), overrides saved metadata when resuming
- `-f, --firmware-path`: Firmware root (enables cross-binary analysis)
- `-r, --rules`: Security rule set (default: `openssl`)

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
- MCP server started per binary: `uv run --directory /path/to/ida-pro-mcp idalib-mcp --host localhost --port <PORT> <BINARY>`
- Tools available: `decompile_function`, `get_callers`, `get_xrefs_to`, etc.
- Port locks in `/tmp/conn_analyzer/port_locks/`

## State Management

**`AnalysisState`** (TypedDict in `graph/state.py`):
- **Context**: `binary_path`, `security_rules`, `firmware_path`
- **SSL Results**: `rule_result` (Dict[str, RuleResult]), `applicable`, `client_type`
- **Tasks**: `pending_dataflow_tasks`, `pending_config_fetch_tasks`
- **Results**: `variable_traces`, `cross_binary_traces`, `external_values`, `script_findings`
- **Output**: `final_report`, `errors`
- **Control**: `current_phase`, `depth` (recursion tracking), `_next_node` (checkpoint router output)

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

### Resumption Modes

**1. Resume from Latest**
```bash
uv run conn_analyzer_new.py --resume libssl_20241203_143052
```
- Loads thread metadata (model, rules, firmware_path)
- Uses CLI `--model` override if provided
- Continues from last checkpoint
- Checkpoint router determines starting node

**2. Fork from Checkpoint**
```bash
uv run conn_analyzer_new.py \
  --resume libssl_20241203_143052 \
  --fork-from-checkpoint <UUID>
```
- Loads state from specific checkpoint
- Creates NEW thread ID
- Runs with fresh LLM calls (no replay)
- Useful for exploring alternative analysis paths

### Maintenance

**List Operations**:
- `--list-threads`: Show all threads with metadata
- `--list-checkpoints THREAD_ID`: Show all checkpoints in thread

**Cleanup**:
```bash
uv run conn_analyzer_new.py --clean-threads --max-age 7
```
- Deletes threads older than 7 days (default)
- Removes SQLite records + metadata JSON files
- Shows summary before deletion

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

## Commit Scopes

Use these scopes for conventional commit messages:

| Scope | Description | Examples |
|-------|-------------|----------|
| `graph` | Workflow, nodes, state, routing, models | `feat(graph): add synthesis node` |
| `agents` | Agent factory, prompts, LLM interactions | `fix(agents): handle timeout in ssl agent` |
| `state` | State management, AnalysisState fields | `refactor(state): simplify task tracking` |
| `persistence` | Checkpointing, thread management | `feat(persistence): add fork support` |
| `ida` | IDA Pro integration, MCP server, static analysis | `fix(ida): handle port conflicts` |
| `firmware` | Firmware exploration, filesystem tools | `feat(firmware): add config file search` |
| `cli` | Command-line interface, argument parsing | `feat(cli): add --list-threads flag` |
| `rules` | Security rule definitions | `docs(rules): update openssl rule` |
| `config` | Configuration loading, llm_config | `fix(config): validate api keys` |
| `logging` | Logging, output formatting, reporting | `refactor(logging): improve state diffs` |

**Guidelines**:
- Use the most specific scope that applies
- Omit scope for cross-cutting changes affecting multiple areas
- When in doubt, use the directory name of the primary file changed

## Development Notes

- Uses **v2 architecture** with modular design
- Checkpoint system enables resumable analysis with state persistence in `.state_snapshots/`
- Fork-from-checkpoint: Load state, create new thread, run with fresh LLM calls
- Thread = complete analysis run with all checkpoints and metadata
- Firmware tools use `fd` and `rg` for fast searching
- Configuration in `llm_config.yaml` (gitignored - contains API keys)
- **After implementation**: Always present a commit message in Conventional Commits format (see Commit Messages section)
- When using TodoWrite for multi-step tasks, the final step should be preparing the commit message
