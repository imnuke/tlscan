# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

This project uses `uv` for Python package management:

- **Run the main application**: `uv run main.py`
- **Run demo**: `uv run demo.py`
- **Install dependencies**: `uv sync`
- **Add new dependencies**: `uv add <package>`
- **Run any Python script**: `uv run <script.py>`

## Architecture Overview

This is a Python project focused on connection analysis with LLM integration:

- **main.py**: Entry point with basic "Hello World" placeholder
- **demo.py**: Demonstrates LangChain integration with DeepSeek chat model and tool calling
- **tools/**: Module for analysis tools (currently contains placeholder files for IDA API and firmware traversal)
- **agents/**: Module for LLM agents (currently empty placeholder)

## Key Dependencies

- **LangChain**: Core framework for LLM applications (`langchain>=0.3.27`)
- **LangChain-DeepSeek**: DeepSeek model integration (`langchain-deepseek>=0.1.4`)

## Project Status

This appears to be an early-stage project with basic scaffolding in place. The demo.py shows tool calling capabilities with LangChain, suggesting the intended direction is toward building LLM-powered analysis tools.

**Note**: The demo.py contains an API key that should be moved to environment variables for security.