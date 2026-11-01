# TLScan

TLScan is an automated tool for discovering TLS client security flaws in embedded firmware. It combines LLM-based analysis of verification logic with cross-component tracing to uncover vulnerabilities hidden in custom implementations and configuration-dependent behavior.

## Features

- Detect insecure TLS verification in firmware binaries and scripts.
- Trace security-critical values across components to determine vulnerability trigger conditions.
- Generate findings with code evidence to support validation and vulnerability triage.

## Requirements

- Linux with Python 3.13 or newer and [uv](https://docs.astral.sh/uv/).
- IDA Pro with the appropriate decompilers and idalib configured for binary analysis.
- Our modified [ida-pro-mcp](https://github.com/imnuke/ida-pro-mcp).
- `fd` and `ripgrep` for firmware filesystem searches.
- Access to a supported LLM backend.

## Setup

Set up IDA Pro and the modified ida-pro-mcp, then clone this repository and install the Python dependencies:

```bash
uv sync --locked
cp llm_config.example.yaml llm_config.yaml
```

Edit `llm_config.yaml` to configure your LLM credentials and the local path to the modified ida-pro-mcp checkout. Prepare an extracted firmware filesystem as the analysis input.

## Demo firmware

The demo image is `examples/firmware/X64_G3_4.3.3.RKD2.img` and is stored with Git LFS. Install Git LFS before cloning, then run `git lfs pull` to download the image. Extract it with Binwalk or Unblob, then analyze the extracted `libupsclient.so.0.0` with its firmware root:

```bash
uv run tlscan-detect /path/to/extracted-firmware --save-cache
uv run tlscan /path/to/extracted-firmware/path/to/libupsclient.so.0.0 \
  --firmware-path /path/to/extracted-firmware --rules openssl --verify
```

## License

TLScan is licensed under the GNU General Public License v3.0 only (GPL-3.0-only). See [LICENSE](LICENSE) for details.

Third-party components remain subject to their respective licenses.
