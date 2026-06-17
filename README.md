# Cortex XDR MCP Server

A [FastMCP](https://github.com/jlowin/fastmcp) server that exposes Palo Alto Networks Cortex XDR alert and endpoint data as MCP tools, enabling AI-assisted security triage workflows.

## Requirements

- [mise](https://mise.jdx.dev/) for tool management
- Python 3.10+

## Setup

```bash
mise install       # installs Python and uv
mise run install   # installs dependencies into .venv
```

## Configuration

The following environment variables are required:

| Variable | Description |
|---|---|
| `CORTEX_API_KEY` | Cortex XDR Standard API key |
| `CORTEX_API_KEY_ID` | Numeric ID for the API key (shown in the API Keys table in the Cortex console) |
| `CORTEX_URL` | Your tenant's API base URL, e.g. `https://api-<tenant>.xdr.us.paloaltonetworks.com` |

> **Note:** This server uses **Standard** API key authentication (`x-xdr-auth-id` + `Authorization` headers). Advanced API keys use a different auth scheme and are not supported.

## Claude Code Setup

After running `mise install` and `uv sync`, register the server using the venv's Python so it works regardless of what's on your shell PATH:

```bash
claude mcp add --scope user cortex-xdr -- /path/to/cortex-mcp/.venv/bin/python /path/to/cortex-mcp/server.py
```

Ensure the required environment variables are available in the shell session where Claude Code runs.

## Tools

| Tool | Description |
|---|---|
| `get_alert` | Get full details for an alert by ID (severity, category, actor, host, MITRE info) |
| `get_alert_process_details` | Get the process causality chain for an alert using XQL (±5 min window around detection) |
| `search_alerts` | Search alerts by hostname, username, severity, and/or alert name |
| `get_alerts_for_endpoint` | Get recent alerts for a given hostname |
| `get_endpoint` | Get endpoint details by hostname (OS, IP, users, status) |

## Notes

- `get_alert_process_details` uses the XQL API to query `xdr_data` for process events around the alert's detection timestamp. XQL access must be enabled for the API key.
- `search_alerts` fetches up to 100 alerts server-side (filtered by time and optionally severity) then filters hostname, username, and alert name client-side.
- The XQL `get_alert_process_details` tool returns a ±5-minute window of process events on the alert's host — useful for understanding the causality chain without navigating to the Cortex UI.
