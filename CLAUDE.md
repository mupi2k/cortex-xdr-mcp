# cortex-xdr-mcp

MCP server for Palo Alto Networks Cortex XDR, providing alert and endpoint data for AI-assisted security triage workflows.

## Git workflow

- Always create a **new feature branch** from `main` before making changes. Never commit directly to `main` or reuse stale branches.
- Branch naming: `feat/<short-description>`, `fix/<short-description>`
- Open a PR and wait for explicit approval before merging — do not create and merge in the same step.

## Development

```bash
mise install       # installs Python and uv
uv sync            # installs dependencies into .venv
.venv/bin/python server.py  # run server directly for testing
```

## Testing changes

Test functions directly before committing:
```bash
.venv/bin/python -c "from server import get_endpoint; print(get_endpoint('hostname'))"
```
