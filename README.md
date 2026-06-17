# PentrAI

PentrAI is an automated penetration-testing tool. A company can point it at its
own infrastructure to run security assessments and surface the exposures worth
fixing, instead of commissioning a manual engagement for every check.

An LLM agent drives a catalog of security tools through a single server over the
Model Context Protocol (MCP): a Flask backend (`pentrai_server.py`) wraps each
tool as an HTTP route, and an MCP client (`pentrai_mcp.py`) presents those tools
to the agent.

## Running it

```bash
python3 -m venv pentrai-env
source pentrai-env/bin/activate
pip install -r requirements.txt
python3 pentrai_server.py            # serves on 127.0.0.1:8888 by default
```

Point an MCP-capable client at the server using `pentrai-mcp.json` as a template
(set the script path and the server address). Override the bind address with the
`PENTRAI_HOST` environment variable.

The server shells out to external security tools; install the ones you need from
their official sources, alongside the Python libraries in `requirements.txt`.

## Status

Early stage. This README is intentionally short; fuller documentation will follow
as the product develops.

## License

MIT. See `LICENSE`.
