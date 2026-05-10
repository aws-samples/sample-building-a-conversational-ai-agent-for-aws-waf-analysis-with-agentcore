# Contributing

Thanks for your interest in contributing to WAF Agent.

## Getting Started

1. Fork the repository
2. Clone your fork and install dependencies:
   ```bash
   pip install -e ".[dev]"
   ```
3. Create a branch for your change:
   ```bash
   git checkout -b my-feature
   ```

## Development

Run locally without AG-UI dependencies:

```bash
export AWS_PROFILE=your-profile
python agent.py "List all WebACLs"
```

Run tests:

```bash
pytest
```

## Code Style

- Python 3.12+
- Keep tools deterministic (no LLM calls inside tools)
- Match existing patterns: `@tool` decorator, return formatted strings, use `session_state` for cross-tool coordination
- Sanitize all user-provided parameters before embedding in queries

## Adding a New Tool

1. Create `tools/your_tool.py` with a `@tool` decorated function
2. Import and add to `_TOOLS` list in `agent.py`
3. Add guidance to the system prompt if the LLM needs to know when/how to use it
4. Test with `python agent.py "prompt that triggers your tool"`

## Submitting Changes

1. Ensure your code works locally against a real WAF environment
2. Commit with a clear message describing what and why
3. Push and open a merge request
4. Describe what you tested in the MR description

## Reporting Issues

Open an issue with:
- What you were trying to do
- What happened instead
- WebACL scope (CLOUDFRONT or REGIONAL) and log destination type (CWL or S3)
