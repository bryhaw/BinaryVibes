# Security Policy

## Important Security Caveats

BinaryVibes generates and optionally executes native machine code from LLM output.
This has inherent security implications that users must understand.

### LLM-Generated Code Execution

**`--run-verify` executes unsandboxed binaries.** When enabled, the tool writes
LLM-generated machine code to a temp file and runs it via `subprocess.run()`.
The binary can perform any operation the current user is permitted to do:

- Read/write/delete files
- Make network connections
- Spawn processes
- Access environment variables and credentials

**Mitigations in place:**
- Temp files are created with owner-only permissions (0o700)
- A 10-second timeout kills runaway processes
- Console windows are suppressed on Windows
- Temp files are cleaned up in a `finally` block

**Recommended practices:**
- Only use `--run-verify` in disposable environments (VMs, containers)
- Never run as root/Administrator
- Use network-restricted environments when possible
- Review generated assembly before running (`bv build` prints it)

### LLM Output Trust

The LLM's assembly output is passed to the Keystone assembler, which validates
syntax but not semantics. A compromised or adversarial LLM could generate
syntactically valid assembly that performs malicious operations. Even without
`--run-verify`, the generated binary written to disk could be executed later.

**Mitigations in place:**
- Output binaries are written with owner-only permissions (0o700)
- Output paths are validated against sensitive system directories
- The assembly is displayed to the user before the binary is written

### API Key Handling

- API keys are read from the `BV_LLM_API_KEY` environment variable (preferred)
  or the `--api-key` CLI flag
- **Avoid `--api-key`** — it exposes the key in shell history and `ps` output
- Keys are never logged, printed, or written to disk
- Keys are transmitted only over HTTPS to the configured provider endpoint
- Error messages are sanitized to avoid leaking API responses or tokens

### Dependency Supply Chain

Dependencies in `pyproject.toml` are pinned to major version ranges (e.g.,
`>=5.0,<6`) to prevent unexpected breaking changes while still receiving
patch-level security fixes. For production deployments, consider using a
lockfile (`pip freeze`, `pip-tools`, or `uv lock`) to pin exact versions.

### Output Path Safety

The CLI validates output paths (`-O`) to prevent writes to sensitive system
directories (`/etc`, `/usr`, `/bin`, etc.). Generated binaries are written with
restrictive file permissions (owner read/write/execute only).

### Temp File Safety

- Temp files use `mkstemp()` for atomic creation with no race window
- Permissions are set to owner-only (0o700) before execution
- Cleanup occurs in `finally` blocks to handle crashes
- Files are removed even if the subprocess times out or errors

## Reporting Vulnerabilities

If you discover a security vulnerability in BinaryVibes, please report it
privately by emailing bryhaw@gmail.com. Do not open a public issue for
security vulnerabilities.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We aim to acknowledge reports within 48 hours and provide a fix within 7 days
for critical issues.
