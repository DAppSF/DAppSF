# Development Conventions & Rules for Aider

## Execution & Architecture Constraints
- Target platform is a Linux Docker container analyzing macOS Mach-O app bundles (`.app` / `.zip`).
- Linux cannot execute Mach-O binaries natively: NEVER attempt dynamic execution, local process spawning, or local `frida-inject` calls on Mach-O files. All binary checks must use static analysis heuristics (parsing plists, Mach-O load commands, strings, and entitlements).
- Avoid bloated diffs: Only touch the exact functions, templates, or lines required. Do not refactor unrelated code.

## Flask & Logging Standards
- Always use Python's standard `logging` module (`logger = logging.getLogger(__name__)`), never bare `print()`.
- Log incoming requests with relevant metadata (job_id, filename).
- Use `logger.exception(...)` inside `except` blocks so tracebacks are preserved.

## Frontend & UI Rules
- In `templates/result.html`, keep JavaScript vanilla (no external CDN dependencies unless already imported in `base.html`).
- Ensure sorting scripts handle both text and badge values cleanly.
- Never introduce elements with `pointer-events: none` that block form inputs or buttons.

## Git & Workflow Rules
- Generate concise, conventional commit messages (e.g., `feat:`, `fix:`, `refactor:`).
- Do not add or edit files unless explicitly instructed or required for the task.
