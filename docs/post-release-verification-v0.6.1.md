# Post-Release Verification — v0.6.1

The following items cannot be verified by static analysis, mocks, or protocol
traces. Run them against a real Gemini API key as the first action after
tagging v0.6.1.

### 1. Plumbing verification (diagnose stages 1–5)

Run `scrutics ai diagnose` end-to-end against a real key. Confirm stages
1–5 (configuration, API key presence, DNS, TLS, authentication) pass
cleanly. This verifies plumbing works with real network conditions.

### 2. Protocol read verification (diagnose stages 7–11)

Confirm stages 7–11 (plain text generation, tool declaration, function-call
generation, thought-signature handling, FunctionCall ID round trip) pass.

### 3. Rate-limit behavior

Deliberately trigger a 429 condition. Verify:
- Gemini's error body contains `google.rpc.RetryInfo.retryDelay`
- The client honors the server-provided delay within the 60s cap
- Retry progress is visible in CLI/TUI during backoff
- Terminal failure after 4 attempts surfaces a clear error

### 4. Parallel call structure

Trigger a parallel tool call from Gemini 3.8. Verify:
- The first functionCall part carries the signature
- Subsequent parts do not
- The response is one model Content block, not split
- Tool responses are one user Content block

### 5. Multi-turn agent conversation

Run question → tool call → final answer end-to-end. Verify no HTTP 400
on follow-up turns.

### Fallback

If any item fails, ship v0.6.2 with the fix within the same week.
