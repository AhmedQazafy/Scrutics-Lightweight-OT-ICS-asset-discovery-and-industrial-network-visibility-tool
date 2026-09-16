#!/usr/bin/env python3
"""Manual verification script for Ollama provider and Semantic Agent Loop."""

import os
import sys
from scrutics.ai.config import load_ai_config, build_provider
from scrutics.ai.provider import LLMConnectionError, LLMProviderError
from scrutics.ai.tools import SessionContext
from scrutics.ai.agent import run_agent_loop


def find_latest_session() -> str | None:
    """Find the most recent session directory in output/."""
    base = "output"
    if not os.path.exists(base):
        return None
    sessions = sorted(
        [os.path.join(base, d) for d in os.listdir(base)
         if os.path.isdir(os.path.join(base, d)) and d.startswith("scrutics_")],
        reverse=True
    )
    return sessions[0] if sessions else None


def main():
    print("[*] Loading AI config...")
    config = load_ai_config()
    print(f"[*] Loaded config: {config}")

    print("[*] Building LLM provider...")
    provider = build_provider(config)
    print(f"[*] Provider created: {provider.__class__.__name__} (model={getattr(provider, 'model', 'unknown')}, base_url={getattr(provider, 'base_url', 'unknown')})")

    session_dir = find_latest_session()
    if session_dir and os.path.exists(os.path.join(session_dir, "manifest.json")):
        print(f"[*] Found session directory: {session_dir}")
        ctx = SessionContext(session_dir)
        print(f"[*] Loaded SessionContext: {len(ctx.assets)} assets, {len(ctx.connections)} connections, {len(ctx.anomalies)} anomalies")

        print("[*] Testing run_agent_loop with query: 'Summarize the assets discovered in this session.'")
        try:
            answer = run_agent_loop(provider, ctx, "Summarize the assets discovered in this session.")
            print(f"[+] Agent Loop Response:\n{answer}")
        except LLMConnectionError as e:
            print(f"[-] Ollama connection error (expected if Ollama is not running): {e}")
        except LLMProviderError as e:
            print(f"[-] LLM provider error: {e}")
    else:
        print("[!] No session directory with manifest.json found in output/. Testing basic chat completion...")
        try:
            response = provider.chat([{"role": "user", "content": "Say hello in exactly three words."}])
            print(f"[+] Response received: {response}")
        except LLMConnectionError as e:
            print(f"[-] Ollama connection error (expected if Ollama is not running): {e}")
        except LLMProviderError as e:
            print(f"[-] LLM provider error: {e}")


if __name__ == "__main__":
    main()
