#!/usr/bin/env bash
# Scrutics AI Setup — run once to configure the AI assistant.
# Saves your API key in ~/.scrutics/ai_keys.sh (readable only by you), makes new terminals load it,
# and writes ai.yaml. The key is passed to Python on standard input or in the environment, never on
# a command line or inside code.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The directory that contains the scrutics package, for running its modules from a checkout
PACKAGE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
export PYTHONPATH="$PACKAGE_ROOT${PYTHONPATH:+:$PYTHONPATH}"
# Write user config to ~/.scrutics/ai.yaml — never overwrite the packaged template
YAML_PATH="$HOME/.scrutics/ai.yaml"
mkdir -p "$HOME/.scrutics"

echo ""
echo " ============================================================"
echo "  Scrutics AI Setup"
echo " ============================================================"
echo ""
echo " This script configures the AI assistant for Scrutics."
echo " It saves your API key and updates ai.yaml automatically."
echo " You will not need to edit any files manually."
echo ""
echo " Which AI provider do you want to use?"
echo ""
echo "   1. Google Gemini   (free tier available - recommended)"
echo "   2. OpenAI          (paid account required)"
echo "   3. Anthropic       (paid account required)"
echo "   4. Ollama (local)  (no API key needed)"
echo "   5. Disable AI assistant"
echo "   6. Reset configuration"
echo "   7. Exit"
echo ""
read -rp "  Enter 1-7: " choice

case "$choice" in
    1)
        VAR_NAME="GEMINI_API_KEY"
        PROVIDER_LABEL="Google Gemini"
        KEY_URL="https://aistudio.google.com/app/apikey"
        YAML_PROVIDER="gemini"
        YAML_MODEL="gemini-3.8-flash"
        ;;
    2)
        VAR_NAME="OPENAI_API_KEY"
        PROVIDER_LABEL="OpenAI"
        KEY_URL="https://platform.openai.com/api-keys"
        YAML_PROVIDER="openai"
        YAML_MODEL="gpt-6-luna"
        ;;
    3)
        VAR_NAME="ANTHROPIC_API_KEY"
        PROVIDER_LABEL="Anthropic"
        KEY_URL="https://console.anthropic.com/settings/keys"
        YAML_PROVIDER="anthropic"
        YAML_MODEL="claude-haiku-5-5"
        ;;
    4)
        VAR_NAME=""
        PROVIDER_LABEL="Ollama"
        KEY_URL=""
        YAML_PROVIDER="ollama"
        YAML_MODEL="qwen3.5:4b"
        USER_KEY=""  # No key needed for Ollama
        ;;
    5)
        # Disable AI
        if [[ ! -f "$YAML_PATH" ]]; then
            echo " AI config not found. Nothing to disable."
            exit 0
        fi
        sed -i 's/^enabled: true/enabled: false/' "$YAML_PATH" 2>/dev/null || {
            echo " Failed to disable AI. Check file permissions."
            exit 1
        }
        echo ""
        echo " ✓ AI assistant disabled."
        echo " To re-enable, run this script again or delete $YAML_PATH"
        exit 0
        ;;
    6)
        # Reset config
        if [[ ! -f "$YAML_PATH" ]]; then
            echo " AI config not found. Nothing to reset."
            exit 0
        fi
        rm "$YAML_PATH" 2>/dev/null || {
            echo " Failed to delete config. Check file permissions."
            exit 1
        }
        echo ""
        echo " ✓ AI configuration deleted."
        echo " Run this script again to set up from scratch."
        exit 0
        ;;
    7|"")
        echo " Exiting."
        exit 0
        ;;
    *)
        echo " Invalid choice. Run the script again."
        exit 1
        ;;
esac

# Skip key prompt for Ollama
if [[ -n "$VAR_NAME" ]]; then
    echo ""
    echo " Get your $PROVIDER_LABEL API key from:"
    echo "   $KEY_URL"
    echo ""

    # Read key without echo
    read -rsp " Paste API key (hidden input): " USER_KEY
    echo ""

    if [[ -z "$USER_KEY" ]]; then
        echo " No key entered. Nothing was changed."
        exit 0
    fi
else
    echo ""
    echo " Using Ollama (no API key required)"
    echo " Make sure Ollama is installed and running: https://ollama.com"
fi

echo ""
echo " Setting up Scrutics AI..."

# Store the key (skip for Ollama). printf is a shell builtin, so the key is never on a command
# line; Python reads it from standard input.
if [[ -n "$VAR_NAME" ]]; then
    if ! printf '%s\n' "$USER_KEY" | python3 -m scrutics.ai.key_store set "$VAR_NAME"; then
        echo " The key was not saved. Nothing else was changed."
        exit 1
    fi
    # For the model check below and this session; export is a builtin too
    export "${VAR_NAME}=${USER_KEY}"
fi

# Fetch available models. The provider, default model and key variable name are passed as
# arguments; the key itself is read from the environment.
echo ""
echo " Checking available models with your key..."
FETCH_RESULT=$(python3 - "$YAML_PROVIDER" "$YAML_MODEL" "$VAR_NAME" <<'PY' 2>/dev/null
import os
import sys

provider, default, var_name = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    from scrutics.ai.model_discovery import fetch_models_with_source
    from scrutics.ai.model_rules import FALLBACK_LABEL, default_index
    base_url = "http://localhost:11434" if provider == "ollama" else ""
    key = os.environ.get(var_name, "") if var_name else ""
    models, source, reason = fetch_models_with_source(provider, key, base_url, timeout=6.0, max_results=10)
    if source == "live":
        print("LIVE")
        print("")
    else:
        print("FALLBACK")
        print(f"Could not list models ({reason}). {FALLBACK_LABEL}:")
    print(default_index(models, default) + 1 if models else 0)
    for m in models:
        print(m)
except Exception as e:
    print("FALLBACK")
    print(f"Could not list models ({type(e).__name__}).")
    print(0)
PY
)

# Parse the result: status, message, default position, then one model per line
FETCH_STATUS="$(echo "$FETCH_RESULT" | sed -n 1p)"
FETCH_MESSAGE="$(echo "$FETCH_RESULT" | sed -n 2p)"
DEFAULT_POS="$(echo "$FETCH_RESULT" | sed -n 3p)"
mapfile -t MODELS < <(echo "$FETCH_RESULT" | tail -n +4 | sed '/^$/d')
if [[ ${#MODELS[@]} -gt 0 ]]; then
    if [[ "$FETCH_STATUS" == "LIVE" ]]; then
        echo " Found ${#MODELS[@]} models available with your key:"
    else
        echo " $FETCH_MESSAGE"
    fi
    echo ""
    for i in "${!MODELS[@]}"; do
        echo "   $((i+1)). ${MODELS[$i]}"
    done
    echo ""
    [[ "$DEFAULT_POS" =~ ^[0-9]+$ ]] && [ "$DEFAULT_POS" -ge 1 ] || DEFAULT_POS=1
    read -rp " Select model (1-${#MODELS[@]}, default=$DEFAULT_POS): " model_choice
    if [[ "$model_choice" =~ ^[0-9]+$ ]] && [ "$model_choice" -ge 1 ] && [ "$model_choice" -le "${#MODELS[@]}" ]; then
        YAML_MODEL="${MODELS[$((model_choice-1))]}"
    else
        YAML_MODEL="${MODELS[$((DEFAULT_POS-1))]}"
    fi
    echo " Selected: $YAML_MODEL"
else
    [[ -n "$FETCH_MESSAGE" ]] && echo " $FETCH_MESSAGE"
    echo " Using default model: $YAML_MODEL"
fi

# Write ai.yaml
TIMEOUT=60
if [ "$YAML_PROVIDER" = "ollama" ]; then
    TIMEOUT=180
fi

cat > "$YAML_PATH" <<EOF
# Scrutics AI Configuration
# Configured automatically by scrutics_ai_setup.sh
# To reconfigure, run scrutics_ai_setup.sh again.
enabled: true
provider: $YAML_PROVIDER
model: $YAML_MODEL
EOF

# Add api_key line only if VAR_NAME is set (not Ollama)
if [[ -n "$VAR_NAME" ]]; then
    echo "api_key: \${$VAR_NAME}" >> "$YAML_PATH"
fi

cat >> "$YAML_PATH" <<EOF
temperature: 0.3
max_tokens: 1024
timeout: $TIMEOUT
EOF

# Add Ollama-specific config
if [ "$YAML_PROVIDER" = "ollama" ]; then
    cat >> "$YAML_PATH" <<EOF
base_url: http://localhost:11434
reasoning_effort: low
EOF
fi

echo ""
echo " ============================================================"
echo "  All done! Scrutics AI is ready to use."
echo " ============================================================"
echo ""
echo " Provider : $PROVIDER_LABEL"
echo " Model    : $YAML_MODEL"
echo ""
echo " Start Scrutics and press A to open the AI assistant."
echo " Or from the terminal:"
echo "   scrutics ai \"What is on this network?\""
echo ""
if [[ -n "$VAR_NAME" ]]; then
    echo " New terminals load the key from ~/.scrutics/ai_keys.sh. To load it"
    echo " in this terminal without reopening it, run:"
    echo "   . ~/.scrutics/ai_keys.sh"
    echo ""
fi
