#!/usr/bin/env bash
# Scrutics AI Setup — run once to configure the AI assistant.
# Saves your API key as an environment variable and writes ai.yaml automatically.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
        YAML_MODEL="gpt-4o-mini"
        ;;
    3)
        VAR_NAME="ANTHROPIC_API_KEY"
        PROVIDER_LABEL="Anthropic"
        KEY_URL="https://console.anthropic.com/settings/keys"
        YAML_PROVIDER="anthropic"
        YAML_MODEL="claude-haiku-4-5"
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

# Save to ~/.bashrc permanently (skip for Ollama)
if [[ -n "$VAR_NAME" ]]; then
    BASHRC="$HOME/.bashrc"
    if grep -q "^export ${VAR_NAME}=" "$BASHRC" 2>/dev/null; then
        sed -i "/^export ${VAR_NAME}=/d" "$BASHRC"
    fi
    echo "export ${VAR_NAME}=\"${USER_KEY}\"" >> "$BASHRC"
    # Apply to current session
    export "${VAR_NAME}=${USER_KEY}"
fi

# Fetch available models using Python
echo ""
echo " Checking available models with your key..."
FETCH_RESULT=$(python3 -c "
import sys
sys.path.insert(0, '$SCRIPT_DIR/..')
try:
    from scrutics.ai.model_discovery import fetch_models
    base_url = 'http://localhost:11434' if '$YAML_PROVIDER' == 'ollama' else ''
    models = fetch_models('$YAML_PROVIDER', '$USER_KEY', base_url, timeout=6.0, max_results=10)
    if models:
        print('SUCCESS')
        for m in models:
            print(m)
    else:
        print('FALLBACK')
        print('$YAML_MODEL')
except Exception as e:
    print('FALLBACK')
    print('$YAML_MODEL')
" 2>/dev/null)

# Parse the result
if echo "$FETCH_RESULT" | head -1 | grep -q "SUCCESS"; then
    mapfile -t MODELS < <(echo "$FETCH_RESULT" | tail -n +2)
    echo " Found ${#MODELS[@]} models available with your key:"
    echo ""
    for i in "${!MODELS[@]}"; do
        echo "   $((i+1)). ${MODELS[$i]}"
    done
    echo ""
    read -rp " Select model (1-${#MODELS[@]}, default=1): " model_choice
    if [[ "$model_choice" =~ ^[0-9]+$ ]] && [ "$model_choice" -ge 1 ] && [ "$model_choice" -le "${#MODELS[@]}" ]; then
        YAML_MODEL="${MODELS[$((model_choice-1))]}"
    else
        YAML_MODEL="${MODELS[0]}"
    fi
    echo " Selected: $YAML_MODEL"
else
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
echo " The key was added to ~/.bashrc. To apply it in this"
echo " terminal without reopening it, run:"
echo "   source ~/.bashrc"
echo ""
