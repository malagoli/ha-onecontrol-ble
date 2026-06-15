#!/bin/bash
set -e

# Configuration
HA_CONFIG_DIR="$(pwd)/.ha-config"
VENV_DIR="$(pwd)/.venv-ha"

echo "=== Local Home Assistant Test Environment Setup ==="

# 1. Detect Python Version (HA 2026.01 supports Python 3.13)
PYTHON_BIN=""
for py_cmd in "/opt/homebrew/bin/python3.13" "python3.13" "/opt/homebrew/bin/python3.14" "/opt/homebrew/bin/python3.12" "python3.14" "python3.12" "python3"; do
  if command -v "$py_cmd" >/dev/null 2>&1; then
    VERSION=$("$py_cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    if [[ "$VERSION" == "3.12" || "$VERSION" == "3.13" || "$VERSION" == "3.14" ]]; then
      PYTHON_BIN="$py_cmd"
      echo "Found compatible Python version: $VERSION ($PYTHON_BIN)"
      break
    fi
  fi
done

if [ -z "$PYTHON_BIN" ]; then
  echo "Warning: No compatible Python executable found. Falling back to default 'python3'..."
  PYTHON_BIN="python3"
fi

# 2. Setup Virtual Environment
if [ ! -d "$VENV_DIR" ]; then
  echo "Creating virtual environment in $VENV_DIR using $PYTHON_BIN..."
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

# 3. Activate and Install Dependencies
echo "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

echo "Upgrading pip, setuptools, and wheel..."
pip install --upgrade pip setuptools wheel

echo "Installing Home Assistant Core and integration dependencies..."
pip install https://github.com/home-assistant/core/archive/refs/tags/2026.1.3.tar.gz bleak bleak-retry-connector pycryptodome

# 4. Setup HA Config Directory & Symlinks
echo "Setting up configuration directory at $HA_CONFIG_DIR..."
mkdir -p "$HA_CONFIG_DIR/custom_components"

# Symlink the custom component directory into the config directory
echo "Symlinking custom component..."
ln -sfn "$(pwd)/custom_components/onecontrol_ble" "$HA_CONFIG_DIR/custom_components/onecontrol_ble"

# Create baseline configuration.yaml if it doesn't exist
if [ ! -f "$HA_CONFIG_DIR/configuration.yaml" ]; then
  echo "Creating baseline configuration.yaml..."
  cat <<EOT > "$HA_CONFIG_DIR/configuration.yaml"
default_config:

logger:
  default: info
  logs:
    custom_components.onecontrol_ble: debug
EOT
fi

echo "================================================="
echo "Setup complete! Starting Home Assistant..."
echo "Open your browser to: http://localhost:8123"
echo "================================================="

# 5. Start Home Assistant
hass -c "$HA_CONFIG_DIR"
