#!/usr/bin/env bash
# Blue Team MCP Server Setup Script
# Run this on your DEFENDER HOST (Ubuntu/Debian recommended)
# Usage: sudo bash setup.sh
# Programmer : NAuliajati (csirt[at]tangerangkota[.]go[.]id)
set -e

INSTALL_DIR="/opt/blue-team-mcp"
SERVICE_USER="blueteam-mcp"

echo "=============================================="
echo "  Blue Team MCP Server - Setup"
echo "=============================================="

# Root check
if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo bash setup.sh"
  exit 1
fi

# Install system dependencies
echo "[1/7] Installing system packages..."
apt-get update -qq
apt-get install -y --no-install-recommends \
  python3 python3-pip python3-venv \
  tcpdump \
  fail2ban \
  rkhunter \
  chkrootkit \
  lynis \
  net-tools \
  iproute2 \
  procps \
  openssh-server \
  2>/dev/null || true

echo "[2/7] Creating install directory at $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

# Clean stale bytecode before copying (prevents Python version mismatch issues)
find . -type d -name "__pycache__" -not -path "./.venv/*" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -not -path "./.venv/*" -delete 2>/dev/null || true

cp blue_team_server.py "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/"
cp README.md "$INSTALL_DIR/"

# Python venv
echo "[3/7] Setting up Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
# Optional: run pip-audit if available (MAESTRO supply chain). Install temporarily and run.
"$INSTALL_DIR/venv/bin/pip" install --quiet pip-audit 2>/dev/null && \
  "$INSTALL_DIR/venv/bin/pip-audit" 2>/dev/null || true

# Config file for environment variables
CONFIG_FILE="$INSTALL_DIR/config.env"
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "[4/7] Creating config file at $CONFIG_FILE..."
  cat > "$CONFIG_FILE" << 'CONFIGEOF'
# Blue Team MCP - Environment Variables
# Edit this file with your API keys and settings. Do not commit to git.
# The wrapper sources this file before starting the server.

# Threat intelligence (optional)
# export ABUSEIPDB_API_KEY="your_key"
# export VIRUSTOTAL_API_KEY="your_key"
# export CROWDSEC_API_KEY="your_key" # free tier: https://www.crowdsec.net/en/user/profile
# export NETRA_API_KEY="your_key"
# export NETRA_VERIFY_SSL="false"   # set to "true" for production / trusted CA

# GreyNoise Community — no API key needed; greynoise_ip_context works out of the box.

# MCP transport (optional — default: stdio for SSH usage)
# Uncomment one for a remote HTTP service:
# export MCP_TRANSPORT="streamable_http"
# export MCP_HOST="0.0.0.0"
# export MCP_PORT="8000"

# Wazuh SIEM (optional)
# export WAZUH_API_URL="https://192.168.1.180:55000"
# export WAZUH_API_USER="wazuh-wui"
# export WAZUH_API_PASSWORD="MyS3cr37P450r.*-"
# export WAZUH_API_VERIFY_SSL="true"   # TLS verification ON by default — disable only for self-signed labs

# Wazuh Indexer / OpenSearch (optional - for HYDRA-DC Windows events, port 9200)
# export WAZUH_INDEXER_URL="https://192.168.1.180:9200"
# export WAZUH_INDEXER_USER="admin"
# export WAZUH_INDEXER_PASSWORD="your_indexer_password"
# export WAZUH_INDEXER_VERIFY_SSL="true"  # TLS verification ON by default — disable only for self-signed labs

# Performance & Tuning Limits
# export BLUETEAM_CHARACTER_LIMIT="100000"       # max chars per tool response before truncation
# export BLUETEAM_HTTP_TIMEOUT="30.0"           # HTTP request timeout in seconds
# export BLUETEAM_VERIFY_SSL="true"             # SSL cert verification for external API calls
# export BLUETEAM_BULK_CONCURRENCY="5"          # max parallel IP lookups (CrowdSec bulk)
# export WAZUH_INDEXER_MAX_SIZE="10000"         # max documents per page in Wazuh Indexer search

# CrowdSec CTI cache TTL (seconds, default 900 = 15 min)
# export CROWDSEC_CACHE_TTL="900"

# Data masking (see SECURITY.md §4 for the three-layer model)
#
# Layer 1 — CREDENTIAL STRIPPING: ALWAYS active, never configurable.
#   Bearer tokens, API keys, JWTs, passwords etc. are stripped before
#   any data reaches the LLM.  There is no legitimate use case for
#   sending credentials to an AI model.
#
# Layer 2 — Email redaction (BLUETEAM_REDACT_EMAILS, default: true):
#   Masks the local part of email addresses (preserving first/last char
#   + forensic hash), keeps the FULL domain visible for threat intel.
#   Set to "false" when SOC analysts need to identify specific
#   compromised accounts during incident investigation.
# export BLUETEAM_REDACT_EMAILS="true"
#
# Layer 3 — Internal IP masking (BLUETEAM_REDACT_PII, default: true):
#   Masks RFC1918 addresses (10.x, 172.16-31.x, 192.168.x).
#   PUBLIC ATTACKER IPs AND DOMAINS ARE NEVER MASKED — they are IoCs.
# export BLUETEAM_REDACT_PII="true"

# Server identity (optional — use lowercase to avoid LLM casing mismatches)
# export BLUE_TEAM_MCP_SERVER_NAME="blue_team_mcp"

# Audit and limits (optional)
# export BLUETEAM_AUDIT_LOG="/var/log/blue-team-mcp-audit.jsonl"
# export BLUETEAM_RATE_LIMIT="60"

# Path restrictions (defaults shown)
# export BLUETEAM_ALLOWED_PATHS="/var:/etc:/home:/opt:/usr"
# export BLUETEAM_CAPTURE_DIR="/tmp"
CONFIGEOF
  chmod 644 "$CONFIG_FILE"
  echo "  Created $CONFIG_FILE - edit to add API keys and Wazuh credentials"
else
  echo "[4/7] Config file exists at $CONFIG_FILE (not overwritten)"
fi

# Wrapper scripts
echo "[5/7] Creating MCP server wrapper scripts..."

# Main wrapper: mcp-server-blueteam (all 43 tools)
cat > /usr/local/bin/mcp-server-blueteam << 'EOF'
#!/usr/bin/env bash
# Wrapper - Claude Desktop calls this via SSH (MAESTRO-compliant)
# Sources config.env if present, then runs the server
[[ -f /opt/blue-team-mcp/config.env ]] && source /opt/blue-team-mcp/config.env
export ABUSEIPDB_API_KEY="${ABUSEIPDB_API_KEY:-}"
export VIRUSTOTAL_API_KEY="${VIRUSTOTAL_API_KEY:-}"
export CROWDSEC_API_KEY="${CROWDSEC_API_KEY:-}"
export NETRA_API_KEY="${NETRA_API_KEY:-}"
export NETRA_VERIFY_SSL="${NETRA_VERIFY_SSL:-false}"
export BLUETEAM_AUDIT_LOG="${BLUETEAM_AUDIT_LOG:-}"
export BLUETEAM_RATE_LIMIT="${BLUETEAM_RATE_LIMIT:-0}"
export BLUETEAM_ALLOWED_PATHS="${BLUETEAM_ALLOWED_PATHS:-/var:/etc:/home:/opt:/usr}"
export BLUETEAM_CAPTURE_DIR="${BLUETEAM_CAPTURE_DIR:-/tmp}"
export BLUETEAM_HTTP_TIMEOUT="${BLUETEAM_HTTP_TIMEOUT:-30.0}"
export BLUETEAM_CHARACTER_LIMIT="${BLUETEAM_CHARACTER_LIMIT:-100000}"
export BLUETEAM_VERIFY_SSL="${BLUETEAM_VERIFY_SSL:-true}"
export CROWDSEC_CACHE_TTL="${CROWDSEC_CACHE_TTL:-900}"
export BLUETEAM_REDACT_PII="${BLUETEAM_REDACT_PII:-true}"
export BLUETEAM_REDACT_EMAILS="${BLUETEAM_REDACT_EMAILS:-true}"
export BLUE_TEAM_MCP_SERVER_NAME="${BLUE_TEAM_MCP_SERVER_NAME:-blue_team_mcp}"
export WAZUH_INDEXER_MAX_SIZE="${WAZUH_INDEXER_MAX_SIZE:-10000}"
export WAZUH_API_URL="${WAZUH_API_URL:-}"
export WAZUH_API_USER="${WAZUH_API_USER:-wazuh-wui}"
export WAZUH_API_PASSWORD="${WAZUH_API_PASSWORD:-}"
export WAZUH_API_VERIFY_SSL="${WAZUH_API_VERIFY_SSL:-true}"
export WAZUH_INDEXER_URL="${WAZUH_INDEXER_URL:-}"
export WAZUH_INDEXER_USER="${WAZUH_INDEXER_USER:-admin}"
export WAZUH_INDEXER_PASSWORD="${WAZUH_INDEXER_PASSWORD:-}"
export WAZUH_INDEXER_VERIFY_SSL="${WAZUH_INDEXER_VERIFY_SSL:-true}"
export MCP_TRANSPORT="${MCP_TRANSPORT:-stdio}"
export MCP_HOST="${MCP_HOST:-127.0.0.1}"
export MCP_PORT="${MCP_PORT:-8000}"
exec /opt/blue-team-mcp/venv/bin/python3 /opt/blue-team-mcp/blue_team_server.py "$@"
EOF
chmod +x /usr/local/bin/mcp-server-blueteam

# DEPRECATED standalone wrappers — redirect to the unified server.
# The standalone CrowdSec and GreyNoise files have been removed;
# all 43 tools (including CrowdSec + GreyNoise) live in blue_team_server.py.
for legacy in mcp-server-crowdsec mcp-server-greynoise; do
  cat > "/usr/local/bin/$legacy" << 'EOF'
#!/usr/bin/env bash
echo "[$0] DEPRECATED — redirecting to mcp-server-blueteam (unified server)" >&2
exec /usr/local/bin/mcp-server-blueteam "$@"
EOF
  chmod +x "/usr/local/bin/$legacy"
done

# SSH hardening reminder
echo "[6/7] Ensuring SSH is running..."
systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd 2>/dev/null || true

# Capability grants (allow tcpdump without root)
echo "[7/7] Granting tcpdump network capture capability..."
setcap cap_net_raw,cap_net_admin=eip "$(which tcpdump)" 2>/dev/null || \
  echo "  WARNING: Could not set tcpdump capabilities. Run captures as root."

# API key configuration
echo ""
echo "=============================================="
echo "  Setup complete!"
echo "=============================================="
echo ""
echo "OPTIONAL: Edit $CONFIG_FILE to add API keys and credentials:"
echo ""
echo "  sudo nano $CONFIG_FILE"
echo ""
echo "  Uncomment and set: ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY, NETRA_API_KEY,"
echo "  CROWDSEC_API_KEY (free tier at crowdsec.net),"
echo "  WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWORD,"
echo "  WAZUH_INDEXER_URL, WAZUH_INDEXER_PASSWORD."
echo ""
echo "  Performance tuning (all optional, defaults shown):"
echo "    BLUETEAM_CHARACTER_LIMIT=100000"
echo "    BLUETEAM_HTTP_TIMEOUT=30.0"
echo "    BLUETEAM_BULK_CONCURRENCY=5       (CrowdSec parallel lookups)"
echo "    WAZUH_INDEXER_MAX_SIZE=10000      (docs per page in indexer search)"
echo ""
echo "  GreyNoise Community needs no key — greynoise_ip_context works immediately."
echo ""
echo "Wrapper entry points installed:"
echo ""
echo "  mcp-server-blueteam    — All 43 tools (Wazuh, threat intel, host forensics)"
echo "  mcp-server-crowdsec    — DEPRECATED — redirects to mcp-server-blueteam"
echo "  mcp-server-greynoise   — DEPRECATED — redirects to mcp-server-blueteam"
echo ""
echo "Run as a remote HTTP service (no SSH needed):"
echo ""
echo "  MCP_TRANSPORT=streamable_http MCP_HOST=0.0.0.0 MCP_PORT=8000 mcp-server-blueteam"
echo ""
echo "Then add to your Claude Desktop config on macOS/Windows:"
echo ""
echo "  Option A — Local via SSH:"
echo '  {
    "mcpServers": {
      "blue-team-mcp": {
        "command": "ssh",
        "args": [
          "-i", "/path/to/your/ssh_key",
          "user@DEFENDER_HOST_IP",
          "mcp-server-blueteam"
        ],
        "transport": "stdio"
      }
    }
  }'
echo ""
echo "  Option B — Remote service (no SSH, connects over HTTP):"
echo '  {
    "mcpServers": {
      "blue-team-mcp": {
        "url": "http://DEFENDER_HOST_IP:8000/mcp",
        "transport": "streamable-http"
      }
    }
  }'
echo ""
echo "Test locally first: mcp-server-blueteam"
echo ""
echo "For a persistent remote service, see README.md § Remote Service Deployment (systemd)."
