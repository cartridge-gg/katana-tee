#!/bin/bash
#
# Katana TEE Client Script
# Remote client script to manage TEE VM on a host running MINIMAL_TEE
#
# Usage: ./client_script.sh {start|stop|status|test|verify|url}
#

set -euo pipefail

# Load environment
if [ -f .env ]; then
    # Parse .env file, handling comments and empty lines
    # Only allow known configuration keys (whitelist)
    while IFS='=' read -r key value; do
        # Skip empty lines and comments
        [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
        # Remove leading/trailing whitespace from key
        key=$(echo "$key" | xargs)
        # Skip if key is empty after trimming
        [[ -z "$key" ]] && continue
        # Only export whitelisted keys
        case "$key" in
            TEE_HOST|TEE_SSH_PORT|TEE_SSH_USER|TEE_SSH_KEY|TEE_REPO_PATH|RPC_PORT)
                if [[ -n "$value" ]]; then
                    export "$key=$value"
                fi
                ;;
            *)
                # Skip unknown keys for security
                ;;
        esac
    done < .env
fi

# Configuration (TEE_HOST required for most commands)
TEE_HOST="${TEE_HOST:-}"

# Optional configuration with defaults
TEE_SSH_PORT="${TEE_SSH_PORT:-22}"
TEE_SSH_USER="${TEE_SSH_USER:-ubuntu}"
TEE_REPO_PATH="${TEE_REPO_PATH:-/home/ubuntu/MINIMAL_TEE}"
RPC_PORT="${RPC_PORT:-5050}"

# SSH command builder using arrays for proper quoting.
# StrictHostKeyChecking=no is intentional: security comes from SEV-SNP attestation
# of the VM's launch measurement, not from SSH host key verification.
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10)

if [ -n "${TEE_SSH_KEY:-}" ]; then
    HOST_SSH=(ssh "${SSH_OPTS[@]}" -i "$TEE_SSH_KEY" -p "$TEE_SSH_PORT" "$TEE_SSH_USER@$TEE_HOST")
else
    HOST_SSH=(ssh "${SSH_OPTS[@]}" -p "$TEE_SSH_PORT" "$TEE_SSH_USER@$TEE_HOST")
fi

show_header() {
    echo "=============================================="
    echo " Katana TEE Client"
    echo "=============================================="
    echo ""
    echo "Host: ${TEE_HOST:-<not set>}"
    echo "Repo: $TEE_REPO_PATH"
    echo ""
}

# Function to run command on host
run_on_host() {
    "${HOST_SSH[@]}" "$1"
}

# Function to wait for condition
wait_for() {
    local msg=$1
    local check_cmd=$2
    local max_attempts=${3:-60}

    echo -n "$msg"
    for i in $(seq 1 $max_attempts); do
        if $check_cmd 2>/dev/null; then
            echo " ✓"
            return 0
        fi
        echo -n "."
        sleep 2
    done
    echo " ✗ (timeout)"
    return 1
}

# Function to check if RPC is responding
check_rpc() {
    curl -s --connect-timeout 2 --max-time 5 "http://${TEE_HOST}:${RPC_PORT}" -X POST \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","method":"starknet_chainId","params":[],"id":1}' 2>/dev/null | grep -q "result"
}

# Helper to check required config
require_tee_host() {
    if [ -z "$TEE_HOST" ]; then
        echo "Error: TEE_HOST not set"
        echo "Create a .env file with: TEE_HOST=your-host"
        echo "Or copy from: cp .env.example .env"
        exit 1
    fi
}

# Dev mode state file
DEV_MODE_FILE=".katana-dev-mode"

case "${1:-help}" in
    start)
        require_tee_host
        show_header

        # Check for --dev flag
        DEV_FLAG=""
        for arg in "$@"; do
            if [ "$arg" = "--dev" ]; then
                DEV_FLAG="--dev"
            fi
        done

        if [ -n "$DEV_FLAG" ]; then
            echo "Starting TEE VM on $TEE_HOST (dev mode)..."
        else
            echo "Starting TEE VM on $TEE_HOST..."
        fi
        echo ""

        # Check if already running via RPC
        if check_rpc; then
            echo "TEE VM is already running ✓"
            echo ""
            echo "RPC URL: http://${TEE_HOST}:${RPC_PORT}"
            echo "http://${TEE_HOST}:${RPC_PORT}" > .katana-rpc-url
            exit 0
        fi

        # Use vm.sh on remote host for robust start
        echo "Invoking vm.sh on remote host..."
        run_on_host "cd $TEE_REPO_PATH && ./vm.sh start --public $DEV_FLAG" || {
            echo ""
            echo "Error: Failed to start VM"
            echo "Check logs on host: cat /tmp/katana-tee-vm-serial.log"
            exit 1
        }

        # Store dev mode state
        if [ -n "$DEV_FLAG" ]; then
            echo "dev" > "$DEV_MODE_FILE"
        else
            rm -f "$DEV_MODE_FILE"
        fi

        # Verify RPC is accessible from here
        echo ""
        echo "Verifying RPC accessibility from client..."
        if ! wait_for "  RPC" "check_rpc" 30; then
            echo ""
            echo "Warning: RPC started on host but not accessible from client"
            echo "Check firewall settings on $TEE_HOST"
        fi

        # Verify TEE attestation
        echo ""
        echo -n "TEE attestation: "
        if curl -s --max-time 10 "http://${TEE_HOST}:${RPC_PORT}" -X POST \
            -H 'Content-Type: application/json' \
            -d '{"jsonrpc":"2.0","method":"tee_generateQuote","params":[],"id":1}' | grep -q "quote"; then
            echo "available ✓"
        else
            echo "not available (non-SNP host?)"
        fi

        echo ""
        echo "=============================================="
        echo " Setup Complete!"
        echo "=============================================="
        echo ""
        echo "RPC URL: http://${TEE_HOST}:${RPC_PORT}"
        echo ""
        echo "Commands:"
        echo "  ./client_script.sh status  - Check VM status"
        echo "  ./client_script.sh test    - Test attestation"
        echo "  ./client_script.sh verify  - Verify measurement"
        echo "  ./client_script.sh stop    - Stop VM"
        echo ""

        echo "http://${TEE_HOST}:${RPC_PORT}" > .katana-rpc-url
        echo "RPC URL saved to .katana-rpc-url"
        ;;

    stop)
        require_tee_host
        show_header
        echo "Stopping TEE VM on $TEE_HOST..."

        # Use vm.sh on remote host
        if ! run_on_host "cd $TEE_REPO_PATH && ./vm.sh stop"; then
            echo "Warning: vm.sh stop returned an error"
        fi

        sleep 1

        if check_rpc; then
            echo ""
            echo "Warning: VM may still be running (RPC still responding)"
        else
            echo ""
            echo "TEE VM stopped ✓"
        fi

        rm -f .katana-rpc-url "$DEV_MODE_FILE" .katana-quote-response.json
        ;;

    status)
        require_tee_host
        show_header
        echo "TEE VM Status"
        echo ""

        # Get status from remote vm.sh
        # vm.sh status returns 1 when VM is stopped (convention for scripting),
        # so use || true on remote side to avoid confusing SSH exit code with errors
        echo "Remote host ($TEE_HOST):"
        run_on_host "cd $TEE_REPO_PATH && ./vm.sh status || true" 2>/dev/null || echo "  Could not connect to host"

        # Show local dev mode state
        if [ -f "$DEV_MODE_FILE" ]; then
            echo "  Mode:       dev (started with --dev)"
        fi

        echo ""
        echo "Client connectivity:"

        # Check if RPC is responding from here
        echo -n "  RPC endpoint: "
        if check_rpc; then
            echo "responding ✓"
        else
            echo "not responding ✗"
        fi

        # Check if TEE attestation works
        echo -n "  TEE attestation: "
        if curl -s --max-time 5 "http://${TEE_HOST}:${RPC_PORT}" -X POST \
            -H 'Content-Type: application/json' \
            -d '{"jsonrpc":"2.0","method":"tee_generateQuote","params":[],"id":1}' 2>/dev/null | grep -q "quote"; then
            echo "available ✓"
        else
            echo "not available ✗"
        fi
        ;;

    test)
        require_tee_host
        RPC_URL=$(cat .katana-rpc-url 2>/dev/null || echo "http://${TEE_HOST}:${RPC_PORT}")
        echo "Testing TEE attestation at $RPC_URL ..."
        echo ""

        RESPONSE=$(curl -s --max-time 10 "$RPC_URL" -X POST \
            -H 'Content-Type: application/json' \
            -d '{"jsonrpc":"2.0","method":"tee_generateQuote","params":[],"id":1}')

        if [ -z "$RESPONSE" ]; then
            echo "Error: No response from RPC (is TEE VM running?)"
            echo "Try: ./client_script.sh start"
            exit 1
        fi

        # Pretty print if possible
        echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"

        # Save response for later use
        echo "$RESPONSE" > .katana-quote-response.json
        echo ""
        echo "Response saved to .katana-quote-response.json"
        ;;

    verify)
        require_tee_host
        show_header
        echo "Verifying TEE measurement..."
        echo ""

        # Check if we started in dev mode
        DEV_FLAG=""
        if [ -f "$DEV_MODE_FILE" ]; then
            DEV_FLAG="--dev"
            echo "Note: Using dev mode measurement (VM was started with --dev)"
            echo ""
        fi

        # Run verification on the host using katana-tee.sh
        run_on_host "cd $TEE_REPO_PATH && ./katana-tee.sh verify \$(./scripts/compute-measurement.sh --hex-only $DEV_FLAG) http://localhost:$RPC_PORT"
        ;;

    measurement)
        require_tee_host
        # Get measurement from running TEE and output in parsable formats
        # --save [path]  Save measurement JSON to disk (default: measurement.json)
        SAVE_PATH=""
        shift  # consume "measurement"
        while [ $# -gt 0 ]; do
            case "$1" in
                --save)
                    SAVE_PATH="${2:-measurement.json}"
                    # If next arg exists and doesn't start with --, consume it as path
                    if [ $# -ge 2 ] && [[ ! "$2" =~ ^-- ]]; then
                        shift
                    fi
                    ;;
            esac
            shift
        done

        RPC_URL="http://${TEE_HOST}:${RPC_PORT}"

        # Fetch quote via RPC
        RESPONSE=$(curl -s --max-time 30 "$RPC_URL" -X POST \
            -H 'Content-Type: application/json' \
            -d '{"jsonrpc":"2.0","method":"tee_generateQuote","params":[],"id":1}')

        QUOTE=$(echo "$RESPONSE" | jq -r '.result.quote // empty' 2>/dev/null)
        if [ -z "$QUOTE" ] || [ "$QUOTE" = "null" ]; then
            echo "Error: Could not get quote from TEE" >&2
            exit 1
        fi

        # Decode quote on remote host to get measurement
        MEASUREMENT=$(run_on_host "cd $TEE_REPO_PATH && ./snp-tools/target/x86_64-unknown-linux-gnu/release/snp-report --hex '$QUOTE' 2>/dev/null | grep -i measurement | grep -oE '[0-9a-fA-F]{96}' | head -1" 2>/dev/null)

        # Fallback path
        if [ -z "$MEASUREMENT" ]; then
            MEASUREMENT=$(run_on_host "cd $TEE_REPO_PATH && ./snp-tools/target/release/snp-report --hex '$QUOTE' 2>/dev/null | grep -i measurement | grep -oE '[0-9a-fA-F]{96}' | head -1" 2>/dev/null)
        fi

        if [ -z "$MEASUREMENT" ]; then
            echo "Error: Could not extract measurement" >&2
            exit 1
        fi

        MEASUREMENT=$(echo "$MEASUREMENT" | tr '[:upper:]' '[:lower:]')

        # Split into Bytes48 parts (each 32 hex chars = 16 bytes = 128 bits)
        # NOTE: byte_reverse_hex and Bytes48 logic below are intentional standalone
        # copies of lib/crypto.sh. This script must remain portable/standalone
        # (runs on client machines without the full repo), so we cannot source lib/*.
        LOW_HEX="${MEASUREMENT:0:32}"
        MID_HEX="${MEASUREMENT:32:32}"
        HIGH_HEX="${MEASUREMENT:64:32}"

        # Byte-reverse each chunk for Cairo's little-endian u128 read (get_u128_at)
        byte_reverse_hex() {
            local hex="$1"
            local reversed=""
            for ((i=${#hex}-2; i>=0; i-=2)); do
                reversed+="${hex:$i:2}"
            done
            echo "$reversed"
        }

        LOW_BITS=$(byte_reverse_hex "$LOW_HEX")
        MID_BITS=$(byte_reverse_hex "$MID_HEX")
        HIGH_BITS=$(byte_reverse_hex "$HIGH_HEX")

        # Output in shell-parsable format
        echo "# TEE Measurement (parsable output)"
        echo "# Source: $RPC_URL"
        echo ""
        echo "HEX=$MEASUREMENT"
        echo "HIGH_BITS=0x${HIGH_BITS}"
        echo "MID_BITS=0x${MID_BITS}"
        echo "LOW_BITS=0x${LOW_BITS}"
        echo ""
        echo "# JSON format for calldata:"
        echo "{"
        echo "  \"hex\": \"$MEASUREMENT\","
        echo "  \"high_bits\": \"0x${HIGH_BITS}\","
        echo "  \"mid_bits\": \"0x${MID_BITS}\","
        echo "  \"low_bits\": \"0x${LOW_BITS}\""
        echo "}"

        # Save to file if --save was specified
        if [ -n "$SAVE_PATH" ]; then
            printf '{\n  "high_bits": "0x%s",\n  "low_bits": "0x%s",\n  "mid_bits": "0x%s"\n}\n' \
                "$HIGH_BITS" "$LOW_BITS" "$MID_BITS" > "$SAVE_PATH"
            echo ""
            echo "Measurement saved to $SAVE_PATH"
        fi
        ;;

    url)
        require_tee_host
        # Just output the RPC URL (for piping to other commands)
        echo "http://${TEE_HOST}:${RPC_PORT}"
        ;;

    *)
        echo "Usage: $0 {start|stop|status|test|verify|measurement|url}"
        echo ""
        echo "Commands:"
        echo "  start [--dev] - Start TEE VM (Katana auto-starts from initrd)"
        echo "                  --dev enables Katana dev mode (different measurement!)"
        echo "  stop          - Stop the TEE VM"
        echo "  status        - Check VM and RPC status"
        echo "  test          - Test TEE attestation endpoint"
        echo "  verify        - Verify measurement matches expected (reproducible build)"
        echo "  measurement [--save [path]]"
        echo "                - Get measurement in parsable format (for calldata)"
        echo "                  --save writes JSON to disk (default: measurement.json)"
        echo "  url           - Print RPC URL"
        echo ""
        echo "Environment (.env file):"
        echo "  TEE_HOST       - Required: TEE host address"
        echo "  TEE_SSH_PORT   - SSH port (default: 22)"
        echo "  TEE_SSH_USER   - SSH user (default: ubuntu)"
        echo "  TEE_SSH_KEY    - Path to SSH key (optional)"
        echo "  TEE_REPO_PATH  - Path to MINIMAL_TEE on host (default: /home/ubuntu/MINIMAL_TEE)"
        echo "  RPC_PORT       - Katana RPC port (default: 5050)"
        ;;
esac
