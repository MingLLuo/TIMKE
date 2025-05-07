#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default settings
KEM1_TYPE="ML-KEM-768"
KEM2_TYPE="ML-KEM-768"
PORT=8443
TEMP_DIR="$(pwd)/.temp"
SERVER_KEY="${TEMP_DIR}/server-key.pem"
CLIENT_ZERO_RTT="Hello from TIMKE client! This is 0-RTT data."
SERVER_PID_FILE="${TEMP_DIR}/server.pid"

# Banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                                                            ║"
    echo "║  ████████╗██╗███╗   ███╗██╗  ██╗███████╗                  ║"
    echo "║  ╚══██╔══╝██║████╗ ████║██║ ██╔╝██╔════╝                  ║"
    echo "║     ██║   ██║██╔████╔██║█████╔╝ █████╗                    ║"
    echo "║     ██║   ██║██║╚██╔╝██║██╔═██╗ ██╔══╝                    ║"
    echo "║     ██║   ██║██║ ╚═╝ ██║██║  ██╗███████╗                  ║"
    echo "║     ╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝                  ║"
    echo "║                                                            ║"
    echo "║         TIghtly secure Multi-stage Key Exchange           ║"
    echo "║                      Demo Script                           ║"
    echo "║                                                            ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --kem1)
            KEM1_TYPE="$2"
            shift 2
            ;;
        --kem2)
            KEM2_TYPE="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --help)
            print_banner
            echo -e "${GREEN}TIMKE Demo Run Script${NC}"
            echo -e "Usage: $0 [options]"
            echo -e ""
            echo -e "Options:"
            echo -e "  --kem1 TYPE     KEM algorithm to use (default: ML-KEM-768)"
            echo -e "  --kem2 TYPE     KEM algorithm to use (default: ML-KEM-768)"
            echo -e "  --port PORT    Port to use for server (default: 8443)"
            echo -e "  --help         Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Function to clean up on exit
cleanup() {
    echo -e "${YELLOW}Cleaning up temporary files...${NC}"
    
    # Check if server is running and stop it
    if [ -f "${SERVER_PID_FILE}" ]; then
        SERVER_PID=$(cat "${SERVER_PID_FILE}")
        if kill -0 "${SERVER_PID}" 2>/dev/null; then
            echo -e "${YELLOW}Stopping TIMKE server (PID: ${SERVER_PID})...${NC}"
            kill "${SERVER_PID}" 2>/dev/null || true
        fi
    fi
}

# Function to generate server keys
generate_keys() {
    echo -e "${YELLOW}Generating server keys with kem1.(${KEM1_TYPE})...${NC}"

    # Move to project root directory (assuming script is in TIMKE/scripts/)
    cd "$(dirname "$0")/.." || exit 1
    # Check if Temp directory exists
    if [[ ! -d "${TEMP_DIR}" ]]; then
        mkdir -p "${TEMP_DIR}"
    fi

    go run ./cmd/server/main.go --genkey "${SERVER_KEY}" --kem1 "${KEM1_TYPE}" --kem2 "${KEM2_TYPE}"
    
    if [[ ! -f "${SERVER_KEY}" || ! -f "${SERVER_KEY}.pub" ]]; then
        echo -e "${RED}Failed to generate server keys.${NC}"
        return 1
    fi
    
    # Print public key for manual client use
    echo -e "${GREEN}Server keys generated:${NC}"
    echo -e "  Private key: ${SERVER_KEY}"
    echo -e "  Public key: ${SERVER_KEY}.pub"
#    echo -e "${BLUE}Server public key in hex format (for manual client use):${NC}"
#    cat "${SERVER_KEY}.pub" | xxd -p | tr -d '\n'
    echo -e "\n"
    
    return 0
}

# Function to start the server
start_server() {
    # Move to project root directory (assuming script is in TIMKE/scripts/)
    cd "$(dirname "$0")/.." || exit 1

    # Check if Temp directory exists
    if [[ ! -d "${TEMP_DIR}" ]]; then
        mkdir -p "${TEMP_DIR}"
    fi

    # Check if server is already running
    if [ -f "${SERVER_PID_FILE}" ]; then
        local old_pid=$(cat "${SERVER_PID_FILE}")
        if kill -0 "${old_pid}" 2>/dev/null; then
            echo -e "${YELLOW}Server is already running with PID ${old_pid}${NC}"
            return 0
        fi
    fi

    # Check if key exists
    if [[ ! -f "${SERVER_KEY}" ]]; then
        echo -e "${RED}Server key not found. Generate keys first.${NC}"
        return 1
    fi

    echo -e "${YELLOW}Starting TIMKE server on port ${PORT}...${NC}"
    
    # Start server in background
    # Create a TimeStamp for the log file
    TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
    echo "TIMKE Server Log File" > "${TEMP_DIR}/server.log"
    echo "TIMESTAMP: ${TIMESTAMP}" >> "${TEMP_DIR}/server.log"
    go run ./cmd/server/main.go --key "${SERVER_KEY}" --port "${PORT}" --kem1 "${KEM1_TYPE}" --kem2 "${KEM2_TYPE}" --v > "${TEMP_DIR}/server.log" 2>&1 &
    local server_pid=$!
    
    # Save PID for later cleanup
    echo "${server_pid}" > "${SERVER_PID_FILE}"
    
    # Wait a moment for the server to start
    sleep 2
    
    # Check if server is running
    if ! kill -0 "${server_pid}" 2>/dev/null; then
        echo -e "${RED}Server failed to start. Check server log: ${TEMP_DIR}/server.log${NC}"
        cat "${TEMP_DIR}/server.log"
        return 1
    fi
    
    echo -e "${GREEN}Server started with PID ${server_pid}${NC}"
    echo -e "${BLUE}Server log available at: ${TEMP_DIR}/server.log${NC}"
    echo -e "${YELLOW}Tail of server log:${NC}"
    tail -n 10 "${TEMP_DIR}/server.log"
    echo
    
    return 0
}

# Function to run client with 0-RTT data
run_client_0rtt() {
    # Check if key exists
    if [[ ! -f "${SERVER_KEY}.pub" ]]; then
        echo -e "${RED}Server public key not found. Generate keys first.${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}Running TIMKE client with 0-RTT data...${NC}"
    # Move to project root directory (assuming script is in TIMKE/scripts/)
    cd "$(dirname "$0")/.." || exit 1
    
    go run ./cmd/client/main.go --server-key-file "${SERVER_KEY}.pub" --port "${PORT}" --kem1 "${KEM1_TYPE}" --kem2 "${KEM2_TYPE}" --v --0rtt "${CLIENT_ZERO_RTT}"
    
    return $?
}

# Function to run client in interactive mode
run_client_interactive() {
    # Check if key exists
    if [[ ! -f "${SERVER_KEY}.pub" ]]; then
        echo -e "${RED}Server public key not found. Generate keys first.${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}Running TIMKE client in interactive mode...${NC}"
    # Move to project root directory (assuming script is in TIMKE/scripts/)
    cd "$(dirname "$0")/.." || exit 1
    
    go run ./cmd/client/main.go --server-key-file "${SERVER_KEY}.pub" --port "${PORT}" --kem1 "${KEM1_TYPE}" --kem2 "${KEM2_TYPE}" --v --i
    
    return $?
}

# Function to display server log
show_server_log() {
    if [ -f "${TEMP_DIR}/server.log" ]; then
        echo -e "${YELLOW}Server log:${NC}"
        cat "${TEMP_DIR}/server.log"
    else
        echo -e "${RED}Server log not found. Start the server first.${NC}"
        return 1
    fi
    
    return 0
}

# Function to stop the server
stop_server() {
    if [ -f "${SERVER_PID_FILE}" ]; then
        local pid=$(cat "${SERVER_PID_FILE}")
        if kill -0 "${pid}" 2>/dev/null; then
            echo -e "${YELLOW}Stopping TIMKE server (PID: ${pid})...${NC}"
            kill "${pid}" 2>/dev/null
            rm -f "${SERVER_PID_FILE}"
            echo -e "${GREEN}Server stopped.${NC}"
        else
            echo -e "${RED}Server process (PID: ${pid}) is not running.${NC}"
            rm -f "${SERVER_PID_FILE}"
        fi
    else
        echo -e "${RED}No running server found.${NC}"
        return 1
    fi
    
    return 0
}

# Register cleanup function
trap cleanup EXIT

# Main menu
show_menu() {
    echo -e "${GREEN}TIMKE Demo Options:${NC}"
    echo -e "  ${YELLOW}1)${NC} Generate server keys"
    echo -e "  ${YELLOW}2)${NC} Start server"
    echo -e "  ${YELLOW}3)${NC} Run client with 0-RTT data"
    echo -e "  ${YELLOW}4)${NC} Run client in interactive mode"
    echo -e "  ${YELLOW}5)${NC} Show server log"
    echo -e "  ${YELLOW}6)${NC} Stop server"
    echo -e "  ${YELLOW}7)${NC} Exit"
    echo
    echo -e "${BLUE}Using KEM1: ${KEM1_TYPE}, KEM2: ${KEM2_TYPE}, Port: ${PORT}${NC}"
    echo
    
    # Check server status
    if [ -f "${SERVER_PID_FILE}" ]; then
        local pid=$(cat "${SERVER_PID_FILE}")
        if kill -0 "${pid}" 2>/dev/null; then
            echo -e "${GREEN}Server is running with PID ${pid}${NC}"
        else
            echo -e "${RED}Server is not running (stale PID file)${NC}"
            rm -f "${SERVER_PID_FILE}"
        fi
    else
        echo -e "${YELLOW}Server is not running${NC}"
    fi
    echo
}

# Main loop
print_banner

while true; do
    show_menu
    echo -n "Enter your choice [1-7]: "
    read -r choice
    
    case $choice in
        1)
            generate_keys
            echo -e "${YELLOW}Press Enter to continue...${NC}"
            read -r
            ;;
        2)
            start_server
            echo -e "${YELLOW}Press Enter to continue...${NC}"
            read -r
            ;;
        3)
            run_client_0rtt
            echo -e "${YELLOW}Press Enter to continue...${NC}"
            read -r
            ;;
        4)
            run_client_interactive
            ;;
        5)
            show_server_log
            echo -e "${YELLOW}Press Enter to continue...${NC}"
            read -r
            ;;
        6)
            stop_server
            echo -e "${YELLOW}Press Enter to continue...${NC}"
            read -r
            ;;
        7)
            echo -e "${GREEN}Exiting TIMKE demo.${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice. Please enter a number between 1 and 7.${NC}"
            sleep 1
            ;;
    esac
    
    clear
    print_banner
done
