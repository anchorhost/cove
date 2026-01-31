#!/bin/bash

# ====================================================
#  Cove Installer (Multi-OS)
#  Description: Detects OS and architecture, creates install paths,
#               and installs the latest version of cove.sh.
# ====================================================

set -e # Exit immediately if a command exits with a non-zero status.

# --- Global Variables ---
OS=""
PKG_MANAGER=""
INSTALL_DIR=""
SUDO_CMD="sudo"
IS_WSL=false
DEV_MODE=false

# --- Parse Arguments ---
for arg in "$@"; do
    case "$arg" in
        --dev)
            DEV_MODE=true
            ;;
    esac
done

# --- Helper Functions for Colored Output ---
# This section remains unchanged from the original script.
if [ -t 1 ]; then
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    BLUE=$(tput setaf 4)
    BOLD=$(tput bold)
    NC=$(tput sgr0) # No Color
else
    RED=""
    GREEN=""
    YELLOW=""
    BLUE=""
    BOLD=""
    NC=""
fi

echo_info() {
    echo "${BLUE}${BOLD}INFO:${NC} $1"
}

echo_success() {
    echo "${GREEN}${BOLD}SUCCESS:${NC} $1"
}

echo_error() {
    echo "${RED}${BOLD}ERROR:${NC} $1" >&2
    exit 1
}

# --- OS & Package Manager Detection ---
setup_environment() {
    echo_info "Detecting operating system and package manager..."
    local os_name
    os_name=$(uname -s)

    # --- Check for MacOS ---
    if [ "$os_name" = "Darwin" ]; then
        OS="macos"
        PKG_MANAGER="brew"
        
        # Architecture detection for MacOS Homebrew paths
        if [ "$(uname -m)" = "arm64" ]; then
            INSTALL_DIR="/opt/homebrew/bin"
        else
            INSTALL_DIR="/usr/local/bin"
        fi
        
        echo_success "Detected $OS with $PKG_MANAGER. Install path set to '$INSTALL_DIR'."
        return 0 # Success, exit function
    fi

    # --- Check for Linux ---
    if [ "$os_name" = "Linux" ]; then
        OS="linux"
        INSTALL_DIR="/usr/local/bin" # Standard for Linux
        
        # Check if running in WSL
        if grep -qEi "(Microsoft|WSL)" /proc/version 2>/dev/null; then
            IS_WSL=true
            echo_info "WSL environment detected."
        fi
        
        # Detect Linux distribution's package manager
        if [ ! -f /etc/os-release ]; then
            echo_error "Could not detect Linux distribution. The file /etc/os-release was not found."
        fi
        
        # shellcheck source=/dev/null
        . /etc/os-release
        if [[ "$ID" == "ubuntu" || "$ID" == "debian" || "$ID_LIKE" == *"debian"* ]]; then
            PKG_MANAGER="apt"
        elif [[ "$ID" == "fedora" || "$ID" == "centos" || "$ID" == "rhel" || "$ID_LIKE" == *"fedora"* || "$ID_LIKE" == *"rhel"* ]]; then
            PKG_MANAGER="dnf"
        else
            echo_error "Unsupported Linux distribution: $ID. Supported: Ubuntu, Debian, Fedora, CentOS, RHEL and derivatives."
        fi
        
        # Check if we need to use sudo
        if [ "$(id -u)" -eq 0 ]; then
            SUDO_CMD=""
        fi
        
        echo_success "Detected $OS with $PKG_MANAGER. Install path set to '$INSTALL_DIR'."
        return 0 # Success, exit function
    fi

    # --- If neither of the above, it's an unsupported OS ---
    echo_error "This script currently only supports MacOS and Linux."
}

# --- Pre-flight Checks & Dependency Management ---
pre_flight_checks() {
    echo_info "Running pre-flight checks..."

    # 1. Check for required command: curl
    if ! command -v curl &> /dev/null; then
        echo_error "cURL is not installed. Please install it using your system's package manager to proceed."
    fi

    # 2. Check for the detected package manager
    if ! command -v $PKG_MANAGER &> /dev/null; then
        if [ "$OS" == "macos" ]; then
            # For MacOS, offer to install Homebrew
            echo "${YELLOW}${BOLD}CONFIRM:${NC} Homebrew is not installed, but it's required by Cove on MacOS."
            read -p "Would you like to install it now? (y/N) " -n 1 -r
            echo # Move to a new line
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                echo_info "Installing Homebrew. This may take a few minutes..."
                if ! /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"; then
                    echo_error "Homebrew installation failed. Please install it manually and run this script again."
                fi
                echo_info "Temporarily configuring shell environment for Homebrew..."
                eval "$($INSTALL_DIR/brew shellenv)"
                echo_success "Homebrew installed successfully."
            else
                echo_error "Homebrew installation declined. Cannot proceed."
            fi
        else
            # For Linux, assume the user should have their package manager.
            echo_error "$PKG_MANAGER is not installed or not in your PATH. Please install it to proceed."
        fi
    fi

    # 3. Check if the installation directory exists and is writable.
    if [ ! -d "$INSTALL_DIR" ]; then
        echo_info "Installation directory '$INSTALL_DIR' not found. Attempting to create it..."
        if ! $SUDO_CMD mkdir -p "$INSTALL_DIR"; then
            echo_error "Failed to create installation directory. Please check your permissions."
        fi
        if ! $SUDO_CMD chown -R "$(whoami)" "$INSTALL_DIR"; then
            echo_error "Failed to set correct ownership for '$INSTALL_DIR'."
        fi
        echo_success "Successfully created and configured '$INSTALL_DIR'."
    fi
    
    if [ ! -w "$INSTALL_DIR" ]; then
        echo_error "Installation directory '$INSTALL_DIR' is not writable. Please fix permissions or run with sudo."
    fi
}

# --- Main Installation Logic ---

# 1. Setup environment variables
setup_environment

# 2. Run checks
pre_flight_checks

# 3. Define installation paths
EXECUTABLE_NAME="cove"
DOWNLOAD_URL="https://github.com/anchorhost/cove/releases/latest/download/cove.sh"
DESTINATION_PATH="$INSTALL_DIR/$EXECUTABLE_NAME"

# Get the directory where this script is located (for --dev mode)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 4. Perform the installation
if [ "$DEV_MODE" = true ]; then
    echo_info "🛠️  DEV MODE: Using local cove.sh from $SCRIPT_DIR"
    
    # Check if local cove.sh exists
    if [ ! -f "$SCRIPT_DIR/cove.sh" ]; then
        echo_error "Local cove.sh not found in '$SCRIPT_DIR'. Run ./compile.sh first."
    fi
    
    # Copy local file to destination
    if [ "$OS" == "linux" ]; then
        if ! $SUDO_CMD cp "$SCRIPT_DIR/cove.sh" "$DESTINATION_PATH"; then
            echo_error "Failed to install cove to '$DESTINATION_PATH'. Please check your permissions."
        fi
        if ! $SUDO_CMD chmod +x "$DESTINATION_PATH"; then
            echo_error "Failed to set execute permissions."
        fi
    else
        if ! cp "$SCRIPT_DIR/cove.sh" "$DESTINATION_PATH"; then
            echo_error "Failed to install cove to '$DESTINATION_PATH'. Please check your permissions."
        fi
        if ! chmod +x "$DESTINATION_PATH"; then
            echo_error "Failed to set execute permissions."
        fi
    fi
    echo_success "Local cove.sh installed to $DESTINATION_PATH"
else
    echo_info "Downloading the latest version of Cove..."

    # Download to temp first, then move with sudo if needed
    TEMP_DOWNLOAD="/tmp/cove.sh.download"
    if ! curl -L --fail --progress-bar "$DOWNLOAD_URL" -o "$TEMP_DOWNLOAD"; then
        echo_error "Failed to download from '$DOWNLOAD_URL'. Please check your connection."
    fi

    # Move to final destination (may require sudo on Linux)
    if [ "$OS" == "linux" ]; then
        if ! $SUDO_CMD mv "$TEMP_DOWNLOAD" "$DESTINATION_PATH"; then
            echo_error "Failed to install cove to '$DESTINATION_PATH'. Please check your permissions."
        fi
        if ! $SUDO_CMD chmod +x "$DESTINATION_PATH"; then
            echo_error "Failed to set execute permissions."
        fi
    else
        if ! mv "$TEMP_DOWNLOAD" "$DESTINATION_PATH"; then
            echo_error "Failed to install cove to '$DESTINATION_PATH'. Please check your permissions."
        fi
        if ! chmod +x "$DESTINATION_PATH"; then
            echo_error "Failed to set execute permissions."
        fi
    fi
    echo_success "Download and installation complete."
fi

# 5. Hand off to Cove to complete its own installation
echo_info "Handing off to Cove to complete the installation..."
echo "--------------------------------------------------"

if ! "$DESTINATION_PATH" install; then
    echo_error "The 'cove install' command failed. Please see the output above for details."
fi

echo "--------------------------------------------------"
echo_success "Cove has been installed successfully!"
echo_info "You can now use the 'cove' command from anywhere in your terminal."
echo_info "You may need to restart your terminal for all changes to take effect."