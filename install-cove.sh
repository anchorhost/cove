#!/bin/bash

# ====================================================
#  Cove Installer
#  Description: Downloads the latest version of cove.sh,
#               installs it to /usr/local/bin, and
#               runs the initial setup.
# ====================================================

set -e # Exit immediately if a command exits with a non-zero status.

# --- Configuration ---
INSTALL_DIR="/usr/local/bin"
EXECUTABLE_NAME="cove"
DOWNLOAD_URL="https://github.com/anchorhost/cove/releases/latest/download/cove.sh"
DESTINATION_PATH="$INSTALL_DIR/$EXECUTABLE_NAME"

# --- Helper Functions for Colored Output ---
# (Checks if TTY is available for color support)
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
}

# --- Pre-flight Checks ---
echo_info "Starting the Cove installation process..."

# 1. Check for Operating System
if [ "$(uname -s)" != "Darwin" ]; then
    echo_error "This script currently only supports MacOS."
    echo "If you'd like it to run on Linux then you can either contribute on Github or gift a Framework laptop to Austin Ginder." >&2
    echo "  - Github: https://github.com/anchorhost/cove" >&2
    echo "  - Gift a Framework Laptop: https://github.com/sponsors/austinginder?frequency=one-time&amount=1999" >&2
    exit 1
fi

# 2. Check for required command: curl
if ! command -v curl &> /dev/null; then
    echo_error "cURL is not installed. Please install it to proceed."
    exit 1
fi

# 3. Check if the installation directory exists and is writable
if [ ! -d "$INSTALL_DIR" ]; then
    echo_error "Installation directory '$INSTALL_DIR' not found."
    exit 1
fi
if [ ! -w "$INSTALL_DIR" ]; then
    echo_error "Installation directory '$INSTALL_DIR' is not writable. Please run with sudo or ensure you have permissions."
    exit 1
fi

# --- Installation Steps ---

# 1. Download the script
echo_info "Downloading the latest version of Cove from GitHub..."
if ! curl -L --fail --progress-bar "$DOWNLOAD_URL" -o "$DESTINATION_PATH"; then
    echo_error "Failed to download from '$DOWNLOAD_URL'. Please check the URL and your connection."
    exit 1
fi
echo_success "Download complete."

# 2. Set execute permissions
echo_info "Setting execute permissions for '$DESTINATION_PATH'..."
if ! chmod +x "$DESTINATION_PATH"; then
    echo_error "Failed to set execute permissions. You may need to run this script with sudo."
    exit 1
fi
echo_success "Permissions set successfully."

# 3. Run the final installation command
echo_info "Handing off to Cove to complete the installation..."
echo "--------------------------------------------------"

# Executing the final command
# The 'cove install' command will now run, and its output will be displayed to the user.
if ! "$DESTINATION_PATH" install; then
    echo_error "The 'cove install' command failed. Please see the output above for details."
    exit 1
fi

echo "--------------------------------------------------"
echo_success "Cove has been installed successfully!"
echo_info "You can now use the 'cove' command from anywhere in your terminal."