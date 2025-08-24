#!/bin/bash

# ====================================================
#  Cove Installer
#  Description: Detects architecture, creates install paths,
#               and installs the latest version of cove.sh.
# ====================================================

set -e # Exit immediately if a command exits with a non-zero status.

# --- Configuration & Architecture Detection ---
INSTALL_DIR="/usr/local/bin" # Default for Intel
if [ "$(uname -m)" = "arm64" ]; then
    INSTALL_DIR="/opt/homebrew/bin" # Override for Apple Silicon
fi

EXECUTABLE_NAME="cove"
DOWNLOAD_URL="https://github.com/anchorhost/cove/releases/latest/download/cove.sh"
DESTINATION_PATH="$INSTALL_DIR/$EXECUTABLE_NAME"

# --- Helper Functions for Colored Output ---
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
fi

# 3. Check for Homebrew. If not found, offer to install it.
if ! command -v brew &> /dev/null; then
    echo "${YELLOW}${BOLD}CONFIRM:${NC} Homebrew is not installed, but it's required by Cove."
    read -p "Would you like to install it now? (y/N) " -n 1 -r
    echo # Move to a new line
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo_info "Installing Homebrew. This may take a few minutes and will likely ask for your password."
        # Run the official Homebrew installer
        if ! /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"; then
            echo_error "Homebrew installation failed. Please try installing it manually and then run this script again."
        fi
        
        echo_info "Temporarily configuring shell environment for Homebrew..."
        # Add brew to the current shell session's PATH
        # This is crucial so the script can find the 'brew' command immediately after install
        eval "$($INSTALL_DIR/brew shellenv)"

        echo_success "Homebrew installed successfully."
    else
        echo_error "Homebrew installation declined. Cannot proceed."
    fi
fi

# 4. Check if the installation directory exists. If not, create it.
if [ ! -d "$INSTALL_DIR" ]; then
    echo_info "Installation directory '$INSTALL_DIR' not found. Attempting to create it..."
    if ! sudo mkdir -p "$INSTALL_DIR"; then
        echo_error "Failed to create installation directory. Please check your permissions."
    fi
    if ! sudo chown -R "$(whoami)" "$INSTALL_DIR"; then
        echo_error "Failed to set correct ownership for '$INSTALL_DIR'."
    fi
    echo_success "Successfully created and configured '$INSTALL_DIR'."
fi

# 5. Check if the directory is writable.
if [ ! -w "$INSTALL_DIR" ]; then
    echo_error "Installation directory '$INSTALL_DIR' is not writable. Please fix permissions or run with sudo."
fi

# --- Installation Steps ---

echo_info "Downloading the latest version of Cove..."
if ! curl -L --fail --progress-bar "$DOWNLOAD_URL" -o "$DESTINATION_PATH"; then
    echo_error "Failed to download from '$DOWNLOAD_URL'. Please check your connection."
fi
echo_success "Download complete."

echo_info "Setting execute permissions..."
if ! chmod +x "$DESTINATION_PATH"; then
    echo_error "Failed to set execute permissions. You may need to run this script with sudo."
fi
echo_success "Permissions set successfully."

echo_info "Handing off to Cove to complete the installation..."
echo "--------------------------------------------------"

if ! "$DESTINATION_PATH" install; then
    echo_error "The 'cove install' command failed. Please see the output above for details."
fi

echo "--------------------------------------------------"
echo_success "Cove has been installed successfully!"
echo_info "You can now use the 'cove' command from anywhere in your terminal."
echo_info "You may need to restart your terminal for all changes to take effect."