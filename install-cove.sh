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
MAIN_MODE=false

# --- Parse Arguments ---
for arg in "$@"; do
    case "$arg" in
        --dev)
            DEV_MODE=true
            ;;
        --main)
            MAIN_MODE=true
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

# Puts Homebrew on PATH for new terminals, as Homebrew's own "Next steps"
# say to: its installer only prints them, and the shellenv eval'd here lasts
# for this run alone, so the next terminal couldn't find brew or cove.
persist_brew_shellenv() {
    local line="eval \"\$($INSTALL_DIR/brew shellenv)\""
    local profile=""
    case "${SHELL:-}" in
        */zsh*) profile="${ZDOTDIR:-$HOME}/.zprofile" ;;
        */bash*) profile="$HOME/.bash_profile" ;;
    esac
    if [ -z "$profile" ]; then
        echo_info "Add this line to your shell's startup file so new terminals find Homebrew and cove:"
        echo "    $line"
        return 0
    fi
    if grep -qsF "$INSTALL_DIR/brew shellenv" "$profile"; then
        return 0
    fi
    if { echo; echo "$line"; } 2>/dev/null >> "$profile"; then
        echo_info "Added Homebrew to your PATH for new terminals, in $profile."
    else
        echo "${YELLOW}${BOLD}WARNING:${NC} Couldn't write to $profile. Add this line to it so new terminals find Homebrew and cove:"
        echo "    $line"
    fi
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
        if [ "$OS" == "macos" ] && [ -x "$INSTALL_DIR/brew" ]; then
            # Installed, but this shell was never set up for it (Homebrew's
            # "Next steps" skipped): use it rather than install it again.
            echo_info "Found Homebrew in $INSTALL_DIR, though it isn't on your PATH."
            eval "$("$INSTALL_DIR/brew" shellenv)"
            persist_brew_shellenv
        elif [ "$OS" == "macos" ]; then
            # For MacOS, offer to install Homebrew
            echo "${YELLOW}${BOLD}CONFIRM:${NC} Homebrew is not installed, but it's required by Cove on MacOS."
            # Read the confirmation from the terminal, not this script's stdin —
            # under `curl … | bash` stdin is the script pipe, so a bare `read`
            # eats a script byte and never sees the keypress (the install then
            # always aborts as "declined"). Same guard as the install handoff
            # at the end of this file; falls through to a safe decline if there
            # is genuinely no controlling terminal.
            if (exec < /dev/tty) 2>/dev/null; then
                read -p "Would you like to install it now? (y/N) " -n 1 -r < /dev/tty
            else
                REPLY=""
            fi
            echo # Move to a new line
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                echo_info "Installing Homebrew. This may take a few minutes..."
                # Saved whole first: under `bash -c "$(curl …)"` a failed
                # download runs an empty script, which "succeeds". Its stdin
                # is the terminal (a reply above means we have one): Homebrew's
                # installer turns non-interactive when stdin isn't a TTY, as
                # under `curl | bash`, and then can't ask for the sudo password
                # it needs on macOS.
                local brew_installer="$TMP_WORK/homebrew-install.sh"
                if ! curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh -o "$brew_installer"; then
                    echo_error "Couldn't download Homebrew's installer. Please check your connection."
                fi
                if ! /bin/bash "$brew_installer" < /dev/tty || [ ! -x "$INSTALL_DIR/brew" ]; then
                    echo_error "Homebrew installation failed. Please install it manually and run this script again."
                fi
                eval "$("$INSTALL_DIR/brew" shellenv)"
                persist_brew_shellenv
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
        if [ "$OS" = "linux" ] && command -v sudo &>/dev/null; then
            echo_info "Installation directory '$INSTALL_DIR' requires sudo — you may be prompted for your password."
        else
            echo_error "Installation directory '$INSTALL_DIR' is not writable. Please fix permissions or run with sudo."
        fi
    fi
}

# Builds cove.sh from the main branch's source into $1. cove.sh itself is
# only committed in release commits, so the copy on main is the last
# release's: build it the way a release is, with main's compile.sh.
build_cove_from_main() {
    local out="$1" src="$TMP_WORK/src" tool
    for tool in tar gzip; do
        if ! command -v "$tool" &> /dev/null; then
            # Minimal RHEL-family images ship without tar.
            if [ "$OS" = "linux" ]; then
                echo_info "Installing $tool (needed to unpack the source)..."
                $SUDO_CMD $PKG_MANAGER install -y "$tool" > /dev/null 2>&1 || true
            fi
            command -v "$tool" &> /dev/null || echo_error "--main needs $tool to unpack the source. Please install it and run this script again."
        fi
    done

    if ! curl -L --fail --progress-bar "$MAIN_TARBALL_URL" -o "$TMP_WORK/main.tar.gz"; then
        echo_error "Failed to download from '$MAIN_TARBALL_URL'. Please check your connection."
    fi
    mkdir -p "$src"
    if ! tar -xzf "$TMP_WORK/main.tar.gz" -C "$src" --strip-components=1; then
        echo_error "Couldn't unpack the main branch's source."
    fi
    # The tarball carries the last release's cove.sh: remove it, so a build
    # that fails can't leave it behind to be installed in its place.
    rm -f "$src/cove.sh"
    if ! (cd "$src" && bash ./compile.sh > /dev/null) || [ ! -s "$src/cove.sh" ]; then
        echo_error "Couldn't build cove.sh from the main branch's source."
    fi
    mv "$src/cove.sh" "$out"
}

# --- Main Installation Logic ---

# Scratch space for downloads, removed however this script exits.
TMP_WORK=$(mktemp -d "${TMPDIR:-/tmp}/cove-install.XXXXXX")
trap 'rm -rf "$TMP_WORK"' EXIT

# 1. Setup environment variables
setup_environment

# 2. Run checks
pre_flight_checks

# 3. Define installation paths
EXECUTABLE_NAME="cove"
DOWNLOAD_URL="https://github.com/anchorhost/cove/releases/latest/download/cove.sh"
MAIN_TARBALL_URL="https://codeload.github.com/anchorhost/cove/tar.gz/refs/heads/main"
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
    # Download (or build) to temp first, then move with sudo if needed. In
    # our own mktemp dir, not a fixed /tmp name another account could
    # create first.
    TEMP_DOWNLOAD="$TMP_WORK/cove.sh"
    if [ "$MAIN_MODE" = true ]; then
        echo_info "🧪 MAIN MODE: Building cove.sh from the main branch's source (unreleased)..."
        build_cove_from_main "$TEMP_DOWNLOAD"
        echo_success "Built cove.sh from the main branch."
    else
        echo_info "Downloading the latest version of Cove..."
        if ! curl -L --fail --progress-bar "$DOWNLOAD_URL" -o "$TEMP_DOWNLOAD"; then
            echo_error "Failed to download from '$DOWNLOAD_URL'. Please check your connection."
        fi
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

# A non-zero exit from `cove install` (a failed step, or a prompt the user
# declined) must stop us before the success message below: we must not
# claim success after the user has explicitly cancelled.
#
# Redirect stdin from /dev/tty so interactive prompts (gum confirm/choose,
# read) work when this installer is run via `curl | bash`, which would
# otherwise hand the child a closed stdin and silently fail every prompt.
COVE_INSTALL_RC=0
if (exec < /dev/tty) 2>/dev/null; then
    "$DESTINATION_PATH" install < /dev/tty || COVE_INSTALL_RC=$?
else
    "$DESTINATION_PATH" install || COVE_INSTALL_RC=$?
fi
if [ "$COVE_INSTALL_RC" -ne 0 ]; then
    echo "--------------------------------------------------"
    echo "${RED}${BOLD}ERROR:${NC} Cove's setup didn't finish. Run 'cove install' to try again." >&2
    exit "$COVE_INSTALL_RC"
fi

echo "--------------------------------------------------"
echo_success "Cove has been installed successfully!"
echo_info "You can now use the 'cove' command from anywhere in your terminal."
echo_info "You may need to restart your terminal for all changes to take effect."