#!/bin/bash

# ----------------------------------------------------
#  Compiler for Cove
#  Description: Combines the main script and individual command files into a single distributable script.
# ----------------------------------------------------

# --- Configuration ---
# The final, compiled script that will be generated.
# Built into a scratch file and moved over cove.sh at the end: an atomic
# rename gives the new build its own inode, so a cove process still running
# from the old file (a long history save, the watchdog's sweeps) keeps
# reading the script it started with. Bash reads scripts incrementally, and
# truncating cove.sh underneath one had it re-run its command when the
# function it was in returned.
FINAL_FILE="cove.sh"
OUTPUT_FILE="cove.sh.build"

# The main script file containing the entry point, helpers, and globals.
MAIN_SCRIPT="main"

# The directory where individual command function files are stored.
COMMANDS_DIR="commands"
# --- End Configuration ---

# Ensure the script is run from the 'cove' directory
if [ ! -f "$MAIN_SCRIPT" ] || [ ! -d "$COMMANDS_DIR" ]; then
    echo "Error: This script must be run from the 'cove' directory." >&2
    echo "Required files/dirs not found: '$MAIN_SCRIPT', '$COMMANDS_DIR'" >&2
    exit 1
fi

# The menu bar sources are REQUIRED — checked before any output is written.
# Silently skipping them (or cat-ing a missing file into an empty heredoc)
# would exit 0 and ship a cove.sh whose `cove menubar enable` is broken for
# every user.
MENUBAR_DIR="menubar"
for menubar_file in Sources/main.m Resources/Info.plist Resources/Assets/cove-logo.svg Linux/cove-tray.py; do
    if [ ! -f "$MENUBAR_DIR/$menubar_file" ]; then
        echo "Error: ${MENUBAR_DIR}/${menubar_file} not found — cannot embed the menu bar app." >&2
        exit 1
    fi
done

# The Adminer theme is REQUIRED too, for the same reason: it is embedded and
# written out by deploy_adminer_theme, which no longer downloads it.
ADMINER_THEME_DIR="adminer-theme"
for theme_file in adminer.css adminer.js; do
    if [ ! -f "$ADMINER_THEME_DIR/$theme_file" ]; then
        echo "Error: ${ADMINER_THEME_DIR}/${theme_file} not found — cannot embed the Adminer theme." >&2
        exit 1
    fi
done

echo "🚀 Starting compilation of ${FINAL_FILE}..."

# 1. Start with the main script content, but EXCLUDE the final line that calls the main function.
#    This ensures all functions are defined before any are called.
echo "   - Adding main script logic from ${MAIN_SCRIPT} (excluding main call)"
grep -v 'main "$@"' "$MAIN_SCRIPT" > "$OUTPUT_FILE"

# 2. Add a separator and a clear marker for the sourced functions.
echo "" >> "$OUTPUT_FILE"
echo "# --- Sourced Command Functions ---" >> "$OUTPUT_FILE"
echo "# The following functions are sourced from the '${COMMANDS_DIR}/' directory." >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# 3. Append each command file from the commands directory.
#    Using 'find' and 'sort' ensures a consistent order.
for cmd_file in $(find "$COMMANDS_DIR" -type f | sort); do
    if [ -f "$cmd_file" ]; then
        echo "   - Appending command from ${cmd_file}"
        cat "$cmd_file" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE" # Add a newline for readability
    fi
done

# 4. Embed the menu bar apps (menubar/) as emitter functions so the
#    distributed cove.sh stays a single self-contained file. Sources are kept
#    as real editable files in menubar/ and inlined here at compile time:
#    main.m + Info.plist + the SVG logo (macOS) and cove-tray.py (Linux) as
#    quoted heredocs. `cove menubar enable` writes these out — building
#    locally with clang on macOS, running as-is under python3 on Linux.
#    Presence of all four source files was asserted up top, before any
#    output was written.
if [ -d "$MENUBAR_DIR" ]; then
    echo "   - Embedding menu bar apps (macOS + Linux) from ${MENUBAR_DIR}/"
    {
        echo "# --- Embedded Menu Bar Apps (generated from ${MENUBAR_DIR}/ by compile.sh) ---"
        echo ""
        echo "emit_menubar_main_m() {"
        echo "cat <<'COVE_MENUBAR_MAIN_M_EOF'"
        cat "$MENUBAR_DIR/Sources/main.m"
        echo "COVE_MENUBAR_MAIN_M_EOF"
        echo "}"
        echo ""
        echo "emit_menubar_info_plist() {"
        echo "cat <<'COVE_MENUBAR_PLIST_EOF'"
        cat "$MENUBAR_DIR/Resources/Info.plist"
        echo "COVE_MENUBAR_PLIST_EOF"
        echo "}"
        echo ""
        echo "emit_menubar_icon_svg() {"
        echo "cat <<'COVE_MENUBAR_ICON_EOF'"
        cat "$MENUBAR_DIR/Resources/Assets/cove-logo.svg"
        echo "COVE_MENUBAR_ICON_EOF"
        echo "}"
        echo ""
        echo "emit_menubar_tray_py() {"
        echo "cat <<'COVE_MENUBAR_TRAY_EOF'"
        cat "$MENUBAR_DIR/Linux/cove-tray.py"
        echo "COVE_MENUBAR_TRAY_EOF"
        echo "}"
        echo ""
    } >> "$OUTPUT_FILE"
fi

# 4b. Embed the Adminer theme (adminer-theme/) the same way. It used to be
#     downloaded at install time from the repo's main branch: unpinned code
#     running inside an auto-signed-in database manager, a network dependency
#     for an otherwise offline install, and local edits that reached nobody
#     until pushed. Now the theme ships with the cove.sh it was built with.
echo "   - Embedding Adminer theme from ${ADMINER_THEME_DIR}/"
{
    echo "# --- Embedded Adminer Theme (generated from ${ADMINER_THEME_DIR}/ by compile.sh) ---"
    echo ""
    echo "emit_adminer_theme_css() {"
    echo "cat <<'COVE_ADMINER_CSS_EOF'"
    cat "$ADMINER_THEME_DIR/adminer.css"
    echo "COVE_ADMINER_CSS_EOF"
    echo "}"
    echo ""
    echo "emit_adminer_theme_js() {"
    echo "cat <<'COVE_ADMINER_JS_EOF'"
    cat "$ADMINER_THEME_DIR/adminer.js"
    echo "COVE_ADMINER_JS_EOF"
    echo "}"
    echo ""
} >> "$OUTPUT_FILE"

# 5. NOW, add the main function call at the very end of the script.
echo "   - Adding final execution call"
echo '#  Pass all script arguments to the main function.' >> "$OUTPUT_FILE"
echo 'main "$@"' >> "$OUTPUT_FILE"


# 6. Syntax-check the compiled output. Catches an embedding accident — a
#    heredoc delimiter fused onto a source file's unterminated last line, a
#    truncated append — that would otherwise ship as a broken artifact.
if ! bash -n "$OUTPUT_FILE"; then
    echo "Error: compiled ${OUTPUT_FILE} failed bash -n syntax check." >&2
    exit 1
fi

# 7. Make the final script executable and put it in place atomically.
chmod +x "$OUTPUT_FILE"
mv -f "$OUTPUT_FILE" "$FINAL_FILE"

echo ""
echo "✅ Compilation complete!"
echo "   Distribution script created at: $(pwd)/${FINAL_FILE}"