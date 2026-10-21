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
#    `exit` on the same line: bash reads a script as it runs it, so a file
#    replaced in place while main runs (as `cove upgrade` did before this
#    release) would otherwise be read on from where main's line ended, in the
#    new text. Bash parses a whole line before running any of it, so the exit
#    is already read when main returns; on a line of its own it would be read
#    from the new file too.
echo "   - Adding final execution call"
echo '#  Pass all script arguments to the main function, then stop reading.' >> "$OUTPUT_FILE"
echo 'main "$@"; exit $?' >> "$OUTPUT_FILE"

# 5b. Landing pads for upgrades from the releases that write the new script
#     over the running one. From v1.16 to v2.4, `cove upgrade` on Linux with a
#     root-owned install dir ran `sudo cp` onto the file bash was still
#     executing. Their last line is a bare `main "$@"`, so when main returns,
#     bash reads on at the old file's size as a byte offset into this build
#     and runs whatever is there (a 2.4 upgrade landed in the middle of
#     cove_proxy_delete and ran its picker). Those releases run their own
#     upgrade code, so this build has to make each of those offsets safe.
#
#     A pad goes in at the last top-level function start before each offset,
#     long enough to reach past it: a here-document, of lines of # and lines
#     of ` exit 0` and ended by a line `exit 0`, for a `:` inside `if false`.
#     Running this build, bash reads the pad as the here-document's text and
#     runs nothing in it. An old process starts reading partway into it,
#     where there's no here-document, only commands: a # line is a comment
#     and ` exit 0` exits. Starting partway into one, the rest is a word that
#     isn't a command (one "command not found" line), then the next one
#     exits; after the last comes the end line, itself `exit 0`. Partway into
#     the opening or closing lines, bash meets a `then` or `fi` it didn't see
#     opened, a syntax error that ends it too. Only starting at the pad's
#     first byte, or at the i of its closing fi, would let it through. The
#     offset itself is placed deep inside a # line, and checked there after
#     the build (6b).
#
#     A here-document rather than bare comments, as bash skips one several
#     times faster (the pads are large when an offset falls in a big
#     function: the dashboard's create_gui_file is close to 1 MB, and every
#     cove command reads them), and under `if false` so it is never written
#     out to a temporary file as a here-document that runs would be.
#
#     The sizes are the published cove.sh of each of those releases (git
#     cat-file -s v2.4:cove.sh), v2.0 to v2.4: about 33 KB of pads. v1.16
#     (864166) and v1.17 (914619) are left out on purpose: both land inside
#     create_gui_file, and their pads alone took this build from 2.2 MB to
#     3.8 MB, read by every cove command. Upgrading from those two still runs
#     stray code once, as it always did. Earlier releases replace the file
#     with mv, which never writes into the old one, and releases from this
#     one on install a new file and rename it over the old.
UPGRADE_LANDING_OFFSETS="1389250 1403361 1481466 1667855 1791418"
PAD_NL=$'\n'
PAD_OPEN="if false; then : <<'exit 0'"
PAD_CLOSE="exit 0${PAD_NL}fi"
PAD_GUARD=" exit 0"
# The offset lands at least PAD_MARGIN bytes inside the pad's first # line.
PAD_MARGIN=64

pad_hashes() {
    printf '%*s' "$1" '' | tr ' ' '#'
}

# Is byte offset $1 of the build the start of a line at the top level: not in
# a function, a quoted string or a here-document? The text before it has to
# parse on its own, and a stray ) after it has to be a syntax error (inside a
# here-document it would be data; bash 3.2 doesn't flag an unclosed one).
pad_top_level_at() {
    head -c "$1" "$OUTPUT_FILE" > "$OUTPUT_FILE.prefix"
    bash -n "$OUTPUT_FILE.prefix" 2>/dev/null || return 1
    printf ')\n' >> "$OUTPUT_FILE.prefix"
    ! bash -n "$OUTPUT_FILE.prefix" 2>/dev/null
}

echo "   - Adding upgrade landing pads for ${UPGRADE_LANDING_OFFSETS// /, }"
pad_after=0
for offset in $UPGRADE_LANDING_OFFSETS; do
    build_size=$(wc -c < "$OUTPUT_FILE" | tr -d ' ')
    # An offset at or past the end reads nothing more: no pad needed.
    if [ "$offset" -ge "$build_size" ]; then
        echo "     · $offset: past the end of the build, nothing to read there"
        continue
    fi
    # Function starts after the previous offset (a pad before it would move
    # that offset out of its own pad) and far enough before this one, nearest
    # first. Byte offsets: awk in the C locale counts bytes.
    pad_at=""
    for candidate in $(LC_ALL=C awk -v lo="$pad_after" -v hi="$((offset - ${#PAD_OPEN} - 1 - PAD_MARGIN))" '
            /^[A-Za-z_][A-Za-z0-9_]*\(\) \{$/ && off > lo && off <= hi { print off }
            { off += length($0) + 1 }' "$OUTPUT_FILE" | sort -rn); do
        if pad_top_level_at "$candidate"; then
            pad_at="$candidate"
            break
        fi
    done
    rm -f "$OUTPUT_FILE.prefix"
    if [ -z "$pad_at" ]; then
        echo "Error: no top-level function starts before byte $offset to put its upgrade landing pad in front of." >&2
        exit 1
    fi
    pad="$PAD_OPEN$PAD_NL$(pad_hashes $((offset - pad_at - ${#PAD_OPEN} - 1 + PAD_MARGIN)))$PAD_NL$PAD_GUARD$PAD_NL"
    pad="$pad$(pad_hashes 200)$PAD_NL$PAD_GUARD$PAD_NL$(pad_hashes 200)$PAD_NL$PAD_GUARD$PAD_NL$PAD_CLOSE$PAD_NL"
    {
        head -c "$pad_at" "$OUTPUT_FILE"
        printf '%s' "$pad"
        tail -c +"$((pad_at + 1))" "$OUTPUT_FILE"
    } > "$OUTPUT_FILE.pad" && mv -f "$OUTPUT_FILE.pad" "$OUTPUT_FILE"
    echo "     · $offset: ${#pad}-byte pad at byte $pad_at"
    pad_after=$offset
done

# 6. Syntax-check the compiled output. Catches an embedding accident — a
#    heredoc delimiter fused onto a source file's unterminated last line, a
#    truncated append — that would otherwise ship as a broken artifact.
if ! bash -n "$OUTPUT_FILE"; then
    echo "Error: compiled ${OUTPUT_FILE} failed bash -n syntax check." >&2
    exit 1
fi

# 6b. Check each landing offset in the finished build: it sits inside a #
#     line, with # for at least 32 bytes on both sides, and the lines after
#     it are the pad's own, up to its end. An old process resuming there
#     reads a comment, then ` exit 0`. The pad's opening line is at the top
#     level, where the syntax check above has parsed it as a here-document.
for offset in $UPGRADE_LANDING_OFFSETS; do
    [ "$offset" -lt "$(wc -c < "$OUTPUT_FILE" | tr -d ' ')" ] || continue
    pad_before=$(head -c "$offset" "$OUTPUT_FILE" | tail -c 32)
    pad_rest=$(tail -c +"$((offset + 1))" "$OUTPUT_FILE" | head -n 9)
    pad_line="${pad_rest%%"$PAD_NL"*}"
    pad_ok=true
    case "$pad_before$pad_line" in *[!#]*) pad_ok=false ;; esac
    [ "${#pad_before}" -eq 32 ] && [ "${#pad_line}" -ge 32 ] || pad_ok=false
    expected="$pad_line$PAD_NL$PAD_GUARD$PAD_NL$(pad_hashes 200)$PAD_NL$PAD_GUARD$PAD_NL$(pad_hashes 200)$PAD_NL$PAD_GUARD$PAD_NL$PAD_CLOSE"
    [ "${pad_rest%"$PAD_NL"*}" = "$expected" ] || pad_ok=false
    if ! $pad_ok; then
        echo "Error: byte $offset of ${OUTPUT_FILE} isn't inside an upgrade landing pad." >&2
        echo "An upgrade from the release that size would run the code there." >&2
        exit 1
    fi
done

# 7. Make the final script executable and put it in place atomically.
chmod +x "$OUTPUT_FILE"
mv -f "$OUTPUT_FILE" "$FINAL_FILE"

echo ""
echo "✅ Compilation complete!"
echo "   Distribution script created at: $(pwd)/${FINAL_FILE}"