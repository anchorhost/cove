#!/bin/bash

# ----------------------------------------------------
#  Compiler for Cove
#  Description: Combines the main script and individual command files into a single distributable script.
# ----------------------------------------------------

# --- Configuration ---
# The final, compiled script that will be generated.
OUTPUT_FILE="cove.sh"

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

echo "🚀 Starting compilation of ${OUTPUT_FILE}..."

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

# 4. NOW, add the main function call at the very end of the script.
echo "   - Adding final execution call"
echo '#  Pass all script arguments to the main function.' >> "$OUTPUT_FILE"
echo 'main "$@"' >> "$OUTPUT_FILE"


# 5. Make the final script executable.
chmod +x "$OUTPUT_FILE"

echo ""
echo "✅ Compilation complete!"
echo "   Distribution script created at: $(pwd)/${OUTPUT_FILE}"