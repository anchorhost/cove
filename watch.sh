#!/bin/bash

# ----------------------------------------------------
#  This script uses fswatch to monitor for changes and trigger the compile script.
# ----------------------------------------------------

# The paths to watch.
WATCH_PATHS="main commands watch.sh"

echo "👀 Watching for changes in '$WATCH_PATHS'..."
echo "Press Ctrl+C to stop."

# The fswatch command:
# -o bundles changes together to run the command only once.
# It then pipes the event to a loop that runs our compile script.
fswatch -o $WATCH_PATHS | while read -r; do
  echo "🔥 [$(date +'%Y-%m-%d %H:%M:%S')] Change detected! Recompiling..."
  ./compile.sh > /dev/null 2>&1
done