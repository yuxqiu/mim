#!/bin/bash

# Check if both arguments are provided
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <command> <logfile>"
  exit 1
fi

# Command to run (first argument)
COMMAND=$1

# Log file (second argument)
LOGFILE=$2

# Run the command and log stdout and stderr to the log file
echo "Running command: $COMMAND"
echo "Logging output to: $LOGFILE"
$COMMAND 2>&1 | tee "$LOGFILE"

# Check if the command was successful
if [ $? -eq 0 ]; then
  echo "Command executed successfully, output logged to $LOGFILE"
else
  echo "Command failed, check the log for details."
fi
