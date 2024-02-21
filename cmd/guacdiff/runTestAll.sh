#!/bin/bash

clear

make clean
make build

if [ $? -ne 0 ]; then
    echo "Error: 'make build' failed"
    exit 1
fi

make run

if [ $? -ne 0 ]; then
    echo "Error: 'make run' failed"
    exit 1
fi

INPUT_DIR="$1"

if [ -d "$INPUT_DIR" ]; then
    for file in "$INPUT_DIR"/*; do
        echo
        echo "Running './guacdiff diff --test --file=$file' $2"
        if [ -f "$file" ]; then
            output=$(./guacdiff diff --test --file="$file" $2 | tail -n 1)  # Capture the last line of the command output
            echo "output dot file: $output"  # Print the last line of output
            if [ "$output" != "Identical" ]; then

                dot -Tjpg "$output" -o "${file%.dot}.jpg"  # Run the dot command and output as JPG
            else
                echo "Skipping 'dot' command because sboms are 'Identical'"
            fi
            sleep 10
        fi
    done
else
    echo "Input dir not found: $INPUT_DIR"
    exit 1
fi
