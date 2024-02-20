#!/bin/bash

clear

make clean

if [ $? -ne 0 ]; then
    echo "Error: 'make clean' failed"
    exit 1
fi


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
        echo "Running './guacident diff --test --file=$file' $2"
        
        if [ -f "$file" ]; then

            ./guacident diff --test --file="$file" $2

            if [ $? -ne 0 ]; then
                echo "Error: './guacident diff --test --file=$file $2' failed"
                exit 1
            fi
            sleep 10
        fi
    done
else
    echo "Input dir not found: $INPUT_DIR"
    exit 1
fi
