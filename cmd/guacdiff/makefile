# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GORUN=$(GOCMD) run

# Binary name
BINARY_NAME=guacdiff

# Main source file
MAIN_SOURCE_FILE=main.go

# Targets
.PHONY: all build clean run

all: clean build run

build:
	@echo "Building $(BINARY_NAME)..."
	@$(GOBUILD) -o $(BINARY_NAME) $(MAIN_SOURCE_FILE)

clean:
	@echo "Cleaning $(BINARY_NAME)..."
	@$(GOCLEAN)
	@rm -f $(BINARY_NAME)
	@rm *.dot

test: build
	@echo "Running $(BINARY_NAME) diff --test..."
	@./$(BINARY_NAME) diff --test 


