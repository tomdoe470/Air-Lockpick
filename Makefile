BINARY_NAME=wifiaudit
BUILD_DIR=build
VERSION=1.0.0
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -s -w"

.PHONY: all build clean install deps run

all: deps build

build:
	@echo "[*] Building $(BINARY_NAME) v$(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	@go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "[+] Binary: $(BUILD_DIR)/$(BINARY_NAME)"

build-linux-arm:
	@GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .
	@echo "[+] ARM64 binary: $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64"

deps:
	@echo "[*] Downloading dependencies..."
	@go mod tidy
	@go mod download

install: build
	@echo "[*] Installing to /usr/local/bin (requires root)..."
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	@sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	@echo "[+] Installed: /usr/local/bin/$(BINARY_NAME)"

dirs:
	@echo "[*] Creating data directories..."
	@mkdir -p data/{macs,sessions,reports,captures}
	@echo "[]" > data/macs/whitelist.json
	@echo "[]" > data/macs/blacklist.json
	@echo "[]" > data/macs/known.json
	@echo "[]" > data/macs/targets.json
	@echo "[+] Data directories created"

clean:
	@rm -rf $(BUILD_DIR)
	@echo "[+] Cleaned build artifacts"

run: build dirs
	@sudo $(BUILD_DIR)/$(BINARY_NAME) $(ARGS)
