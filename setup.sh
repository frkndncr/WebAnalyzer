# 2. Install Subfinder
echo "[2/4] Installing Subfinder..."
if command -v subfinder &>/dev/null; then
    echo "  [✔] Subfinder is already installed."
else
    # Try to install with git and go
    if command -v go &>/dev/null; then
        echo "  [➤] Installing Subfinder..."
        if [ -d "subfinder" ]; then
            echo "  Subfinder directory already exists. Removing it..."
            rm -rf subfinder
        fi
        git clone https://github.com/projectdiscovery/subfinder.git || { echo "Error: Failed to clone Subfinder repository."; exit 1; }
        cd subfinder/v2/cmd/subfinder 2>/dev/null || {
            # Try alternative directory structure
            cd subfinder/cmd/subfinder 2>/dev/null || { echo "Error: Cannot navigate to Subfinder directory."; exit 1; }
        }
        echo "  [➤] Building Subfinder..."
        go build . || { echo "Error: Failed to build Subfinder."; exit 1; }
        sudo mv subfinder /usr/local/bin/ || { echo "Error: Failed to move the Subfinder executable."; exit 1; }
        cd - || exit
        echo "  [✔] Subfinder installed successfully!"
    else
        echo "Error: Go is required to install Subfinder."
        exit 1
    fi
fi
