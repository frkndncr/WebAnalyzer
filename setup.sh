#!/bin/bash

echo "========================================"
echo "        Project Installation Script     "
echo "========================================"

LOG_FILE="installation_log.txt"
exec > >(tee -a $LOG_FILE) 2>&1

# 1. Install Required System Packages
echo "[1/6] Checking and installing required system packages..."
sudo apt update
REQUIRED_PACKAGES=("golang" "git" "python3" "python3-pip")
for pkg in "${REQUIRED_PACKAGES[@]}"; do
    if dpkg -l | grep -q "^ii\s*$pkg"; then
        echo "  [✔] $pkg is already installed."
    else
        echo "  [➤] Installing $pkg..."
        sudo apt install -y $pkg || { echo "Error: Failed to install $pkg."; exit 1; }
    fi
done

# 2. Install Subfinder
echo "[2/6] Installing Subfinder..."
if command -v subfinder &>/dev/null; then
    echo "  [✔] Subfinder is already installed."
else
    if [ -d "subfinder" ]; then
        echo "  Subfinder directory already exists. Skipping cloning."
    else
        git clone https://github.com/projectdiscovery/subfinder.git || { echo "Error: Failed to clone Subfinder repository."; exit 1; }
    fi

    cd subfinder/v2/cmd/subfinder || { echo "Error: Cannot navigate to Subfinder directory."; exit 1; }
    echo "  [➤] Building Subfinder..."
    go build . || { echo "Error: Failed to build Subfinder."; exit 1; }
    sudo mv subfinder /usr/local/bin/ || { echo "Error: Failed to move the Subfinder executable."; exit 1; }
    cd - || exit
    echo "  [✔] Subfinder installed successfully!"
fi

# 3. Install Python Dependencies
echo "[3/6] Installing Python dependencies..."
PYTHON_DEPENDENCIES=("requests" "bs4" "urllib3" "pyOpenSSL" "dnspython")
for dep in "${PYTHON_DEPENDENCIES[@]}"; do
    echo "  [➤] Installing $dep..."
    pip3 install $dep --break-system-packages || { echo "Error: Failed to install $dep."; exit 1; }
done
echo "  [✔] Python dependencies installed successfully!"

# 4. Update PATH Settings
echo "[4/6] Updating PATH settings..."
if ! grep -q 'export PATH=$PATH:$HOME/go/bin' ~/.bashrc; then
    echo 'export PATH=$PATH:$HOME/go/bin' >>~/.bashrc
    source ~/.bashrc || { echo "Error: Failed to source .bashrc."; exit 1; }
    echo "  [✔] PATH updated successfully!"
else
    echo "  [✔] PATH is already configured."
fi

# 5. Finalizing Installation
echo "[5/6] Finalizing installation..."
echo "  You can run the project using the following command:"
echo "    python3 main.py"

echo "========================================"
echo " Installation Completed Successfully! "
echo "========================================"
echo "  Log file saved to $LOG_FILE"