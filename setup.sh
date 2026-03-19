#!/bin/bash

echo "========================================"
echo "        Project Installation Script     "
echo "========================================"

LOG_FILE="installation_log.txt"
exec > >(tee -a $LOG_FILE) 2>&1

# 1. Install Required System Packages
echo "[1/4] Checking and installing required system packages..."
if command -v apt &>/dev/null; then
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
elif command -v yum &>/dev/null; then
    sudo yum update -y
    REQUIRED_PACKAGES=("golang" "git" "python3" "python3-pip")
    for pkg in "${REQUIRED_PACKAGES[@]}"; do
        if rpm -q $pkg &>/dev/null; then
            echo "  [✔] $pkg is already installed."
        else
            echo "  [➤] Installing $pkg..."
            sudo yum install -y $pkg || { echo "Error: Failed to install $pkg."; exit 1; }
        fi
    done
elif command -v brew &>/dev/null; then
    REQUIRED_PACKAGES=("go" "git" "python3")
    for pkg in "${REQUIRED_PACKAGES[@]}"; do
        if brew list | grep -q "^$pkg\$"; then
            echo "  [✔] $pkg is already installed."
        else
            echo "  [➤] Installing $pkg..."
            brew install $pkg || { echo "Error: Failed to install $pkg."; exit 1; }
        fi
    done
else
    echo "Unsupported package manager. Please install required packages manually."
    echo "Required packages: golang, git, python3, python3-pip"
fi

#!/bin/bash

echo "[2/4] Installing Subfinder..."
if command -v subfinder &>/dev/null; then
    echo "  [✔] Subfinder is already installed."
else
    echo "  [➤] Installing Subfinder..."
    
    # Clone repository
    git clone https://github.com/projectdiscovery/subfinder.git
    
    # Navigate to directory
    cd subfinder/v2/cmd/subfinder
    
    # Build
    go build
    
    # Move to bin folder
    sudo mv subfinder /usr/local/bin/
    
    # Go back to original directory
    cd -
    
    # Verify installation
    if command -v subfinder &>/dev/null; then
        echo "  [✔] Subfinder installed successfully!"
        subfinder -version
    else
        echo "  [✖] Subfinder installation failed."
        exit 1
    fi
fi

# 3. Create requirements.txt file
echo "[3/4] Creating requirements.txt file..."
cat > requirements.txt << EOF
requests>=2.25.0
bs4>=0.0.1
urllib3>=1.26.0
pyOpenSSL>=20.0.0
dnspython>=2.1.0
validators>=0.18.0
tldextract>=3.1.0
iso3166>=2.0.0
pycountry>=20.7.3
phonenumbers>=8.12.0
timezonefinder>=5.2.0
langdetect>=1.0.9
EOF
echo "  [✔] requirements.txt created successfully!"

# 4. Install Python Dependencies
echo "[4/4] Installing Python dependencies..."
# Determine the appropriate pip command (pip3 if available, else pip)
if command -v pip3 >/dev/null 2>&1; then
    PIP_CMD=pip3
elif command -v pip >/dev/null 2>&1; then
    PIP_CMD=pip
else
    echo "Error: pip is not installed." >&2
    exit 1
fi

# Try installing with --user flag first (most portable)
echo "  [➤] Attempting to install dependencies with --user flag..."
$PIP_CMD install --user -r requirements.txt
PIP_EXIT_CODE=$?

# If the first installation method failed, try alternative methods
if [ $PIP_EXIT_CODE -ne 0 ]; then
    echo "  [➤] User installation failed, trying without --user flag..."
    $PIP_CMD install -r requirements.txt
    PIP_EXIT_CODE=$?
    
    # If still failing, try with sudo
    if [ $PIP_EXIT_CODE -ne 0 ]; then
        echo "  [➤] Standard installation failed, trying with sudo..."
        sudo $PIP_CMD install -r requirements.txt || { 
            echo "Error: All installation methods failed. Please check your Python environment."; 
            exit 1; 
        }
    fi
fi

echo "  [✔] All Python dependencies installed successfully!"

# Update PATH settings if necessary
if [ "$(uname)" = "Linux" ] || [ "$(uname)" = "Darwin" ]; then
    # For Unix-like systems, update ~/.bashrc if necessary.
    GO_BIN_PATH="$HOME/go/bin"
    if [ -d "$GO_BIN_PATH" ] && ! grep -q "$GO_BIN_PATH" ~/.bashrc; then
        echo "export PATH=\$PATH:$GO_BIN_PATH" >> ~/.bashrc
        echo "  [✔] Go bin path added to PATH in ~/.bashrc"
    fi
    
    # Add Python user bin to PATH if not already there
    USER_BIN_PATH="$HOME/.local/bin"
    if [ -d "$USER_BIN_PATH" ] && ! grep -q "$USER_BIN_PATH" ~/.bashrc; then
        echo "export PATH=\$PATH:$USER_BIN_PATH" >> ~/.bashrc
        echo "  [✔] Python user bin path added to PATH in ~/.bashrc"
        echo "  [!] You may need to run 'source ~/.bashrc' or restart your terminal"
    fi
fi

echo "========================================"
echo " Installation Completed Successfully! "
echo "========================================"
echo "  Log file saved to $LOG_FILE"
echo ""
echo "  You can run the project using the following command:"
echo "    python main.py"
