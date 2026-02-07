#!/bin/bash
###############################################################################
# DigitalOcean Droplet Setup Script
# 
# This script prepares an Ubuntu 22.04 droplet with Chrome, ChromeDriver,
# and Python environment for Google Workspace automation.
#
# Installation Steps:
# 1. Updates system packages
# 2. Installs Chrome and ChromeDriver
# 3. Installs Python 3.10+ and required packages
# 4. Sets up the automation script (do_automation.py)
# 5. Configures SFTP access for result collection
#
# Usage:
#   Run as root: sudo bash setup_droplet.sh
###############################################################################

set -e  # Exit on any error

echo "===== DigitalOcean Droplet Setup for Google Workspace Automation ====="
echo "Starting at: $(date)"

# Helper function for robust apt-get
apt_install_with_retry() {
    local max_retries=10
    local count=0
    while [ $count -lt $max_retries ]; do
        DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" "$@" && return 0
        echo "apt-get failed. Retrying in 15s... (Attempt $((count+1))/$max_retries)"
        sleep 15
        # Try to clear locks forcefully if we are stuck
        rm /var/lib/dpkg/lock-frontend || true
        rm /var/lib/dpkg/lock || true
        dpkg --configure -a || true
        count=$((count+1))
    done
    echo "CRITICAL: apt-get failed after $max_retries attempts."
    return 1
}

# Update system packages
echo ""
echo "[1/6] Updating system packages..."
apt_install_with_retry update -y
apt_install_with_retry upgrade -y

# Install basic dependencies
echo ""
echo "[2/6] Installing basic dependencies..."
apt_install_with_retry install -y \
    wget \
    curl \
    unzip \
    python3 \
    python3-pip \
    python3-venv \
    xvfb \
    libxss1 \
    libappindicator1 \
    libindicator7 \
    fonts-liberation \
    libnss3 \
    libgbm1 \
    libxshmfence1

# Install Google Chrome
echo ""
echo "[3/6] Installing Google Chrome..."
wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
apt_install_with_retry install -y ./google-chrome-stable_current_amd64.deb
rm google-chrome-stable_current_amd64.deb

# Verify Chrome installation
CHROME_VERSION=$(google-chrome --version | awk '{print $3}')
echo "Chrome installed: version $CHROME_VERSION"

# Install ChromeDriver (matching Chrome version)
echo ""
echo "[4/6] Installing ChromeDriver..."
CHROME_MAJOR_VERSION=$(google-chrome --version | grep -oP "[0-9]+" | head -1)

if [ "$CHROME_MAJOR_VERSION" -ge "115" ]; then
    echo "Chrome version is 115+, using cf-for-testing..."
    # Fetch the correct ChromeDriver version for 115+
    LATEST_CHROMEDRIVER_VERSION=$(curl -s "https://googlechromelabs.github.io/chrome-for-testing/LATEST_RELEASE_STABLE")
    wget -q "https://storage.googleapis.com/chrome-for-testing-public/$LATEST_CHROMEDRIVER_VERSION/linux64/chromedriver-linux64.zip"
    unzip -q chromedriver-linux64.zip
    mv chromedriver-linux64/chromedriver /usr/local/bin/
    rm -rf chromedriver-linux64.zip chromedriver-linux64
else
    echo "Chrome version is < 115, using legacy storage..."
    CHROMEDRIVER_VERSION=$(curl -sS chromedriver.storage.googleapis.com/LATEST_RELEASE)
    wget -q "https://chromedriver.storage.googleapis.com/$CHROMEDRIVER_VERSION/chromedriver_linux64.zip"
    unzip -q chromedriver_linux64.zip
    mv chromedriver /usr/local/bin/
    chmod +x /usr/local/bin/chromedriver
    rm chromedriver_linux64.zip
fi
chmod +x /usr/local/bin/chromedriver

# Verify ChromeDriver installation
CHROMEDRIVER_VER=$(chromedriver --version | awk '{print $2}')
echo "ChromeDriver installed: version $CHROMEDRIVER_VER"

# Install Python packages
echo ""
echo "[5/6] Installing Python packages..."

# Ensure pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "pip3 not found, installing..."
    apt-get update
    apt-get install -y python3-pip
fi

pip3 install --no-cache-dir \
    selenium==4.15.2 \
    selenium-stealth==1.0.6 \
    selenium-wire==5.1.0 \
    undetected-chromedriver>=3.5.5 \
    paramiko \
    pyotp \
    requests

# Create automation directory
echo ""
echo "[6/6] Setting up automation environment..."
mkdir -p /opt/automation
cd /opt/automation

# Create placeholder for automation script (will be uploaded separately)
cat > /opt/automation/README.txt << 'EOF'
This directory contains the Google Workspace automation script.

The main script (do_automation.py) will be uploaded separately.
SSH keys and SFTP configuration will be set up for result collection.
EOF

# Set permissions
chmod 755 /opt/automation
chmod 644 /opt/automation/README.txt

# Disable unattended upgrades to prevent interference
echo ""
echo "Disabling unattended upgrades..."
systemctl stop unattended-upgrades || true
systemctl disable unattended-upgrades || true

# Clean up
echo ""
echo "Cleaning up..."
apt-get autoremove -y
apt-get autoclean -y

# Create completion marker
touch /opt/automation/setup_complete

echo ""
echo "===== Setup Complete! ====="
echo "Finished at: $(date)"
echo ""
echo "Chrome: $CHROME_VERSION"
echo "ChromeDriver: $CHROMEDRIVER_VER"
echo "Python: $(python3 --version)"
echo ""
echo "Ready for snapshot! Create a DigitalOcean snapshot of this droplet."
echo "The snapshot can be used for bulk droplet creation."
