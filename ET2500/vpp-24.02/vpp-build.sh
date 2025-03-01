#!/bin/bash

# Check if the script is run as root
if [ "$(id -u)" -ne "0" ]; then
    echo "This script needs to be run as root. Please use sudo to execute the script."
    exit 1
fi

# Check for build type argument
if [ -z "$1" ]; then
    echo "Error: No build type specified. Please use '-debug' or '-release'."
    exit 1 
elif [ "$1" = "-debug" ]; then     
    BUILD_CMD="make build"
elif [ "$1" = "-release" ]; then     
    BUILD_CMD="make build-release"
else
    echo "Error: Invalid build type specified. Please use '-debug' or '-release'."
    exit 1 
fi

# Install necessary packages
echo "Installing necessary packages..."
apt install bzip2 git cmake -y
if [ $? -ne 0 ]; then
    echo "Failed to install packages."
    exit 1
fi

# Reinstall ca-certificates and update certificates
echo "Reinstalling ca-certificates and updating certificates..."
apt-get install --reinstall ca-certificates -y
if [ $? -ne 0 ]; then
    echo "Failed to reinstall ca-certificates."
    exit 1
fi

update-ca-certificates -y
if [ $? -ne 0 ]; then
    echo "Failed to update certificates."
    exit 1
fi

# Configure Git to recognize the current directory as safe
echo "Configuring Git to recognize the current directory as safe..."
git config --global --add safe.directory "$(pwd)"
if [ $? -ne 0 ]; then
    echo "Failed to configure Git safe.directory."
    exit 1
fi

# Run make install-dep
echo "Running make install-dep..."
make install-dep
if [ $? -ne 0 ]; then
    echo "Failed to run make install-dep."
    exit 1
fi

# Get the OS name and version
OS_NAME=$(lsb_release -is)
OS_VERSION=$(lsb_release -rs)

# Check if the OS is Ubuntu 24.04
if [ "$OS_NAME" = "Ubuntu" ] && [ "$OS_VERSION" = "24.04" ]; then
    echo "Detected Ubuntu 24.04. Setting GCC and G++ to version 12..."
    export CC=gcc-12     
    export CXX=g++-12     
    echo "GCC and G++ are now set to version 12."
else
    echo "This is not Ubuntu 24.04. No changes made."
fi

# Set environment variable
export VPP_PLATFORM=octeon10
export ASROUTER_NAME=$2

# Run the appropriate build command
echo "Running $BUILD_CMD..."
$BUILD_CMD
if [ $? -ne 0 ]; then
    echo "Failed to run $BUILD_CMD."
    exit 1 
fi

echo "All operations completed successfully."
