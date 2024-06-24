#!/bin/bash

# Update the package list
echo "Updating package list..."
sudo yum update -y

# Install iptables
echo "Installing iptables..."
sudo yum install iptables-services -y

# Start and enable iptables service to ensure it runs on boot
echo "Starting and enabling iptables service..."
sudo systemctl start iptables
sudo systemctl enable iptables

# Flush existing iptables rules
echo "Flushing existing iptables rules..."
sudo iptables -F

# Set default policies to drop all incoming and forwarding traffic
echo "Setting default iptables policies..."
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT # Allow all outbound traffic by default

# Allow inbound HTTPS traffic (port 8443)
echo "Allowing HTTPS traffic..."
sudo iptables -A INPUT -p tcp --dport 8443 -j ACCEPT

# Allow established and related connections for ongoing HTTPS sessions
echo "Allowing established and related connections..."
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Save iptables rules to ensure they persist across reboots
echo "Saving iptables rules..."
sudo iptables-save | sudo tee /etc/sysconfig/iptables

# Restart iptables to apply the rules
echo "Restarting iptables..."
sudo systemctl restart iptables

# Stop and disable SSH
echo "Stopping and disabling SSH service..."
sudo systemctl stop sshd
sudo systemctl disable sshd

# Stop and disable SSM agent
echo "Stopping and disabling SSM agent service..."
if systemctl list-units --type=service | grep -q "amazon-ssm-agent.service"; then
    sudo systemctl stop amazon-ssm-agent
    sudo systemctl disable amazon-ssm-agent
fi

# Disable serial-getty service on ttyS0 to block serial console access
echo "Disabling serial-getty service on ttyS0..."
if systemctl list-units --type=service | grep -q "serial-getty@ttyS0.service"; then
    sudo systemctl stop serial-getty@ttyS0.service
    sudo systemctl disable serial-getty@ttyS0.service
    sudo systemctl mask serial-getty@ttyS0.service
fi

# Reload systemd manager configuration to apply changes
sudo systemctl daemon-reload

# Ensure no getty is running on ttyS0
sudo killall getty || true

echo "Instance has been locked down. Only HTTPS (port 443) is allowed."
