# DigitalOcean Droplet Files

This directory contains files used for DigitalOcean droplet preparation and automation.

## Files:

### setup_droplet.sh
Bash script that prepares an Ubuntu 22.04 droplet with:
- Google Chrome (latest stable)
- ChromeDriver (matching Chrome version)
- Python 3 and required packages (selenium, paramiko, pyotp, etc.)

**Usage:**
```bash
# SSH into your droplet
# Upload this script
# Run as root
sudo bash setup_droplet.sh
```

After running this script, create a DigitalOcean snapshot of the droplet.
This snapshot will be used as the base image for bulk droplet creation.

### do_automation.py
Python script for Google Workspace automation that runs on the droplet.
This is a simplified version of the AWS Lambda automation adapted for running on regular VMs.

**Note:** This is currently a placeholder structure. The full automation logic from
`repo_aws_files/main.py` needs to be adapted and implemented here.

## Workflow:

1. **Initial Setup:**
   - Create a new DigitalOcean droplet (Ubuntu 22.04)
   - Upload `setup_droplet.sh`
   - Run the setup script
   - Manually install/configure your automation script
   - Test the automation
   - Create a snapshot

2. **Bulk Execution:**
   - Use the snapshot ID in DigitalOcean configuration (in Settings page)
   - When running bulk automation, the system will:
     - Create multiple droplets from the snapshot
     - Distribute users across droplets
     - SSH into each droplet and run automation
     - Collect results
     - Destroy droplets (if auto-destroy is enabled)
