# SSH Key Distributor (MAX)

An efficient and robust SSH Key Distributor script for managing, rotating, and distributing SSH keys across multiple remote nodes. This script ensures secure inter-node SSH communication by automating the key distribution process, handling key rotation, and maintaining organized `authorized_keys` files with detailed metadata.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Command](#basic-command)
  - [Options](#options)
  - [Examples](#examples)
- [Configuration](#configuration)
- [Script Overview](#script-overview)
- [Logging](#logging)
- [Testing](#testing)
- [License](#license)
- [Contributing](#contributing)
- [Acknowledgments](#acknowledgments)

## Features

- **Automated SSH Key Distribution**: Distributes SSH public keys to a list of remote nodes, ensuring seamless SSH communication between them.
- **SSH Key Rotation**: Supports rotating SSH keys on remote nodes to enhance security.
- **Customizable Comments**: Adds SSH keys to the `authorized_keys` file with detailed comments including timestamps for when the key was added, updated, and rotated.
- **Inter-node Connectivity Testing**: Verifies that all nodes can successfully SSH into each other after key distribution.
- **Parallel Execution**: Utilizes multithreading to perform operations on multiple nodes concurrently for faster execution.
- **Permission Handling**: Ensures correct permissions are set on `.ssh` directories and files to maintain security.
- **Extensive Logging**: Provides detailed logs for all operations, aiding in troubleshooting and audit trails.

## Prerequisites

- **Python 3.6+**: Ensure you have Python version 3.6 or higher installed.
- **Paramiko Library**: A Python implementation of SSHv2. Used for SSH connections.
- **pytz Library**: For timezone handling to format timestamps in IST (Indian Standard Time).

### Install Required Python Packages

```bash
pip install paramiko pytz
```

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/ssh-key-distributor.git
   cd ssh-key-distributor
   ```

2. **Install Dependencies**

   Install the required Python packages if you haven't already:

   ```bash
   pip install -r requirements.txt
   ```

   *Note: Create a `requirements.txt` file with the following content:*

   ```
   paramiko
   pytz
   ```

## Usage

### Basic Command

```bash
python ssh_key_distributor.py -u USERNAME -k /path/to/private_key -n NODE_IPS [OPTIONS]
```

### Options

- `-u`, `--user`: SSH username (default: `root`).
- `-k`, `--key`: Path to your private SSH key (default: `~/.ssh/id_rsa`).
- `-n`, `--nodes`: **(Required)** Comma-separated list of node IPs.
- `-r`, `--retries`: Number of retries for SSH connections (default: `3`).
- `-t`, `--timeout`: SSH connection timeout in seconds (default: `10`).
- `--rotate`: Rotate SSH keys on nodes.
- `--debug`: Enable debug mode for detailed logging.
- `-h`, `--help`: Show help message and exit.

### Examples

#### Distribute SSH Keys Without Rotation

```bash
python ssh_key_distributor.py -u root -k ~/.ssh/id_rsa -n 192.168.1.10,192.168.1.11
```

#### Distribute SSH Keys With Rotation

```bash
python ssh_key_distributor.py -u root -k ~/.ssh/id_rsa -n 192.168.1.10,192.168.1.11 --rotate
```

#### Enable Debug Mode for Detailed Logging

```bash
python ssh_key_distributor.py -u root -k ~/.ssh/id_rsa -n 192.168.1.10,192.168.1.11 --debug
```

## Configuration

- **SSH User**: By default, the script uses the `root` user. You can specify a different user with the `-u` option.
- **SSH Key**: The script uses your local SSH private key to authenticate with the remote nodes. Ensure the key is added to the `authorized_keys` of the remote user or use passwordless SSH.

## Script Overview

### Workflow

1. **Setup Nodes and Collect Public Keys**

   - Connects to each node.
   - Ensures the `.ssh` directory and `authorized_keys` file exist.
   - Rotates SSH keys if the `--rotate` flag is used.
   - Collects the public SSH key from each node.

2. **Distribute Public Keys to All Nodes**

   - Adds all collected public keys to each node's `authorized_keys` file.
   - Uses a custom comment format for each key:
     ```
     ssh-rsa AAAAB3... root@hostname #Managed by SSH Key Distributor | Added: DDMMYY-hhmm | Updated: DDMMYY-hhmm IST | Rotated: DDMMYY-hhmm
     ```

3. **Test Inter-node Connectivity**

   - Verifies that all nodes can SSH into each other using the distributed keys.

### Key Comment Format

- **Example Entry in `authorized_keys`**:

  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC... root@node01 #Managed by SSH Key Distributor | Added: 051023-1430 | Updated: 051023-1430 IST | Rotated: 051023-1430
  ```

- **Fields**:
  - **Managed by SSH Key Distributor**: Marker to identify keys managed by the script.
  - **Added**: Timestamp when the key was first added.
  - **Updated**: Timestamp when the key was last updated.
  - **Rotated**: Timestamp when the key was last rotated.

## Logging

- **Log File**: `ssh_key_distributor.log`
- **Log Levels**:
  - **INFO**: General information about the script's progress.
  - **DEBUG**: Detailed information for debugging (enabled with `--debug`).
- **Console Output**: The script also outputs logs to the console.

## Testing

- **Dry Run**: Test the script on a single node before deploying it to multiple nodes.
- **Backup**: Backup existing `authorized_keys` files on remote nodes before running the script.
- **Permissions**: Ensure the script has the necessary permissions to execute SSH commands on the remote nodes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please follow these steps:

1. **Fork the Repository**

   Click the "Fork" button at the top right of this page to create a copy of this repository in your account.

2. **Clone Your Fork**

   ```bash
   git clone https://github.com/yourusername/ssh-key-distributor.git
   cd ssh-key-distributor
   ```

3. **Create a New Branch**

   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Make Changes**

   Implement your feature or bug fix.

5. **Commit Changes**

   ```bash
   git commit -am 'Add new feature'
   ```

6. **Push to Your Fork**

   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create a Pull Request**

   Go to the original repository and create a pull request from your fork.

## Acknowledgments

- **Paramiko**: For providing a robust SSH library for Python.
- **pytz**: For timezone handling in Python.
- **Community Contributors**: Thanks to everyone who has contributed by reporting issues, suggesting features, or submitting pull requests.

---

*This script is provided "as is" without warranty of any kind. Use it at your own risk.*
