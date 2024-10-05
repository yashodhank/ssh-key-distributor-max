"""
Copyright © 2024 Yashodhan Kulkarni <yashodhan.kulkarni@gmail.com>
"""
import paramiko
import os
import sys
import time
import logging
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import pytz  # Added for time zone handling

# Default settings
MAX_RETRIES = 3
RETRY_BACKOFF = 2
DEFAULT_TIMEOUT = 10
MANAGED_KEY_MARKER = "# Managed by SSH Key Distributor"  # Adjusted to match your format

def setup_logging(debug_mode):
    """
    Configure logging settings based on debug mode.
    """
    log_level = logging.DEBUG if debug_mode else logging.INFO
    # Set up logging to console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)

    # Set up logging to file
    logging.basicConfig(
        filename='ssh_key_distributor.log',
        filemode='a',
        format='%(asctime)s - %(levelname)s - %(message)s',
        level=log_level
    )

    # Add console handler
    logging.getLogger().addHandler(console_handler)

def get_hostname(client):
    """
    Retrieve the hostname set on the remote node.
    """
    stdin, stdout, stderr = client.exec_command('hostname')
    hostname = stdout.read().decode('utf-8').strip()
    return hostname

def fix_permissions(client, ssh_user):
    """
    Ensure correct permissions on .ssh directory and its contents.
    """
    commands = [
        f'chown -R {ssh_user}:{ssh_user} ~/.ssh',
        'chmod 700 ~/.ssh',
        'chmod 600 ~/.ssh/authorized_keys',
        'chmod 600 ~/.ssh/id_rsa',
        'chmod 644 ~/.ssh/id_rsa.pub',
    ]
    for cmd in commands:
        client.exec_command(cmd)
    logging.debug(f"Fixed permissions for user {ssh_user}")

def ensure_ssh_directory(client, ssh_user):
    """
    Ensure that the .ssh directory and authorized_keys file exist.
    If not, prompt the user whether to create them.
    """
    stdin, stdout, stderr = client.exec_command('test -d ~/.ssh && echo "EXISTS"')
    ssh_dir_exists = stdout.read().decode().strip() == "EXISTS"

    if not ssh_dir_exists:
        create_ssh_dir = input(f"The ~/.ssh directory does not exist for user {ssh_user}. Create it? (yes/no): ").strip().lower()
        if create_ssh_dir == 'yes':
            client.exec_command('mkdir -p ~/.ssh')
            logging.info(f"Created ~/.ssh directory for user {ssh_user}")
        else:
            logging.error(f"Cannot proceed without ~/.ssh directory on node.")
            return False

    stdin, stdout, stderr = client.exec_command('test -f ~/.ssh/authorized_keys && echo "EXISTS"')
    auth_keys_exists = stdout.read().decode().strip() == "EXISTS"

    if not auth_keys_exists:
        create_auth_keys = input(f"The ~/.ssh/authorized_keys file does not exist for user {ssh_user}. Create it? (yes/no): ").strip().lower()
        if create_auth_keys == 'yes':
            client.exec_command('touch ~/.ssh/authorized_keys')
            logging.info(f"Created ~/.ssh/authorized_keys file for user {ssh_user}")
        else:
            logging.error(f"Cannot proceed without ~/.ssh/authorized_keys file on node.")
            return False

    return True

def rotate_ssh_key_on_node(client, node_identifier, ssh_user):
    """
    Rotate the SSH key pair on the node with standard key comment.
    """
    key_comment = f"{ssh_user}@{node_identifier}"
    commands = [
        'rm -f ~/.ssh/id_rsa ~/.ssh/id_rsa.pub',
        f'ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -C "{key_comment}" -N "" <<< y >/dev/null 2>&1',
    ]
    for cmd in commands:
        client.exec_command(cmd)
    logging.debug(f"Rotated SSH key on node {node_identifier}")
    # Fix permissions after key rotation
    fix_permissions(client, ssh_user)

def collect_public_key(client):
    """
    Collect the public key from the node without any comment.
    """
    stdin, stdout, stderr = client.exec_command('cat ~/.ssh/id_rsa.pub')
    public_key_line = stdout.read().decode('utf-8').strip()
    # Remove any existing comment
    parts = public_key_line.strip().split()
    key_type = parts[0]
    key_data = parts[1]
    public_key = f"{key_type} {key_data}"
    return public_key

def distribute_public_keys_to_node(client, nodes_info, ssh_user):
    """
    Add all collected public keys to the node's authorized_keys file.
    """
    # Ensure .ssh directory and authorized_keys exist
    if not ensure_ssh_directory(client, ssh_user):
        return False

    # Fetch existing authorized_keys content
    stdin, stdout, stderr = client.exec_command('cat ~/.ssh/authorized_keys')
    authorized_keys_content = stdout.read().decode('utf-8').splitlines()

    # Initialize a dictionary to hold existing keys and their metadata
    existing_keys = {}
    for line in authorized_keys_content:
        if MANAGED_KEY_MARKER in line:
            # Parse the line
            parts = line.strip().split()
            if len(parts) < 2:
                continue  # Not a valid key line
            key_type = parts[0]
            key_data = parts[1]
            key = f"{key_type} {key_data}"
            comment = ' '.join(parts[2:])

            # Now parse the comment to extract 'Added', 'Updated', 'Rotated' times
            # Assume the comment format:
            # root@hostname # Managed by SSH Key Distributor | Added: DDMMYY-hhmm | Updated: DDMMYY-hhmm IST | Rotated: DDMMYY-hhmm

            # Split comment by '|'
            comment_sections = comment.split('|')
            if len(comment_sections) >= 2:
                first_part = comment_sections[0].strip()
                added_time = updated_time = rotated_time = None
                for section in comment_sections[1:]:
                    section = section.strip()
                    if section.startswith('Added:'):
                        added_time = section.replace('Added:', '').strip()
                    elif section.startswith('Updated:'):
                        updated_time = section.replace('Updated:', '').strip()
                    elif section.startswith('Rotated:'):
                        rotated_time = section.replace('Rotated:', '').strip()
                existing_keys[key] = {
                    'comment': first_part,
                    'added_time': added_time,
                    'updated_time': updated_time,
                    'rotated_time': rotated_time
                }
            else:
                continue

    # Remove old managed keys
    client.exec_command(f'sed -i "/{MANAGED_KEY_MARKER}/d" ~/.ssh/authorized_keys')

    # Get current time in IST
    ist = pytz.timezone('Asia/Kolkata')
    current_time = datetime.now(ist).strftime('%d%m%y-%H%M')
    current_time_with_ist = f"{current_time} IST"

    # For each node in nodes_info
    for node_info in nodes_info:
        key = node_info['public_key']
        hostname = node_info['hostname']
        rotated = node_info['rotated']

        # Remove comment from key
        key_parts = key.strip().split()
        key_type = key_parts[0]
        key_data = key_parts[1]
        key_no_comment = f"{key_type} {key_data}"

        if key_no_comment in existing_keys:
            added_time = existing_keys[key_no_comment]['added_time']
        else:
            added_time = current_time

        updated_time = current_time_with_ist
        if rotated:
            rotated_time = current_time
        else:
            rotated_time = existing_keys.get(key_no_comment, {}).get('rotated_time', 'Not Rotated')

        key_comment = f"{ssh_user}@{hostname} {MANAGED_KEY_MARKER} | Added: {added_time} | Updated: {updated_time} | Rotated: {rotated_time}"

        key_entry = f"{key_no_comment} {key_comment}"

        # Add the key_entry to authorized_keys
        client.exec_command(f'echo "{key_entry}" >> ~/.ssh/authorized_keys')

    # Fix permissions after updating authorized_keys
    fix_permissions(client, ssh_user)
    logging.debug(f"Distributed public keys to node and fixed permissions")
    return True

def setup_node(ip_address, ssh_user, ssh_private_key, retries, timeout, rotate_keys=False):
    """
    Set up SSH key on node and collect public key.
    """
    for attempt in range(1, retries + 1):
        try:
            logging.info(f"Connecting to {ip_address} (Attempt {attempt}/{retries})")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip_address, username=ssh_user, key_filename=ssh_private_key, timeout=timeout)

            hostname = get_hostname(client) or ip_address
            node_identifier = hostname

            if not ensure_ssh_directory(client, ssh_user):
                logging.error(f"Cannot proceed without ~/.ssh directory and authorized_keys file on {ip_address}")
                return None, None, None

            rotated = False
            if rotate_keys:
                logging.debug(f"Rotating SSH key on node {node_identifier}")
                rotate_ssh_key_on_node(client, node_identifier, ssh_user)
                rotated = True
            else:
                logging.debug(f"Ensuring SSH key exists on node {node_identifier}")
                # Check if key exists
                stdin, stdout, stderr = client.exec_command('test -f ~/.ssh/id_rsa || echo "NO_KEY"')
                if stdout.read().decode().strip() == "NO_KEY":
                    rotate_ssh_key_on_node(client, node_identifier, ssh_user)
                    rotated = True
                else:
                    logging.debug(f"SSH key already exists on node {node_identifier}")
                    # Fix permissions in case they are incorrect
                    fix_permissions(client, ssh_user)

            public_key = collect_public_key(client)
            client.close()
            return hostname, public_key, rotated
        except Exception as e:
            logging.error(f"Failed to set up node {ip_address} on attempt {attempt}: {e}")
            time.sleep(RETRY_BACKOFF ** attempt)
    return None, None, None

def distribute_keys_to_all_nodes(node_ips, ssh_user, ssh_private_key, nodes_info, retries, timeout):
    """
    Distribute all public keys to each node.
    """
    successful_nodes = []
    failed_nodes = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_node = {}
        for ip in node_ips:
            future = executor.submit(
                distribute_keys_to_node, ip, ssh_user, ssh_private_key, nodes_info, retries, timeout
            )
            future_to_node[future] = ip

        for future in as_completed(future_to_node):
            node_ip = future_to_node[future]
            try:
                result = future.result()
                if result:
                    successful_nodes.append(node_ip)
                else:
                    failed_nodes.append(node_ip)
            except Exception as exc:
                logging.error(f"Node {node_ip} generated an exception: {exc}")
                failed_nodes.append(node_ip)

    return successful_nodes, failed_nodes

def distribute_keys_to_node(ip_address, ssh_user, ssh_private_key, nodes_info, retries, timeout):
    """
    Add collected public keys to the node's authorized_keys file.
    """
    for attempt in range(1, retries + 1):
        try:
            logging.info(f"Distributing keys to {ip_address} (Attempt {attempt}/{retries})")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip_address, username=ssh_user, key_filename=ssh_private_key, timeout=timeout)

            result = distribute_public_keys_to_node(client, nodes_info, ssh_user)
            client.close()
            return result
        except Exception as e:
            logging.error(f"Failed to distribute keys to node {ip_address} on attempt {attempt}: {e}")
            time.sleep(RETRY_BACKOFF ** attempt)
    return False

def test_inter_node_connectivity(node_ips, ssh_user, ssh_private_key):
    """
    Ensure that all nodes can connect to each other using the distributed keys.
    """
    print("Testing inter-node connectivity...")
    logging.info("Testing inter-node connectivity...")
    success = True
    admin_private_key = os.path.expanduser(ssh_private_key)
    for source_ip in node_ips:
        for target_ip in node_ips:
            if source_ip != target_ip:
                try:
                    logging.debug(f"Testing SSH connection from {source_ip} to {target_ip}")
                    # SSH into source node using admin's private key
                    source_client = paramiko.SSHClient()
                    source_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    source_client.connect(source_ip, username=ssh_user, key_filename=admin_private_key, timeout=DEFAULT_TIMEOUT)

                    # Execute SSH command from source node to target node
                    command = f"ssh -o StrictHostKeyChecking=no {ssh_user}@{target_ip} 'echo SUCCESS'"
                    stdin, stdout, stderr = source_client.exec_command(command)
                    output = stdout.read().decode().strip()
                    error = stderr.read().decode().strip()

                    if output == "SUCCESS":
                        print(f"SSH connection from {source_ip} to {target_ip} successful.")
                        logging.info(f"SSH connection from {source_ip} to {target_ip} successful.")
                    else:
                        print(f"SSH connection from {source_ip} to {target_ip} failed. Error: {error}")
                        logging.error(f"SSH connection from {source_ip} to {target_ip} failed. Error: {error}")
                        success = False

                    source_client.close()
                except Exception as e:
                    print(f"SSH connection from {source_ip} to {target_ip} failed: {e}")
                    logging.error(f"SSH connection from {source_ip} to {target_ip} failed: {e}")
                    success = False
    return success

def save_public_keys(node_public_keys, node_hostnames):
    """
    Save public keys to the admin's machine for future reference.
    """
    keys_dir = os.path.expanduser("~/node_public_keys")
    os.makedirs(keys_dir, exist_ok=True)

    for hostname, public_key in zip(node_hostnames, node_public_keys):
        key_path = os.path.join(keys_dir, f"{hostname}_id_rsa.pub")
        with open(key_path, 'w') as key_file:
            key_file.write(public_key + "\n")
        logging.info(f"Saved public key for {hostname} to {key_path}")

def main():
    parser = argparse.ArgumentParser(description="Distribute SSH keys to remote nodes.")
    parser.add_argument('-u', '--user', type=str, default='root', help='SSH username (default: root)')
    parser.add_argument('-k', '--key', type=str, default='~/.ssh/id_rsa', help='Path to your private SSH key')
    parser.add_argument('-n', '--nodes', type=str, required=True, help='Comma-separated list of node IPs')
    parser.add_argument('-r', '--retries', type=int, default=MAX_RETRIES, help='Number of retries (default: 3)')
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT, help='SSH timeout in seconds (default: 10)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--rotate', action='store_true', help='Rotate SSH keys on nodes')

    args = parser.parse_args()

    setup_logging(args.debug)

    ssh_private_key = os.path.expanduser(args.key)
    ssh_user = args.user
    node_ips = [ip.strip() for ip in args.nodes.split(',') if ip.strip()]

    if not os.path.exists(ssh_private_key):
        print(f"Error: SSH key {ssh_private_key} does not exist.")
        sys.exit(1)

    # Step 1: Set up nodes and collect public keys
    print("Setting up nodes and collecting public keys...")
    logging.info("Setting up nodes and collecting public keys...")
    nodes_info = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_node = {}
        for ip in node_ips:
            future = executor.submit(
                setup_node, ip, ssh_user, ssh_private_key, args.retries, args.timeout, rotate_keys=args.rotate
            )
            future_to_node[future] = ip

        for future in as_completed(future_to_node):
            ip = future_to_node[future]
            hostname, public_key, rotated = future.result()
            if hostname and public_key:
                nodes_info.append({
                    'ip': ip,
                    'hostname': hostname,
                    'public_key': public_key,
                    'rotated': rotated
                })
                logging.info(f"Collected public key from {ip} ({hostname})")
                if args.debug:
                    print(f"Collected public key from {ip} ({hostname})")
            else:
                print(f"Failed to set up node {ip}")
                logging.error(f"Failed to set up node {ip}")
                sys.exit(1)

    # Save public keys for future reference
    save_public_keys([node['public_key'] for node in nodes_info], [node['hostname'] for node in nodes_info])

    # Step 2: Distribute public keys to all nodes
    print("Distributing public keys to all nodes...")
    logging.info("Distributing public keys to all nodes...")
    successful_nodes, failed_nodes = distribute_keys_to_all_nodes(
        node_ips, ssh_user, ssh_private_key, nodes_info, args.retries, args.timeout
    )

    # Step 3: Test inter-node connectivity
    if successful_nodes:
        connectivity_success = test_inter_node_connectivity(successful_nodes, ssh_user, ssh_private_key)
        if not connectivity_success:
            print("Inter-node connectivity test failed.")
            logging.error("Inter-node connectivity test failed.")
        else:
            print("Inter-node connectivity test succeeded.")
            logging.info("Inter-node connectivity test succeeded.")
    else:
        print("No nodes were successfully set up.")
        logging.error("No nodes were successfully set up.")

    # Summary
    print("\nSummary of SSH Key Distribution:")
    logging.info("Summary of SSH Key Distribution:")
    print(f"Successful nodes: {', '.join(successful_nodes) if successful_nodes else 'None'}")
    logging.info(f"Successful nodes: {', '.join(successful_nodes) if successful_nodes else 'None'}")
    print(f"Failed nodes: {', '.join(failed_nodes) if failed_nodes else 'None'}")
    logging.info(f"Failed nodes: {', '.join(failed_nodes) if failed_nodes else 'None'}")

if __name__ == "__main__":
    main()
