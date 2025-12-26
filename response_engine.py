import paramiko
import time
import logging

# Setup Logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [SOAR] %(message)s")
LOG = logging.getLogger("soar_engine")

# Configuration for the Victim Machine (Kali)
SSH_USER = "kkkkkk"     # Change to your VM username
SSH_PASS = "kkkkkk"      # Change to your VM password
SSH_PORT = 22

def isolate_host(target_ip):
    """
    Connects to the compromised host and applies a Quarantine firewall policy.
    """
    LOG.info(f"⚡ INITIATING RESPONSE: Isolating Host {target_ip}...")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(target_ip, port=SSH_PORT, username=SSH_USER, password=SSH_PASS, timeout=5)

        # 1. The Quarantine Command (Allow SSH, Block Everything Else)
        commands = [
            f"echo '{SSH_PASS}' | sudo -S iptables -F",  # Flush old rules
            f"echo '{SSH_PASS}' | sudo -S iptables -A INPUT -p tcp --dport 22 -j ACCEPT", # Allow Admin Access
            f"echo '{SSH_PASS}' | sudo -S iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT",
            f"echo '{SSH_PASS}' | sudo -S iptables -P INPUT DROP",  # Drop all other incoming
            f"echo '{SSH_PASS}' | sudo -S iptables -P OUTPUT DROP"  # Drop all other outgoing
        ]

        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status != 0:
                err = stderr.read().decode()
                LOG.error(f"Command failed: {err}")
                return False

        LOG.warning(f"✅ SUCCESS: Host {target_ip} has been QUARANTINED.")
        return True

    except Exception as e:
        LOG.error(f"❌ RESPONSE FAILED: Could not connect to {target_ip}. Reason: {e}")
        return False
    finally:
        ssh.close()

if __name__ == "__main__":
    # Test it manually
    target = input("Enter IP to quarantine (Test Mode): ")
    isolate_host(target)
