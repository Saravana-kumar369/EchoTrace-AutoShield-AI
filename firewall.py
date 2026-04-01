"""
Windows Firewall Integration for EchoTrace-AutoShield.

Creates/removes actual Windows Firewall rules using 'netsh advfirewall'
to block malicious IPs at the OS/network level when the AI flags a threat.

All rules created by this module are prefixed with 'EchoTrace-' for easy
identification and cleanup.

NOTE: Requires Administrator privileges to modify firewall rules.
"""

import subprocess
import logging
import time

logger = logging.getLogger("EchoTrace-Firewall")

RULE_PREFIX = "EchoTrace-Block"

# Track rules we've created (in-memory, reset on restart)
active_rules = {}


def _run_netsh(args, timeout=10):
    """Run a netsh command and return (success, output)."""
    cmd = ["netsh"] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        success = result.returncode == 0
        output = result.stdout.strip() if success else result.stderr.strip()
        return success, output
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except FileNotFoundError:
        return False, "netsh not found"
    except Exception as e:
        return False, str(e)


def check_admin():
    """Check if we have admin privileges (required for firewall rules)."""
    success, output = _run_netsh(["advfirewall", "show", "currentprofile"])
    return success


def block_ip(ip_address, reason="AI-detected threat", username="unknown", attack_type="unknown"):
    """
    Block an IP address by creating an inbound + outbound Windows Firewall rule.
    
    Args:
        ip_address: The IP to block
        reason: Why it's being blocked
        username: Who triggered the block
        attack_type: Type of attack detected
        
    Returns:
        dict with status info
    """
    # Don't block localhost / loopback
    if ip_address in ["127.0.0.1", "::1", "localhost", "0.0.0.0"]:
        return {
            "success": False,
            "message": f"Cannot block loopback address {ip_address}",
            "firewall_rule": None
        }
    
    # Check if already blocked
    if ip_address in active_rules:
        return {
            "success": True,
            "message": f"IP {ip_address} is already blocked",
            "firewall_rule": active_rules[ip_address]["rule_name"],
            "already_blocked": True
        }
    
    rule_name = f"{RULE_PREFIX}-{ip_address.replace('.', '_')}"
    
    # Create INBOUND block rule
    success_in, output_in = _run_netsh([
        "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}-IN",
        "dir=in",
        "action=block",
        f"remoteip={ip_address}",
        "enable=yes",
        f"description=EchoTrace-AutoShield: Blocked {attack_type} from {username} at {time.strftime('%Y-%m-%d %H:%M:%S')}"
    ])
    
    # Create OUTBOUND block rule
    success_out, output_out = _run_netsh([
        "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}-OUT",
        "dir=out",
        "action=block",
        f"remoteip={ip_address}",
        "enable=yes",
        f"description=EchoTrace-AutoShield: Blocked {attack_type} from {username} at {time.strftime('%Y-%m-%d %H:%M:%S')}"
    ])
    
    if success_in and success_out:
        active_rules[ip_address] = {
            "rule_name": rule_name,
            "blocked_at": time.time(),
            "reason": reason,
            "attack_type": attack_type,
            "username": username
        }
        logger.info(f"FIREWALL BLOCK: {ip_address} ({attack_type}) - Rules created: {rule_name}-IN, {rule_name}-OUT")
        return {
            "success": True,
            "message": f"IP {ip_address} blocked in Windows Firewall",
            "firewall_rule": rule_name,
            "inbound": output_in,
            "outbound": output_out
        }
    else:
        error_msg = f"IN: {output_in if not success_in else 'OK'} | OUT: {output_out if not success_out else 'OK'}"
        logger.error(f"FIREWALL BLOCK FAILED: {ip_address} - {error_msg}")
        return {
            "success": False,
            "message": f"Failed to create firewall rules: {error_msg}",
            "firewall_rule": None,
            "requires_admin": "Access is denied" in error_msg or "requested operation requires elevation" in error_msg.lower()
        }


def unblock_ip(ip_address):
    """
    Remove the firewall block rule for an IP address.
    
    Returns:
        dict with status info
    """
    rule_name = f"{RULE_PREFIX}-{ip_address.replace('.', '_')}"
    
    # Remove inbound rule
    success_in, output_in = _run_netsh([
        "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}-IN"
    ])
    
    # Remove outbound rule
    success_out, output_out = _run_netsh([
        "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}-OUT"
    ])
    
    # Remove from tracking
    if ip_address in active_rules:
        del active_rules[ip_address]
    
    if success_in or success_out:
        logger.info(f"FIREWALL UNBLOCK: {ip_address} - Rules removed")
        return {
            "success": True,
            "message": f"IP {ip_address} unblocked from Windows Firewall"
        }
    else:
        return {
            "success": False,
            "message": f"Could not remove firewall rules (may not exist or requires admin)"
        }


def unblock_all():
    """Remove ALL EchoTrace firewall rules."""
    # Delete all rules matching our prefix
    success, output = _run_netsh([
        "advfirewall", "firewall", "delete", "rule",
        f"name={RULE_PREFIX}*"  
    ])
    
    # Clear tracking — also try deleting each known rule individually
    removed = []
    for ip in list(active_rules.keys()):
        unblock_ip(ip)
        removed.append(ip)
    
    active_rules.clear()
    logger.info(f"FIREWALL CLEANUP: Removed all EchoTrace rules ({len(removed)} tracked IPs)")
    
    return {
        "success": True,
        "removed_ips": removed,
        "message": f"All EchoTrace firewall rules removed ({len(removed)} IPs)"
    }


def list_rules():
    """List all active EchoTrace firewall rules."""
    success, output = _run_netsh([
        "advfirewall", "firewall", "show", "rule",
        f"name={RULE_PREFIX}*" if active_rules else "name=EchoTrace-Block*"
    ])
    
    return {
        "tracked_rules": active_rules,
        "firewall_output": output if success else "Could not query firewall rules",
        "total_blocked": len(active_rules)
    }


def get_status():
    """Get firewall integration status."""
    has_admin = check_admin()
    return {
        "admin_privileges": has_admin,
        "active_blocks": len(active_rules),
        "blocked_ips": list(active_rules.keys()),
        "module": "Windows Firewall (netsh advfirewall)"
    }
