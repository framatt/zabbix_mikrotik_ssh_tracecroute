#!/usr/bin/env python3
import paramiko
import json
import re
import sys
import time

# Configuration - will be passed via Zabbix macros
MIKROTIK_HOST = "{$MIKROTIK_IP}"
MIKROTIK_USER = "{$MIKROTIK_USER}"
MIKROTIK_PASS = "{$MIKROTIK_PASS}"
DESTINATION = sys.argv[1] if len(sys.argv) > 1 else "{$TARGET_IP}"
COUNT = "{$PROBE_COUNT}"

def ssh_execute(command):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(MIKROTIK_HOST, username=MIKROTIK_USER, password=MIKROTIK_PASS)
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()
        
        if error:
            print(f"Error: {error}", file=sys.stderr)
        
        return output
    finally:
        client.close()

def parse_traceroute(traceroute_output):
    lines = traceroute_output.strip().split('\n')
    
    # Initialize the result structure
    result = {
        "hops": []
    }
    
    # Process all data blocks (multiple snapshots in the output)
    current_hops = {}
    
    for line in lines:
        # Skip header or empty lines
        if not line.strip() or line.startswith("Columns:") or line.startswith("#  ADDRESS"):
            continue
            
        # Parse the line using regex
        match = re.match(r'^\s*(\d+)\s+([^\s]+)\s+(\d+%)\s+(\d+)\s+([\d.]+ms|timeout)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)', line)
        
        if match:
            hop_num, address, loss, sent, last, avg, best, worst, stddev = match.groups()
            
            # Clean up the values
            loss = loss.replace('%', '')
            if last == "timeout":
                last_val = 999999  # Represent timeout with a very high value
            else:
                last_val = float(last.replace('ms', ''))
            
            # Create or update hop entry
            if hop_num not in current_hops:
                current_hops[hop_num] = {
                    "hop": int(hop_num),
                    "address": address,
                    "loss": float(loss),
                    "sent": int(sent),
                    "last": last_val,
                    "avg": float(avg),
                    "best": float(best),
                    "worst": float(worst),
                    "stddev": float(stddev),
                    "asn": ""  # Placeholder for AS number
                }
            else:
                # Update with the latest data
                hop = current_hops[hop_num]
                hop["loss"] = float(loss)
                hop["sent"] = int(sent)
                hop["last"] = last_val
                hop["avg"] = float(avg)
                hop["best"] = float(best)
                hop["worst"] = float(worst)
                hop["stddev"] = float(stddev)
    
    # Add all hops to the result
    for hop_num in sorted(current_hops.keys(), key=int):
        result["hops"].append(current_hops[hop_num])
    
    return result

# Main execution
try:
    # Run the traceroute command
    command = f"/tool/traceroute count={COUNT} address={DESTINATION}"
    output = ssh_execute(command)
    
    # Parse the output
    result = parse_traceroute(output)
    
    # Output the JSON result
    print(json.dumps(result))
    
except Exception as e:
    print(f"Error: {str(e)}", file=sys.stderr)
    sys.exit(1)
