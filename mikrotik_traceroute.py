#!/usr/bin/env python3
import paramiko
import json
import re
import sys
import socket
import os
import warnings
import time
from collections import defaultdict

try:
    import routeros_api
    from routeros_api import exceptions
except ImportError:
    print("Error: The 'routeros_api' library is not installed. Please install it using 'pip install routeros-api'.", file=sys.stderr)
    sys.exit(1)

# Suppress the specific UserWarning about unknown host keys
warnings.filterwarnings("ignore", category=UserWarning, module="paramiko.client")

def ssh_execute(client, command, timeout=60):
    try:
        channel = client.get_transport().open_session()
        channel.settimeout(timeout)
        channel.set_combine_stderr(True)
        channel.exec_command(command)

        output = ""
        while True:
            if channel.exit_status_ready():
                break
            if channel.recv_ready():
                data = channel.recv(1024).decode('utf-8', errors='replace')
                output += data
            time.sleep(0.1)

        while channel.recv_ready():
            data = channel.recv(1024).decode('utf-8', errors='replace')
            output += data

        return output
    except Exception as e:
        print(f"Command execution error: {str(e)}", file=sys.stderr)
        return ""

def parse_traceroute(traceroute_output):
    lines = traceroute_output.strip().split('\n')
    result = {"hops": []}
    current_hops = {}
    for line in lines:
        if not line.strip() or line.startswith("Columns:") or line.startswith("#  ADDRESS"):
            continue
        match = re.match(r'^\s*(\d+)\s+([^\s]+)\s+(\d+%)\s+(\d+)\s+([\d.]+ms|timeout)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)', line)
        if match:
            hop_num, address, loss, sent, last, avg, best, worst, stddev = match.groups()
            loss = loss.replace('%', '')
            last_val = 999999 if last == "timeout" else float(last.replace('ms', ''))
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
                    "asn": ""
                }
    for hop_num in sorted(current_hops.keys(), key=int):
        result["hops"].append(current_hops[hop_num])
    return result

def api_traceroute(host, username, password, target_ip, count, api_port=8728):
    try:
        connection = routeros_api.RouterOsApiPool(
            host=host,
            username=username,
            password=password,
            port=api_port,
            plaintext_login=True,
            use_ssl=False
        )
        api = connection.get_api()
        
        # Use get_resource instead of get_binary_resource
        traceroute = api.get_resource('/tool').call('traceroute', {
            'address': target_ip,
            'count': str(count)
        })
        
        connection.disconnect()
        return traceroute
    except exceptions.RouterOsApiConnectionError as e:
        print(f"API Connection error: {e}", file=sys.stderr)
        return None
    except exceptions.RouterOsApiCommunicationError as e:
        print(f"API Communication error: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"API Error: {e}", file=sys.stderr)
        return None

def parse_api_traceroute(api_output):
    if api_output is None:
        return {"hops": []}
    
    # Group results by hop number
    hop_groups = defaultdict(list)
    for item in api_output:
        if '.section' in item:
            hop_num = int(item['.section'])
            hop_groups[hop_num].append(item)
    
    result = {"hops": []}
    
    for hop_num, items in sorted(hop_groups.items()):
        if not items:
            continue
            
        # Get the most complete item (usually the last one)
        item = items[-1]
        
        # Convert bytes to strings if needed
        def decode_value(v):
            return v.decode('utf-8') if isinstance(v, bytes) else str(v)
            
        address = decode_value(item.get('address', ''))
        loss = decode_value(item.get('loss', '100%')).replace('%', '')
        last = decode_value(item.get('last', 'timeout'))
        avg = decode_value(item.get('avg', '0'))
        best = decode_value(item.get('best', '0'))
        worst = decode_value(item.get('worst', '0'))
        stddev = decode_value(item.get('std-dev', '0'))
        sent = decode_value(item.get('sent', '1'))
        
        # Convert values to appropriate types
        try:
            loss_pct = float(loss)
        except ValueError:
            loss_pct = 100.0
            
        try:
            last_val = 999999 if last == 'timeout' else float(last)
        except ValueError:
            last_val = 999999
            
        try:
            avg_val = float(avg)
        except ValueError:
            avg_val = last_val if last_val != 999999 else 0
            
        try:
            best_val = float(best)
        except ValueError:
            best_val = avg_val
            
        try:
            worst_val = float(worst)
        except ValueError:
            worst_val = avg_val
            
        try:
            stddev_val = float(stddev)
        except ValueError:
            stddev_val = 0.0
            
        try:
            sent_val = int(sent)
        except ValueError:
            sent_val = 1
            
        result["hops"].append({
            "hop": hop_num,
            "address": address,
            "loss": loss_pct,
            "sent": sent_val,
            "last": last_val,
            "avg": avg_val,
            "best": best_val,
            "worst": worst_val,
            "stddev": stddev_val,
            "asn": ""
        })
    
    return result

def main():
    if len(sys.argv) < 5:
        print("Usage: {} <api|ssh> <mikrotik_ip> <username> <password> <target_ip> [probe_count=5] [api_port=8728] [ssh_port=22]".format(sys.argv[0]))
        print("Example (API): {} api 192.168.88.1 admin password 8.8.8.8 5 8728".format(sys.argv[0]))
        print("Example (SSH): {} ssh 192.168.88.1 admin password 8.8.8.8 5 22".format(sys.argv[0]))
        sys.exit(1)

    connection_method = sys.argv[1].lower()
    mikrotik_ip = sys.argv[2]
    username = sys.argv[3]
    password = sys.argv[4]
    target_ip = sys.argv[5]
    count = int(sys.argv[6]) if len(sys.argv) > 6 else 5
    
    # Default ports
    api_port = 8728
    ssh_port = 22
    
    # Get custom ports if provided
    if connection_method == 'api' and len(sys.argv) > 7:
        api_port = int(sys.argv[7])
    elif connection_method == 'ssh' and len(sys.argv) > 7:
        ssh_port = int(sys.argv[7])

    if connection_method == 'api':
        api_output = api_traceroute(mikrotik_ip, username, password, target_ip, count, api_port)
        if api_output is not None:
            result = parse_api_traceroute(api_output)
            print(json.dumps(result))
        else:
            print("Failed to get traceroute output via API", file=sys.stderr)
            sys.exit(1)
    elif connection_method == 'ssh':
        known_hosts_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'known_hosts')
        client = paramiko.SSHClient()
        client.load_system_host_keys()

        try:
            client.load_host_keys(known_hosts_path)
        except FileNotFoundError:
            open(known_hosts_path, 'a').close()
            client.load_host_keys(known_hosts_path)

        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            connection_timeout = 15 + (count * 2)
            command_timeout = 30 + (count * 5)
            
            transport_params = {
                'disabled_algorithms': {
                    'pubkeys': ['rsa-sha2-256', 'rsa-sha2-512']
                },
                'timeout': connection_timeout,
                'banner_timeout': connection_timeout
            }

            client.connect(
                mikrotik_ip,
                port=ssh_port,
                username=username,
                password=password,
                look_for_keys=False,
                allow_agent=False,
                **transport_params
            )

            client.save_host_keys(known_hosts_path)

            if client.get_transport() is not None:
                client.get_transport().set_keepalive(30)

            command = f"/tool/traceroute count={count} address={target_ip}"
            output = ssh_execute(client, command, timeout=command_timeout)

            if output:
                result = parse_traceroute(output)
                print(json.dumps(result))
            else:
                print("Failed to get traceroute output via SSH", file=sys.stderr)
                sys.exit(1)

        except paramiko.AuthenticationException:
            print("Authentication failed, please verify your credentials", file=sys.stderr)
            sys.exit(1)
        except paramiko.SSHException as e:
            print(f"SSH connection failed: {str(e)}", file=sys.stderr)
            sys.exit(1)
        except socket.timeout:
            print(f"Connection timed out. Consider increasing the timeout values for larger counts.", file=sys.stderr)
            sys.exit(1)
        except socket.error as e:
            print(f"Socket error: {str(e)}", file=sys.stderr)
            sys.exit(1)
        except (TimeoutError, paramiko.buffered_pipe.PipeTimeout) as e:
            print(f"Operation timed out: {str(e)}. Consider increasing the timeout values for larger counts.", file=sys.stderr)
            sys.exit(1)
        except KeyboardInterrupt:
            print("Operation aborted by user", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Unexpected error: {str(e)}", file=sys.stderr)
            sys.exit(1)
        finally:
            if client:
                client.close()
    else:
        print("Error: Invalid connection method. Use 'api' or 'ssh'.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
