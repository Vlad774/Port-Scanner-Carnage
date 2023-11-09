import socket
import termcolor
from multiprocessing import Pool
from datetime import datetime
import subprocess

def print_c_a_r():
    red_color = "\033[91m"  # ASCII escape code for red color
    reset_color = "\033[0m"  # Reset color to default
    print(f"""{red_color}
     ███████╗     █████╗    ██████     ██║█║  ██║     █████╗      █████╗   ███████╗
     ██╔════╝    ██╔══██╗   ██╔══██    ██║ █║ ██║    ██╔══██╗   ██╔══ ██╗  ██╔════╝
     ██║        ███████║    ██████╗    ██║  █║██║   ███████║    ██║ ══     ███████╗
     ██║        ██╔══██║   ╚██═══██║   ██║   ║██║   ██╔══██║    ██║   ██╗  ██║
     ███████╗    ██║  ██║   ██   ██║   ██║    ██║    ██║  ██║    ╚█████    ███████╗ 
{reset_color}
    Version 2.01                                         created by Vlad Vesninskiy
    """)
print_c_a_r()

def get_mac_address(ip_address):
    try:
        return f"MAC Address: {':'.join(['{:02x}'.format((int(x, 16) & 0xff)) for x in hex(get_mac_from_ip(ip_address))[2:].split('0x')])}"
    except:
        return "MAC Address: Unknown"

def get_mac_from_ip(ip_address):
    import subprocess
    output = subprocess.check_output(['arp', '-n', ip_address])
    mac_address = output.decode().split()[3]
    return mac_address

def scan(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            service_name = socket.getservbyport(port, 'tcp')
            return termcolor.colored(f"{str(port)}/tcp".ljust(9) + "open".ljust(7) + service_name, 'green')
        else:
            return None
    except Exception as e:
        return termcolor.colored(f"Error on port {port}: {e}", 'red')

def multi_process_scan(target, ports, processes):
    with Pool(processes=processes) as pool:
        results = []
        for port in range(1, ports + 1):
            results.append(pool.apply_async(scan, (target, port)))

        open_ports = []
        for idx, result in enumerate(results, start=1):
            open_port = result.get()
            if open_port is not None:
                open_ports.append(open_port)

            progress = int((idx / ports) * 100)
            progress_bar_length = 50
            progress_filled_part = int(progress / 2)
            progress_bar = '█' * progress_filled_part + '-' * (progress_bar_length - progress_filled_part)
            print(f"\r|{progress_bar}| {progress}%", end="")
    return open_ports

def scan_ports(target, ports, processes=10):
    print('\n' + termcolor.colored(f"Starting Carnage Scanner at {datetime.now().strftime('%Y-%m-%d %H:%M %Z')}", 'cyan'))
    print(f"Carnage scan report for {target}\n")

    start_time = datetime.now()
    open_ports = multi_process_scan(target, ports, processes)
    end_time = datetime.now()
    elapsed_time = end_time - start_time

    print("PORT     STATE  SERVICE")
    if open_ports:
        print("{:<9}{:<7}{}".format("PORT", "STATE", "SERVICE"))
        print("---------------------------------------")
        print('\n'.join(open_ports))
    else:
        print("No open ports found.")

    print(get_mac_address(target))
    print(f"\nScanning elapsed time: {elapsed_time}")

if __name__ == "__main__":
    try:
        target = input("[*] Enter Target IP: ")
        ports = int(input("[*] Enter How Many Ports You Want To Scan: "))
        processes = int(input("[*] Enter number of processes for scanning: "))
        scan_ports(target, ports, processes)
    except KeyboardInterrupt:
        print("\nScan interrupted. Stopping.")
    finally:
        print(termcolor.colored("\nCarnage v2.01", 'red'))
