import subprocess
import ipaddress
import socket
import concurrent.futures
import json
from datetime import datetime

def scan_port(ip, port, timeout=1):
    """Сканирование одного порта"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((str(ip), port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                return (ip, port, service, "OPEN")
    except:
        pass
    return None

def scan_network(network_cidr, ports, max_workers=50):
    """Сканирование сети"""
    results = {}
    network = ipaddress.ip_network(network_cidr, strict=False)
    
    print(f"[*] Scanning {network_cidr} ({network.num_addresses} hosts)")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for ip in network.hosts():
            for port in ports:
                futures.append(executor.submit(scan_port, ip, port))
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                ip, port, service, status = result
                if str(ip) not in results:
                    results[str(ip)] = []
                results[str(ip)].append({"port": port, "service": service, "status": status})
    
    return results

def check_smb_shares(ip):
    """Проверка SMB шаров (нужен nmblookup или smbclient)"""
    try:
        # Проверка NetBIOS
        result = subprocess.run(['nmblookup', '-A', str(ip)], 
                              capture_output=True, text=True, timeout=5)
        if '<00>' in result.stdout or '<20>' in result.stdout:
            return True
    except:
        pass
    return False

def main():
    # Целевые порты
    common_ports = [21, 22, 23, 80, 443, 445, 139, 135, 3389, 5900, 8080, 8443]
    printer_ports = [9100, 515, 631, 9220, 9290, 9091]  # Kyocera 9091
    database_ports = [1433, 1521, 3306, 5432, 27017]
    
    target_ports = common_ports + printer_ports + database_ports
    
    # Сети для сканирования (возьмем из локальных интерфейсов)
    networks_to_scan = []
    
    try:
        # Получаем локальные сети
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'src' in line and not 'default' in line:
                parts = line.split()
                if len(parts) > 0:
                    networks_to_scan.append(parts[0])
    except:
        # Дефолтные сети
        networks_to_scan = ['192.168.0.0/24', '10.0.0.0/24', '172.16.0.0/24']
    
    all_results = {}
    
    for network in networks_to_scan[:3]:  # Ограничим 3 сетями
        print(f"\n[+] Scanning network: {network}")
        results = scan_network(network, target_ports)
        
        # Проверка SMB для хостов с открытым 445
        for ip in list(results.keys()):
            for service in results[ip]:
                if service['port'] == 445:
                    print(f"  Checking SMB shares on {ip}...")
                    if check_smb_shares(ip):
                        print(f"    [!] SMB shares found on {ip}")
                        if 'smb' not in results[ip]:
                            results[ip].append({"port": 445, "service": "microsoft-ds", "status": "SMB_SHARES"})
        
        all_results[network] = results
    
    # Вывод результатов
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    
    for network, hosts in all_results.items():
        if hosts:
            print(f"\nNetwork: {network}")
            for ip, services in hosts.items():
                print(f"  {ip}:")
                for service in services:
                    print(f"    Port {service['port']} ({service['service']}): {service['status']}")
    
    # Сохранение в файл
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"/tmp/network_scan_{timestamp}.json"
    with open(filename, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"\n[+] Results saved to {filename}")

if __name__ == "__main__":
    main()
