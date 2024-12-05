import socket
import psutil

def get_internet_interface_info():
    """
    Ottieni l'indirizzo IP e il MAC address dell'interfaccia che connette a Internet.
    """
    try:
        # Ottieni l'indirizzo IP locale dell'interfaccia connessa a Internet
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))  # Usa il DNS di Google per determinare l'interfaccia
            ip_address = s.getsockname()[0]

        # Trova l'interfaccia corrispondente all'indirizzo IP
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == ip_address:
                    # Trova il MAC address corrispondente
                    mac_address = next(
                        (a.address for a in addrs if a.family == psutil.AF_LINK), None
                    )
                    return {"interface": interface, "ip": ip_address, "mac": mac_address}

    except Exception as e:
        print(f"Errore: {e}")
        return None

# Recupera l'indirizzo IP e il MAC address
interface_info = get_internet_interface_info()

if interface_info:
    print(f"Interfaccia: {interface_info['interface']}")
    print(f"IP Address: {interface_info['ip']}")
    print(f"MAC Address: {interface_info['mac']}")
else:
    print("Impossibile recuperare le informazioni dell'interfaccia.")