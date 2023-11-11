import psutil
import speedtest
import time
import socket
from scapy.all import ARP, Ether, srp

def monitorizar():
    while True:
        # Obtener el uso de la CPU y la memoria
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()

        # Obtener estadísticas de ancho de banda de red
        network_stats = psutil.net_io_counters()

        # Obtener una lista de conexiones de red activas
        conexiones_activas = psutil.net_connections(kind='inet')

        # Mostrar información
        print(f"Uso de CPU: {cpu_percent}%")
        print(f"Uso de memoria: {memory.percent}%")
        print(f"Bytes enviados: {network_stats.bytes_sent}")
        print(f"Bytes recibidos: {network_stats.bytes_recv}")
        
        # Mostrar información
        print("\nConexiones de red activas:")
        for conn in conexiones_activas:
            print(f"Estado: {conn.status}, Local: {conn.laddr}, Remoto: {conn.raddr}")

        time.sleep(10)

def medir_rendimiento_red():
    st = speedtest.Speedtest()
    while True:
        st.get_best_server()
        download_speed = st.download() / 1_000_000  # en Mbps
        upload_speed = st.upload() / 1_000_000  # en Mbps

        print(f"Velocidad de descarga: {download_speed} Mbps")
        print(f"Velocidad de carga: {upload_speed} Mbps")

        time.sleep(10)


def estadisticas_dns():
    resoluciones_exitosas = 0
    resoluciones_fallidas = 0

    while True:
        host_a_resolver = "google.com"  # Cambia a un dominio que desees resolver
        try:
            socket.gethostbyname(host_a_resolver)
            resoluciones_exitosas += 1
        except socket.gaierror:
            resoluciones_fallidas += 1

        print(f"Resoluciones exitosas: {resoluciones_exitosas}, Resoluciones fallidas: {resoluciones_fallidas}")

        time.sleep(10)


def escanear_red(ip_range):
    # Crear una trama Ethernet para el escaneo ARP
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Crear un paquete ARP para solicitar las direcciones IP en la red
    arp = ARP(pdst=ip_range)

    # Combinar la trama Ethernet y el paquete ARP
    packet = ether/arp

    # Realizar el escaneo y obtener una lista de respuestas
    result = srp(packet, timeout=3, verbose=0)[0]

    # Recopilar las direcciones IP de los dispositivos activos
    connected_devices = []
    for sent, received in result:
        connected_devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return connected_devices



if __name__ == "__main__":
    # monitorizar()
    
    #medir_rendimiento_red()
    
    #estadisticas_dns()
    
    ip_range = "192.168.18.5/24"  # Cambia a la subred de tu red local
    dispositivos_conectados = escanear_red(ip_range)

    print("Dispositivos conectados a la red:")
    for device in dispositivos_conectados:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")

