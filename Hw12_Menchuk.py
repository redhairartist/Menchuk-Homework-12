from scapy.all import rdpcap
from scapy.layers.inet import IP
from scapy.layers.dns import DNS, DNSQR
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

def main():
    # Укажите путь к файлу дампа
    file_path = r'C:\Users\idmit\pep\Homework_12\dhcp.pcapng'

    # Чтение дампа
    packets = rdpcap(file_path)

    dns_queries = []
    ip_addresses = []

    for packet in packets:
        # Извлечение IP-адресов
        if packet.haslayer(IP):
            ip_addresses.append(packet[IP].src)
            ip_addresses.append(packet[IP].dst)

        # Извлечение DNS-запросов
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns_queries.append(packet[DNSQR].qname.decode('utf-8'))

    # Уникальные DNS-запросы и IP-адреса
    unique_dns = set(dns_queries)
    unique_ips = set(ip_addresses)

    # Визуализация: количество уникальных DNS-запросов
    if dns_queries:
        dns_counts = pd.Series(dns_queries).value_counts()
        if not dns_counts.empty:
            plt.figure(figsize=(10, 6))
            sns.countplot(y=dns_counts.index[:10], order=dns_counts.index[:10])
            plt.title('Топ 10 DNS-запросов')
            plt.show()

    # Сохранение результатов в CSV
    if unique_dns:
        pd.DataFrame({'DNS-запросы': list(unique_dns)}).to_csv('dns_queries.csv', index=False)
    if unique_ips:
        pd.DataFrame({'IP-адреса': list(unique_ips)}).to_csv('ip_addresses.csv', index=False)

if __name__ == "__main__":
    main()
