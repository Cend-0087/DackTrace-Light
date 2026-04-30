#!/usr/bin/env python3
"""
Real-time packet capture module using Scapy
"""

import sys
import threading
import time
import subprocess
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, Raw

class RealPacketCapture:
    """Реальный захват сетевого трафика"""
    
    def __init__(self, packet_queue, log_callback=None):
        self.packet_queue = packet_queue
        self.log_callback = log_callback
        self.sniffing = False
        self.sniffer_thread = None
        self.packet_count = 0
        
    def log(self, message, level="INFO"):
        """Логирование с callback в GUI"""
        if self.log_callback:
            self.log_callback(f"[CAPTURE] {message}")
        print(f"[{level}] {message}")
    
    def packet_handler(self, pkt):
        """Обработчик одного пакета от scapy"""
        if not self.sniffing:
            return
        
        self.packet_count += 1
        
        # Извлекаем основные поля
        packet_info = {
            'timestamp': time.time(),
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'protocol': None,
            'length': len(pkt) if pkt else 0,
            'payload': '',
            'flags': None
        }
        
        # IP-слой
        if pkt.haslayer(IP):
            packet_info['src_ip'] = pkt[IP].src
            packet_info['dst_ip'] = pkt[IP].dst
            packet_info['protocol'] = pkt[IP].proto
            
            # TCP слой
            if pkt.haslayer(TCP):
                packet_info['src_port'] = pkt[TCP].sport
                packet_info['dst_port'] = pkt[TCP].dport
                packet_info['flags'] = pkt[TCP].flags
                
                # Payload (только для HTTP портов)
                if pkt.haslayer(Raw) and (pkt[TCP].dport in [80, 8080, 8000] or pkt[TCP].sport in [80, 8080, 8000]):
                    try:
                        payload = bytes(pkt[Raw]).decode('utf-8', errors='ignore')
                        # Ограничиваем размер для производительности
                        packet_info['payload'] = payload[:500]
                    except:
                        packet_info['payload'] = str(pkt[Raw])[:500]
            
            # UDP слой
            elif pkt.haslayer(UDP):
                packet_info['src_port'] = pkt[UDP].sport
                packet_info['dst_port'] = pkt[UDP].dport
                if pkt.haslayer(Raw):
                    packet_info['payload'] = str(pkt[Raw])[:200]
        
        # Отправляем в очередь для анализа
        if packet_info['src_ip']:  # Только если есть IP
            try:
                self.packet_queue.put(packet_info, timeout=0.1)
            except:
                pass  # Очередь переполнена - пропускаем
            
            # Логируем каждый 100-й пакет
            if self.packet_count % 100 == 0:
                self.log(f"Собрано {self.packet_count} пакетов. Последний: {packet_info['src_ip']} -> {packet_info['dst_ip']}")
    
    def start_capture(self, interface=None, filter_str=None):
        """Запуск захвата трафика в отдельном потоке"""
        if self.sniffing:
            self.log("Захват уже запущен")
            return False
        
        self.sniffing = True
        
        # Определяем интерфейс
        if not interface:
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'default via' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        interface = parts[4]
                        break
            if not interface:
                interface = 'eth0'
        
        # BPF фильтр
        if not filter_str:
            filter_str = "tcp or udp"
        
        self.log(f"Запуск захвата на интерфейсе {interface} с фильтром '{filter_str}'")
        
        # Запуск сниффинга в отдельном потоке
        def sniff_thread():
            self.log("Sniffer поток запущен")
            try:
                sniff(
                    iface=interface,
                    filter=filter_str,
                    prn=self.packet_handler,
                    store=False,
                    stop_filter=lambda x: not self.sniffing
                )
            except Exception as e:
                self.log(f"Ошибка сниффинга: {e}", "ERROR")
            finally:
                self.log("Sniffer поток остановлен")
        
        self.sniffer_thread = threading.Thread(target=sniff_thread, daemon=True)
        self.sniffer_thread.start()
        
        return True
    
    def stop_capture(self):
        """Остановка захвата"""
        self.log("Остановка захвата...")
        self.sniffing = False
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=3)
        self.log(f"Всего обработано пакетов: {self.packet_count}")
        return True
    
    def is_running(self):
        return self.sniffing