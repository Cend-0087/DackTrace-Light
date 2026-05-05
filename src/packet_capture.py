#!/usr/bin/env python3
"""
Real-time packet capture module using Scapy
Захватывает весь трафик (входящий и исходящий) для анализа
"""

import sys
import threading
import time
import subprocess
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, Raw

class RealPacketCapture:
    """Реальный захват сетевого трафика (весь трафик)"""
    
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
    
    def extract_http_payload(self, raw_data):
        """
        Извлечение HTTP payload из сырых данных
        Возвращает строку с методом, URI и телом запроса
        """
        try:
            # Пытаемся декодировать как UTF-8
            payload = raw_data.decode('utf-8', errors='ignore')
            
            # Для HTTP запросов: ищем GET/POST/PUT/DELETE
            http_methods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ']
            for method in http_methods:
                if payload.startswith(method):
                    # Находим конец первой строки (до \r\n)
                    end_of_line = payload.find('\r\n')
                    if end_of_line > 0:
                        request_line = payload[:end_of_line]
                        # Также захватываем тело, если есть
                        body_start = payload.find('\r\n\r\n')
                        if body_start > 0:
                            body = payload[body_start+4:min(body_start+500, len(payload))]
                            return f"{request_line}\n{body}"
                        return request_line
                    
            # Для HTTP ответов: ищем статус код
            if payload.startswith('HTTP/'):
                end_of_line = payload.find('\r\n')
                if end_of_line > 0:
                    return payload[:end_of_line]
            
            # Если не HTTP, возвращаем первые 200 символов
            return payload[:200]
        except:
            return str(raw_data)[:200]
    
    def packet_handler(self, pkt):
        """Обработчик одного пакета от scapy (анализирует весь трафик)"""
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
            'flags': None,
            'direction': None  # 'in' или 'out' для определения направления
        }
        
        # IP-слой
        if pkt.haslayer(IP):
            packet_info['src_ip'] = pkt[IP].src
            packet_info['dst_ip'] = pkt[IP].dst
            packet_info['protocol'] = pkt[IP].proto
            
            # Определяем направление (локальный IP vs внешний)
            # Это нужно для правильного анализа атак
            src_ip = packet_info['src_ip']
            dst_ip = packet_info['dst_ip']
            
            # Проверяем, является ли IP локальным
            is_local = lambda ip: ip.startswith(('10.', '192.168.', '172.', '127.'))
            
            if is_local(src_ip) and not is_local(dst_ip):
                packet_info['direction'] = 'outgoing'  # Исходящий запрос (атака с твоего IP)
            elif not is_local(src_ip) and is_local(dst_ip):
                packet_info['direction'] = 'incoming'  # Входящий ответ
            else:
                packet_info['direction'] = 'unknown'
            
            # TCP слой
            if pkt.haslayer(TCP):
                packet_info['src_port'] = pkt[TCP].sport
                packet_info['dst_port'] = pkt[TCP].dport
                packet_info['flags'] = pkt[TCP].flags
                
                # Извлекаем payload из любого TCP пакета (не только HTTP)
                if pkt.haslayer(Raw):
                    try:
                        raw_bytes = bytes(pkt[Raw])
                        if raw_bytes:
                            # Извлекаем HTTP-подобный payload
                            packet_info['payload'] = self.extract_http_payload(raw_bytes)
                    except Exception as e:
                        packet_info['payload'] = f"[ERROR: {e}]"
            
            # UDP слой
            elif pkt.haslayer(UDP):
                packet_info['src_port'] = pkt[UDP].sport
                packet_info['dst_port'] = pkt[UDP].dport
                if pkt.haslayer(Raw):
                    try:
                        raw_bytes = bytes(pkt[Raw])
                        packet_info['payload'] = raw_bytes[:200].decode('utf-8', errors='ignore')
                    except:
                        packet_info['payload'] = str(pkt[Raw])[:200]
        
        # Отправляем в очередь для анализа, если есть IP и есть данные для анализа
        if packet_info['src_ip'] and packet_info['payload']:
            try:
                self.packet_queue.put(packet_info, timeout=0.1)
            except:
                pass  # Очередь переполнена - пропускаем
            
            # Логируем каждый 100-й пакет (только важные)
            if self.packet_count % 100 == 0:
                direction = packet_info['direction']
                if direction == 'outgoing':
                    self.log(f"Собрано {self.packet_count} пакетов. Исходящий: {packet_info['src_ip']}:{packet_info['src_port']} -> {packet_info['dst_ip']}:{packet_info['dst_port']}")
                else:
                    self.log(f"Собрано {self.packet_count} пакетов. Входящий: {packet_info['src_ip']}:{packet_info['src_port']} -> {packet_info['dst_ip']}:{packet_info['dst_port']}")
    
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
        
        # BPF фильтр для захвата TCP трафика на всех портах
        # Убираем ограничение по портам, чтобы видеть весь трафик
        if not filter_str:
            filter_str = "tcp"  # Захватываем весь TCP трафик для анализа атак
        
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