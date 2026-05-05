#!/usr/bin/env python3
"""
Whitelist Manager for DarkTrace Light
Управление белым списком IP и сетей
"""

import json
import threading
import os
from pathlib import Path

class WhitelistManager:
    """Управление белым списком IP и сетей"""
    
    def __init__(self, whitelist_file="config/whitelist.json"):
        # Определяем путь к файлу относительно текущего файла
        self.whitelist_file = Path(__file__).parent.parent / whitelist_file
        self.whitelist_file.parent.mkdir(parents=True, exist_ok=True)
        self.whitelist_ips = set()
        self.whitelist_networks = set()
        self.lock = threading.Lock()
        print(f"[WHITELIST] Файл: {self.whitelist_file}")
        self.load()
    
    def load(self):
        """Загрузка белого списка из файла"""
        with self.lock:
            self.whitelist_ips = set()
            self.whitelist_networks = set()
            
            if self.whitelist_file.exists():
                try:
                    with open(self.whitelist_file, 'r') as f:
                        data = json.load(f)
                        self.whitelist_ips = set(data.get('ips', []))
                        self.whitelist_networks = set(data.get('networks', []))
                    print(f"[WHITELIST] Загружено {len(self.whitelist_ips)} IP и {len(self.whitelist_networks)} сетей")
                except Exception as e:
                    print(f"[WHITELIST] Ошибка загрузки: {e}")
            
            # Добавляем стандартные сети, если список пустой
            if not self.whitelist_ips and not self.whitelist_networks:
                self.init_defaults()
                self.save()
                print(f"[WHITELIST] Инициализированы настройки по умолчанию")
    
    def init_defaults(self):
        """Инициализация белого списка по умолчанию"""
        # Точные IP
        self.whitelist_ips = {
            '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1',
        }
        
        # Префиксы сетей (CDN, облачные провайдеры)
        self.whitelist_networks = {
            # Google
            '74.125.', '173.194.', '172.217.', '64.233.', '142.251.',
            '108.177.', '34.160.', '34.107.', '34.49.', '209.85.',
            # Akamai
            '151.101.', '150.171.', '23.35.', '20.44.', '104.103.',
            # Cloudflare
            '104.16.', '172.64.', '162.159.',
            # Microsoft Azure
            '20.42.', '20.189.', '51.116.', '51.11.', '52.182.',
            '13.107.', '13.33.',
            # AWS
            '16.59.', '54.37.', '52.94.',
            # Telia
            '62.115.', '80.239.',
            # Level 3
            '8.6.', '8.7.',
            # Fastly
            '151.101.',
        }
    
    def save(self):
        """Сохранение белого списка в файл"""
        with self.lock:
            try:
                with open(self.whitelist_file, 'w') as f:
                    json.dump({
                        'ips': list(self.whitelist_ips),
                        'networks': list(self.whitelist_networks)
                    }, f, indent=2)
                print(f"[WHITELIST] Сохранено {len(self.whitelist_ips)} IP и {len(self.whitelist_networks)} сетей")
                return True
            except Exception as e:
                print(f"[WHITELIST] Ошибка сохранения: {e}")
                return False
    
    def is_whitelisted(self, ip):
        """Проверка, входит ли IP в белый список"""
        if not ip:
            return False
        
        with self.lock:
            if ip in self.whitelist_ips:
                return True
            
            for network in self.whitelist_networks:
                if ip.startswith(network):
                    return True
        
        return False
    
    def add_ip(self, ip):
        """Добавление IP в белый список"""
        with self.lock:
            self.whitelist_ips.add(ip)
        return self.save()
    
    def remove_ip(self, ip):
        """Удаление IP из белого списка"""
        with self.lock:
            if ip in self.whitelist_ips:
                self.whitelist_ips.remove(ip)
                return self.save()
        return False
    
    def add_network(self, network):
        """Добавление префикса сети в белый список"""
        if not network.endswith('.'):
            network = network + '.'
        with self.lock:
            self.whitelist_networks.add(network)
        return self.save()
    
    def remove_network(self, network):
        """Удаление префикса сети из белого списка"""
        if not network.endswith('.'):
            network = network + '.'
        with self.lock:
            if network in self.whitelist_networks:
                self.whitelist_networks.remove(network)
                return self.save()
        return False
    
    def get_all(self):
        """Получить весь белый список"""
        with self.lock:
            return {
                'ips': list(self.whitelist_ips),
                'networks': list(self.whitelist_networks)
            }