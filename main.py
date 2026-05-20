#!/usr/bin/env python3
"""
DarkTrace Light - Network Anomaly Detection System
Main entry point with GUI and multithreading
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
import time
import os
import sys
import json
import subprocess
import socket
import re
from datetime import datetime
import logging
from pathlib import Path
from collections import defaultdict

# Настройка путей
BASE_DIR = Path(__file__).parent
LOG_DIR = BASE_DIR / "logs"
DB_DIR = BASE_DIR / "database"
CONFIG_DIR = BASE_DIR / "config"

LOG_DIR.mkdir(exist_ok=True)
DB_DIR.mkdir(exist_ok=True)
CONFIG_DIR.mkdir(exist_ok=True)

# Добавляем src в путь для импорта модулей
sys.path.insert(0, str(BASE_DIR / "src"))

print("[DEBUG] Инициализация модулей...")

# Попытка импорта реального захвата
REAL_CAPTURE_AVAILABLE = False
try:
    from packet_capture import RealPacketCapture
    REAL_CAPTURE_AVAILABLE = True
    print("[OK] RealPacketCapture модуль загружен")
except ImportError as e:
    print(f"[WARN] RealPacketCapture не найден: {e}")

# Белый список - ВКЛЮЧЁН
WHITELIST_FILE = CONFIG_DIR / "whitelist.json"
BLACKLIST_FILE = CONFIG_DIR / "blacklist.json"

print("[DEBUG] Модули загружены, настройка логирования...")

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "darktrace.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

print("[DEBUG] Логирование настроено, импорт sqlite3...")


# ============================================================
# КЛАСС БЕЛОГО СПИСКА
# ============================================================

class WhitelistManager:
    def __init__(self, whitelist_file=WHITELIST_FILE):
        self.whitelist_file = whitelist_file
        self.ips = set()
        self.networks = set()
        self.load()
    
    def load(self):
        if self.whitelist_file.exists():
            try:
                with open(self.whitelist_file, 'r') as f:
                    data = json.load(f)
                    self.ips = set(data.get('ips', []))
                    self.networks = set(data.get('networks', []))
                print(f"[WHITELIST] Загружено {len(self.ips)} IP и {len(self.networks)} сетей")
                return
            except:
                pass
        
        # Значения по умолчанию
        self.ips = {'8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1'}
        self.networks = {
            '74.125.', '173.194.', '172.217.', '64.233.', '142.251.',
            '108.177.', '34.160.', '34.107.', '151.101.', '150.171.',
        }
        self.save()
    
    def save(self):
        try:
            with open(self.whitelist_file, 'w') as f:
                json.dump({'ips': list(self.ips), 'networks': list(self.networks)}, f, indent=2)
            return True
        except:
            return False
    
    def is_whitelisted(self, ip):
        if not ip:
            return False
        if ip in self.ips:
            return True
        for net in self.networks:
            if ip.startswith(net):
                return True
        return False
    
    def add_ip(self, ip):
        self.ips.add(ip)
        return self.save()
    
    def remove_ip(self, ip):
        if ip in self.ips:
            self.ips.remove(ip)
            return self.save()
        return False
    
    def add_network(self, net):
        if not net.endswith('.'):
            net = net + '.'
        self.networks.add(net)
        return self.save()
    
    def remove_network(self, net):
        if not net.endswith('.'):
            net = net + '.'
        if net in self.networks:
            self.networks.remove(net)
            return self.save()
        return False
    
    def get_all(self):
        return {'ips': list(self.ips), 'networks': list(self.networks)}


# ============================================================
# КЛАСС ЧЁРНОГО СПИСКА
# ============================================================

class BlacklistManager:
    def __init__(self, blacklist_file=BLACKLIST_FILE):
        self.blacklist_file = blacklist_file
        self.ips = {}
        self.load()
    
    def load(self):
        if self.blacklist_file.exists():
            try:
                with open(self.blacklist_file, 'r') as f:
                    data = json.load(f)
                    self.ips = data.get('ips', {})
                print(f"[BLACKLIST] Загружено {len(self.ips)} заблокированных IP")
                return
            except:
                pass
        self.save()
    
    def save(self):
        try:
            with open(self.blacklist_file, 'w') as f:
                json.dump({'ips': self.ips}, f, indent=2)
            return True
        except:
            return False
    
    def is_blocked(self, ip):
        return ip in self.ips
    
    def add(self, ip, reason):
        if ip in self.ips:
            return
        self.ips[ip] = {'reason': reason, 'blocked_at': datetime.now().isoformat()}
        self.save()
        try:
            subprocess.run(f"iptables -I INPUT 1 -s {ip} -j DROP", shell=True, stderr=subprocess.DEVNULL)
            subprocess.run(f"iptables -I OUTPUT 1 -d {ip} -j DROP", shell=True, stderr=subprocess.DEVNULL)
            print(f"[FW] IP {ip} заблокирован в iptables (вход/выход)")
        except Exception as e:
            print(f"[FW] Ошибка блокировки: {e}")
    
    def remove(self, ip):
        if ip in self.ips:
            del self.ips[ip]
            self.save()
            try:
                subprocess.run(f"iptables -D INPUT -s {ip} -j DROP", shell=True, stderr=subprocess.DEVNULL)
                subprocess.run(f"iptables -D OUTPUT -d {ip} -j DROP", shell=True, stderr=subprocess.DEVNULL)
                print(f"[FW] IP {ip} разблокирован в iptables")
            except:
                pass
            return True
        return False
    
    def get_all(self):
        return self.ips


class Database:
    """Работа с SQLite базой данных"""
    
    def __init__(self, db_path="database/darktrace.db"):
        print(f"[DEBUG] Инициализация БД: {db_path}")
        self.db_path = Path(__file__).parent / db_path
        self.db_path.parent.mkdir(exist_ok=True)
        self.init_tables()
        print(f"[DB] База данных: {self.db_path}")
    
    def init_tables(self):
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    length INTEGER,
                    payload TEXT,
                    direction TEXT
                );
                
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT,
                    dst_ip TEXT,
                    attack_type TEXT,
                    anomaly_score REAL,
                    blocked INTEGER DEFAULT 0,
                    packet_id INTEGER,
                    details TEXT
                );
                
                CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_packets_time ON packets(timestamp);
                CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(src_ip);
            ''')
    
    def log_packet(self, packet):
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute('''
                INSERT INTO packets (src_ip, dst_ip, src_port, dst_port, protocol, length, payload, direction)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                RETURNING id
            ''', (
                packet.get('src_ip'), packet.get('dst_ip'),
                packet.get('src_port'), packet.get('dst_port'),
                str(packet.get('protocol', '')),
                packet.get('length', 0),
                packet.get('payload', '')[:1000],
                packet.get('direction', 'unknown')
            ))
            return cur.fetchone()[0]
    
    def log_alert(self, src_ip, dst_ip, attack_type, score, packet_id=None, blocked=0, details=None):
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO alerts (src_ip, dst_ip, attack_type, anomaly_score, packet_id, blocked, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (src_ip, dst_ip, attack_type, score, packet_id, blocked, json.dumps(details) if details else None))
    
    def get_stats(self):
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute('''
                SELECT 
                    (SELECT COUNT(*) FROM packets) as total_packets,
                    (SELECT COUNT(*) FROM alerts) as total_alerts,
                    (SELECT COUNT(*) FROM alerts WHERE blocked=1) as blocked_count
            ''')
            return cur.fetchone()
    
    def get_suspicious_ips_grouped(self):
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute('''
                SELECT src_ip, attack_type, MAX(anomaly_score) as max_score, 
                       COUNT(*) as attack_count, MAX(timestamp) as last_seen,
                       GROUP_CONCAT(DISTINCT attack_type) as attack_types
                FROM alerts 
                WHERE timestamp > datetime('now', '-24 hours')
                GROUP BY src_ip
                ORDER BY max_score DESC
            ''')
            return [{'ip': r[0], 'type': r[1], 'score': r[2], 'count': r[3], 
                     'last_seen': r[4], 'types': r[5]} for r in cur.fetchall()]
    
    def get_alerts_by_ip(self, ip, limit=100):
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute('''
                SELECT timestamp, attack_type, anomaly_score, blocked, details, packet_id, dst_ip
                FROM alerts WHERE src_ip = ? ORDER BY timestamp DESC LIMIT ?
            ''', (ip, limit))
            return cur.fetchall()
    
    def get_packet_by_id(self, packet_id):
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute('SELECT src_ip, dst_ip, src_port, dst_port, protocol, length, payload FROM packets WHERE id = ?', (packet_id,))
            return cur.fetchone()


print("[DEBUG] Класс Database определён, создание основного класса DarkTraceLight...")

import sqlite3


# ============================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ IP ИНФОРМАЦИИ
# ============================================================

def get_ip_info(ip):
    """Получение информации об IP без использования внешних API"""
    info = {
        'is_private': False,
        'is_local': False,
        'isp': 'Unknown',
        'country': 'Unknown',
        'rdns': None,
        'is_suspicious': False,
        'suspicious_reason': []
    }
    
    # Проверка на приватные IP
    private_ranges = [
        ('10.', 'Private'), ('192.168.', 'Private'),
        ('172.16.', 'Private'), ('172.17.', 'Private'), ('172.18.', 'Private'),
        ('172.19.', 'Private'), ('172.20.', 'Private'), ('172.21.', 'Private'),
        ('172.22.', 'Private'), ('172.23.', 'Private'), ('172.24.', 'Private'),
        ('172.25.', 'Private'), ('172.26.', 'Private'), ('172.27.', 'Private'),
        ('172.28.', 'Private'), ('172.29.', 'Private'), ('172.30.', 'Private'),
        ('172.31.', 'Private'), ('127.', 'Loopback'), ('0.', 'Invalid'),
        ('224.', 'Multicast'), ('240.', 'Reserved'), ('255.255.255.255', 'Broadcast'),
    ]
    
    for prefix, desc in private_ranges:
        if ip.startswith(prefix) or ip == '255.255.255.255':
            info['is_private'] = True
            info['is_local'] = True
            info['isp'] = desc
            return info
    
    # Попытка обратного DNS запроса
    try:
        info['rdns'] = socket.gethostbyaddr(ip)[0]
    except:
        pass
    
    # Определение ISP
    known_ips = {
        '8.8.8.8': 'Google (Public DNS)', '8.8.4.4': 'Google (Public DNS)',
        '1.1.1.1': 'Cloudflare (Public DNS)', '1.0.0.1': 'Cloudflare (Public DNS)',
        '9.9.9.9': 'Quad9 (Public DNS)', '208.67.222.222': 'OpenDNS',
        '208.67.220.220': 'OpenDNS',
    }
    
    for known_ip, name in known_ips.items():
        if ip == known_ip or ip.startswith(known_ip.rstrip('.')):
            info['isp'] = name
            return info
    
    if ip.startswith('151.101.'):
        info['isp'] = 'Fastly (CDN)'
    elif ip.startswith('74.125.') or ip.startswith('173.194.') or ip.startswith('172.217.'):
        info['isp'] = 'Google (CDN)'
    elif ip.startswith('104.16.') or ip.startswith('172.64.'):
        info['isp'] = 'Cloudflare (CDN)'
    elif ip.startswith('20.'):
        info['isp'] = 'Microsoft / Azure'
    elif ip.startswith('34.'):
        info['isp'] = 'Google Cloud / Oracle Cloud'
    elif ip.startswith('52.'):
        info['isp'] = 'Amazon AWS / Microsoft'
    elif ip.startswith('13.'):
        info['isp'] = 'Amazon AWS / Microsoft'
    else:
        info['isp'] = 'Unknown'
        info['is_suspicious'] = True
        info['suspicious_reason'].append('Неизвестный провайдер')
    
    return info


# ============================================================
# ГЛАВНЫЙ КЛАСС ПРИЛОЖЕНИЯ
# ============================================================

class DarkTraceLight:
    """Главный класс приложения"""
    
    def __init__(self, root):
        print("[DEBUG] DarkTraceLight.__init__ начат")
        self.root = root
        self.root.title("DarkTrace Light - Network Anomaly Detection")
        self.root.geometry("1300x750")
        self.root.configure(bg='#1e1e1e')
        
        print("[DEBUG] Инициализация БД...")
        self.db = Database()
        
        print("[DEBUG] Инициализация белого списка...")
        self.whitelist = WhitelistManager()
        
        print("[DEBUG] Инициализация чёрного списка...")
        self.blacklist = BlacklistManager()
        
        print("[DEBUG] Настройка стилей...")
        self.setup_styles()
        
        print("[DEBUG] Инициализация очередей...")
        self.packet_queue = queue.Queue(maxsize=1000)
        
        print("[DEBUG] Инициализация флагов...")
        self.monitoring = False
        self.capture_thread = None
        self.analysis_thread = None
        self.capture = None
        self.anomaly_detector = None
        
        # Флаги для обновления таблиц
        self._refresh_alerts_needed = False
        self._refresh_whitelist_needed = False
        self._refresh_blacklist_needed = False
        self._alerts_data = None
        self._whitelist_data = None
        self._blacklist_data = None
        
        print("[DEBUG] Создание GUI...")
        self.setup_gui()
        
        print("[DEBUG] Запуск обновления интерфейса...")
        self.update_gui()
        
        print("[DEBUG] Проверка прав...")
        self.check_permissions()
        
        print("[DEBUG] Загрузка ML модели...")
        self.init_ml_model()
        
        print("[DEBUG] DarkTrace Light инициализирован")
        logger.info("DarkTrace Light инициализирован")
    
    def init_ml_model(self):
        """Инициализация ML модели"""
        try:
            from anomaly_detector import AnomalyDetector
            self.anomaly_detector = AnomalyDetector(contamination=0.01)
            if self.anomaly_detector.load_model():
                self.log_message("[ML] Модель загружена. Режим детектирования.", "green")
            else:
                self.log_message("[ML] Модель не найдена. Будет собран baseline для обучения.", "yellow")
        except Exception as e:
            self.log_message(f"[ML] Ошибка инициализации: {e}", "red")
            self.anomaly_detector = None
    
    def setup_styles(self):
        """Настройка стилей для тёмной темы"""
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('TFrame', background='#1e1e1e')
        style.configure('TLabel', background='#1e1e1e', foreground='#ffffff')
        style.configure('TButton', background='#0e639c', foreground='#ffffff')
        style.map('TButton', background=[('active', '#1177bb')])
        style.configure('TNotebook', background='#1e1e1e')
        style.configure('TNotebook.Tab', background='#2d2d2d', foreground='#ffffff')
        style.configure('Treeview', background='#2d2d2d', foreground='#ffffff', fieldbackground='#2d2d2d')
        style.configure('Treeview.Heading', background='#3c3c3c', foreground='#ffffff')
    
    def setup_gui(self):
        """Создание графического интерфейса"""
        print("[DEBUG] setup_gui начат")
        
        # Основной контейнер
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Верхняя панель
        control_frame = ttk.Frame(main_container)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        print("[DEBUG] Создание кнопок управления...")
        
        self.start_btn = ttk.Button(control_frame, text="▶ Start Monitoring", command=self.start_monitoring)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="⏹ Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Выбор режима ML
        mode_frame = ttk.LabelFrame(control_frame, text="ML Mode", padding=5)
        mode_frame.pack(side=tk.LEFT, padx=20)
        
        self.ml_mode_var = tk.StringVar(value="detect")
        
        ttk.Radiobutton(mode_frame, text="🔍 Detect (использовать модель)", 
                       variable=self.ml_mode_var, value="detect").pack(anchor=tk.W)
        ttk.Radiobutton(mode_frame, text="📊 Train (сбор данных для обучения)", 
                       variable=self.ml_mode_var, value="train").pack(anchor=tk.W)
        
        # Кнопка принудительного обучения
        self.train_btn = ttk.Button(control_frame, text="🧠 Train Model from DB", 
                                    command=self.train_model_from_db)
        self.train_btn.pack(side=tk.LEFT, padx=5)
        
        # Кнопка очистки БД
        self.clear_db_btn = ttk.Button(control_frame, text="🗑️ Clear DB (keep lists)", 
                                        command=self.clear_database_keep_lists)
        self.clear_db_btn.pack(side=tk.LEFT, padx=5)
        
        # Кнопка сброса модели
        self.reset_model_btn = ttk.Button(control_frame, text="🔄 Reset Model", 
                                           command=self.reset_ml_model)
        self.reset_model_btn.pack(side=tk.LEFT, padx=5)
        
        # Статусная строка
        self.status_label = ttk.Label(control_frame, text="● Stopped", foreground="red")
        self.status_label.pack(side=tk.LEFT, padx=20)
        
        # Счётчики
        stats_frame = ttk.Frame(control_frame)
        stats_frame.pack(side=tk.RIGHT, padx=5)
        
        self.packets_label = ttk.Label(stats_frame, text="Packets: 0")
        self.packets_label.pack(side=tk.LEFT, padx=5)
        
        self.alerts_label = ttk.Label(stats_frame, text="Suspicious IPs: 0", foreground="orange")
        self.alerts_label.pack(side=tk.LEFT, padx=5)
        
        self.blocked_label = ttk.Label(stats_frame, text="Blocked: 0", foreground="red")
        self.blocked_label.pack(side=tk.LEFT, padx=5)
        
        print("[DEBUG] Создание вкладок...")
        
        # Вкладки
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Вкладка 1: Логи
        self.log_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.log_frame, text="Live Logs")
        self.setup_log_tab()
        
        # Вкладка 2: Подозрительные IP
        self.alerts_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.alerts_frame, text="Suspicious IPs")
        self.setup_alerts_tab()
        
        # Вкладка 3: Белый список
        self.whitelist_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.whitelist_frame, text="Whitelist")
        self.setup_whitelist_tab()
        
        # Вкладка 4: Чёрный список
        self.blacklist_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.blacklist_frame, text="Blacklist")
        self.setup_blacklist_tab()
        
        # Вкладка 5: Статистика
        self.stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.stats_frame, text="Statistics")
        self.setup_stats_tab()
        
        print("[DEBUG] setup_gui завершён")
    
    def setup_log_tab(self):
        """Настройка вкладки с логами"""
        self.log_text = scrolledtext.ScrolledText(
            self.log_frame,
            bg='#1e1e1e',
            fg='#00ff00',
            font=('Consolas', 10)
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        clear_btn = ttk.Button(self.log_frame, text="Clear Logs", command=self.clear_logs)
        clear_btn.pack(pady=5)
    
    def setup_alerts_tab(self):
        """Настройка вкладки с группированными подозрительными IP"""
        columns = ('Source IP', 'Attack Type', 'Score', 'Count', 'Last Seen')
        self.alerts_tree = ttk.Treeview(self.alerts_frame, columns=columns, show='headings', height=20)
        
        self.alerts_tree.heading('Source IP', text='Source IP')
        self.alerts_tree.heading('Attack Type', text='Attack Type')
        self.alerts_tree.heading('Score', text='Score')
        self.alerts_tree.heading('Count', text='Count')
        self.alerts_tree.heading('Last Seen', text='Last Seen')
        
        self.alerts_tree.column('Source IP', width=140)
        self.alerts_tree.column('Attack Type', width=120)
        self.alerts_tree.column('Score', width=80)
        self.alerts_tree.column('Count', width=60)
        self.alerts_tree.column('Last Seen', width=150)
        
        self.alerts_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Кнопки управления
        btn_frame = ttk.Frame(self.alerts_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame, text="🔍 Details", command=self.view_alert_details).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="🚫 Block IP", command=self.block_selected_ip).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="✅ Add to Whitelist", command=self.add_selected_to_whitelist).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="🔄 Refresh", command=self.force_refresh_alerts).pack(side=tk.LEFT, padx=5)
        
        self.alerts_tree.bind('<Double-1>', lambda e: self.view_alert_details())
    
    def setup_whitelist_tab(self):
        """Настройка вкладки с белым списком"""
        add_frame = ttk.LabelFrame(self.whitelist_frame, text="Add to Whitelist", padding=5)
        add_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(add_frame, text="IP Address:").grid(row=0, column=0, padx=5, pady=5)
        self.whitelist_ip_entry = ttk.Entry(add_frame, width=25)
        self.whitelist_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(add_frame, text="Add IP", command=self.add_ip_to_whitelist).grid(row=0, column=2, padx=5, pady=5)
        
        ttk.Label(add_frame, text="Network Prefix:").grid(row=1, column=0, padx=5, pady=5)
        self.whitelist_network_entry = ttk.Entry(add_frame, width=25)
        self.whitelist_network_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(add_frame, text="Add Network", command=self.add_network_to_whitelist).grid(row=1, column=2, padx=5, pady=5)
        
        columns = ('Type', 'Value')
        self.whitelist_tree = ttk.Treeview(self.whitelist_frame, columns=columns, show='headings', height=15)
        
        self.whitelist_tree.heading('Type', text='Type')
        self.whitelist_tree.heading('Value', text='Value')
        
        self.whitelist_tree.column('Type', width=100)
        self.whitelist_tree.column('Value', width=400)
        
        self.whitelist_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        btn_frame = ttk.Frame(self.whitelist_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame, text="Remove Selected", command=self.remove_from_whitelist).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Refresh", command=self.force_refresh_whitelist).pack(side=tk.LEFT, padx=5)
        
        self.force_refresh_whitelist()
    
    def setup_blacklist_tab(self):
        """Настройка вкладки с чёрным списком"""
        columns = ('IP Address', 'Reason', 'Blocked At')
        self.blacklist_tree = ttk.Treeview(self.blacklist_frame, columns=columns, show='headings', height=20)
        
        self.blacklist_tree.heading('IP Address', text='IP Address')
        self.blacklist_tree.heading('Reason', text='Reason')
        self.blacklist_tree.heading('Blocked At', text='Blocked At')
        
        self.blacklist_tree.column('IP Address', width=150)
        self.blacklist_tree.column('Reason', width=250)
        self.blacklist_tree.column('Blocked At', width=200)
        
        self.blacklist_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        btn_frame = ttk.Frame(self.blacklist_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame, text="Unblock Selected IP", command=self.unblock_ip).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Refresh", command=self.force_refresh_blacklist).pack(side=tk.LEFT, padx=5)
        
        self.force_refresh_blacklist()
    
    def setup_stats_tab(self):
        """Настройка вкладки со статистикой"""
        # Основной фрейм с прокруткой
        canvas = tk.Canvas(self.stats_frame, bg='#1e1e1e', highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.stats_frame, orient=tk.VERTICAL, command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Заголовок
        title = ttk.Label(scrollable_frame, text="DARKTRACE LIGHT STATISTICS", 
                         font=('Arial', 16, 'bold'), foreground='#0e639c')
        title.pack(pady=20)
        
        # Создаём карточки с данными
        stats_frame_inner = ttk.Frame(scrollable_frame)
        stats_frame_inner.pack(pady=10)
        
        # Карточка 1: Общая статистика
        card1 = ttk.LabelFrame(stats_frame_inner, text="📊 Общая статистика", padding=15)
        card1.pack(fill=tk.X, padx=20, pady=10)
        
        self.stat_packets = ttk.Label(card1, text="Packets: 0", font=('Consolas', 12), foreground='#00ff00')
        self.stat_packets.pack(anchor=tk.W, pady=2)
        
        self.stat_alerts = ttk.Label(card1, text="Alerts: 0", font=('Consolas', 12), foreground='#ffaa00')
        self.stat_alerts.pack(anchor=tk.W, pady=2)
        
        self.stat_blocked = ttk.Label(card1, text="Blocked IPs: 0", font=('Consolas', 12), foreground='#ff5555')
        self.stat_blocked.pack(anchor=tk.W, pady=2)
        
        # Карточка 2: Списки
        card2 = ttk.LabelFrame(stats_frame_inner, text="📋 Списки", padding=15)
        card2.pack(fill=tk.X, padx=20, pady=10)
        
        self.stat_wl_ips = ttk.Label(card2, text="Whitelist IPs: 0", font=('Consolas', 12))
        self.stat_wl_ips.pack(anchor=tk.W, pady=2)
        
        self.stat_wl_nets = ttk.Label(card2, text="Whitelist Networks: 0", font=('Consolas', 12))
        self.stat_wl_nets.pack(anchor=tk.W, pady=2)
        
        # Карточка 3: Состояние
        card3 = ttk.LabelFrame(stats_frame_inner, text="⚙️ Состояние", padding=15)
        card3.pack(fill=tk.X, padx=20, pady=10)
        
        self.stat_ml = ttk.Label(card3, text="ML Status: COLLECTING", font=('Consolas', 12))
        self.stat_ml.pack(anchor=tk.W, pady=2)
        
        self.stat_mode = ttk.Label(card3, text="Mode: detect", font=('Consolas', 12))
        self.stat_mode.pack(anchor=tk.W, pady=2)
        
        self.stat_monitoring = ttk.Label(card3, text="Monitoring: STOPPED", font=('Consolas', 12), foreground='#ff5555')
        self.stat_monitoring.pack(anchor=tk.W, pady=2)
        
        self.stat_capture = ttk.Label(card3, text="Capture Mode: REAL", font=('Consolas', 12))
        self.stat_capture.pack(anchor=tk.W, pady=2)
        
        # Запускаем обновление статистики
        self.update_stats_display_v2()
    
    # ==================== МЕТОДЫ БЕЛОГО СПИСКА ====================
    
    def add_ip_to_whitelist(self):
        ip = self.whitelist_ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Warning", "Введите IP адрес")
            return
        if self.whitelist.add_ip(ip):
            self.log_message(f"[WHITELIST] IP {ip} добавлен", "green")
            self.whitelist_ip_entry.delete(0, tk.END)
            self.force_refresh_whitelist()
    
    def add_network_to_whitelist(self):
        net = self.whitelist_network_entry.get().strip()
        if not net:
            messagebox.showwarning("Warning", "Введите префикс сети")
            return
        if self.whitelist.add_network(net):
            self.log_message(f"[WHITELIST] Сеть {net} добавлена", "green")
            self.whitelist_network_entry.delete(0, tk.END)
            self.force_refresh_whitelist()
    
    def remove_from_whitelist(self):
        selected = self.whitelist_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Выберите элемент для удаления")
            return
        for item in selected:
            values = self.whitelist_tree.item(item, 'values')
            if values and values[0] == 'IP':
                self.whitelist.remove_ip(values[1])
                self.log_message(f"[WHITELIST] IP {values[1]} удалён", "yellow")
            elif values and values[0] == 'Network':
                self.whitelist.remove_network(values[1].rstrip('.'))
                self.log_message(f"[WHITELIST] Сеть {values[1]} удалена", "yellow")
        self.force_refresh_whitelist()
    
    def force_refresh_whitelist(self):
        """Принудительное обновление таблицы белого списка"""
        for item in self.whitelist_tree.get_children():
            self.whitelist_tree.delete(item)
        data = self.whitelist.get_all()
        for ip in data['ips']:
            self.whitelist_tree.insert('', 'end', values=('IP', ip))
        for net in data['networks']:
            self.whitelist_tree.insert('', 'end', values=('Network', net))
    
    def add_selected_to_whitelist(self):
        """Добавление выбранного IP из таблицы алертов в белый список"""
        selected = self.alerts_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Выберите IP для добавления в белый список")
            return
        values = self.alerts_tree.item(selected[0], 'values')
        ip = values[0]
        if self.whitelist.add_ip(ip):
            self.log_message(f"[WHITELIST] IP {ip} добавлен в белый список из алертов", "green")
            self.force_refresh_whitelist()
            self.force_refresh_alerts()
    
    # ==================== МЕТОДЫ АЛЕРТОВ ====================
    
    def force_refresh_alerts(self):
        """Принудительное обновление таблицы алертов"""
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        
        suspicious_ips = self.db.get_suspicious_ips_grouped()
        self.alerts_label.config(text=f"Suspicious IPs: {len(suspicious_ips)}")
        
        for ip in suspicious_ips:
            last_seen = ip['last_seen'][:19] if ip['last_seen'] else ''
            self.alerts_tree.insert('', 'end', values=(
                ip['ip'], ip['type'], f"{ip['score']:.3f}", ip['count'], last_seen
            ))
    
    def force_refresh_blacklist(self):
        """Принудительное обновление таблицы чёрного списка с сохранением выделения"""
        # Сохраняем выделенные IP
        selected_items = []
        for item in self.blacklist_tree.selection():
            values = self.blacklist_tree.item(item, 'values')
            if values:
                selected_items.append(values[0])
        
        for item in self.blacklist_tree.get_children():
            self.blacklist_tree.delete(item)
        
        for ip, data in self.blacklist.get_all().items():
            blocked_at = data.get('blocked_at', '')[:19]
            self.blacklist_tree.insert('', 'end', values=(ip, data['reason'], blocked_at))
        
        # Восстанавливаем выделение
        for item in self.blacklist_tree.get_children():
            values = self.blacklist_tree.item(item, 'values')
            if values and values[0] in selected_items:
                self.blacklist_tree.selection_add(item)
        
        self.blocked_label.config(text=f"Blocked: {len(self.blacklist.get_all())}")
    
    def get_ip_additional_info(self, ip):
        """Получение дополнительной информации об IP"""
        info = get_ip_info(ip)
        
        alerts = self.db.get_alerts_by_ip(ip, limit=5)
        
        lines = []
        lines.append(f"IP: {ip}")
        lines.append(f"Тип: {'Приватный / Локальный' if info['is_private'] else 'Публичный'}")
        lines.append(f"Провайдер/Владелец: {info['isp']}")
        
        if info['rdns']:
            lines.append(f"Reverse DNS: {info['rdns']}")
        
        if info['is_suspicious']:
            lines.append(f"⚠️ Подозрительный: {', '.join(info['suspicious_reason'])}")
        
        lines.append("")
        lines.append(f"📊 Статистика атак:")
        lines.append(f"   Всего алертов: {len(alerts)}")
        
        attack_counts = defaultdict(int)
        for alert in alerts:
            attack_counts[alert[1]] += 1
        
        if attack_counts:
            lines.append("   Типы атак:")
            for attack_type, count in sorted(attack_counts.items(), key=lambda x: -x[1]):
                lines.append(f"      - {attack_type}: {count} раз(а)")
        
        return "\n".join(lines)
    
    def view_alert_details(self):
        """Просмотр деталей алертов для выбранного IP"""
        selected = self.alerts_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Выберите IP для просмотра деталей")
            return
        
        values = self.alerts_tree.item(selected[0], 'values')
        ip = values[0]
        
        alerts = self.db.get_alerts_by_ip(ip)
        if not alerts:
            messagebox.showinfo("Info", f"Нет деталей для IP {ip}")
            return
        
        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"IP Details - {ip}")
        detail_window.geometry("800x600")
        detail_window.configure(bg='#1e1e1e')
        
        text_widget = scrolledtext.ScrolledText(
            detail_window, bg='#1e1e1e', fg='#00ff00', font=('Consolas', 10)
        )
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        text_widget.insert(tk.END, f"{'='*70}\n")
        text_widget.insert(tk.END, f"ИНФОРМАЦИЯ ОБ IP: {ip}\n")
        text_widget.insert(tk.END, f"{'='*70}\n\n")
        
        ip_info = self.get_ip_additional_info(ip)
        text_widget.insert(tk.END, ip_info)
        text_widget.insert(tk.END, f"\n\n{'='*70}\n")
        text_widget.insert(tk.END, f"ДЕТАЛИ АТАК (последние 30)\n")
        text_widget.insert(tk.END, f"{'='*70}\n\n")
        
        for alert in alerts[:30]:
            timestamp, attack_type, score, blocked, details, packet_id, dst_ip = alert
            text_widget.insert(tk.END, f"┌────────────────────────────────────────────────────────────────────┐\n")
            text_widget.insert(tk.END, f"│ Время:      {timestamp}\n")
            text_widget.insert(tk.END, f"│ Тип атаки:  {attack_type}\n")
            text_widget.insert(tk.END, f"│ Score:      {score:.4f}\n")
            text_widget.insert(tk.END, f"│ Цель:       {dst_ip}\n")
            text_widget.insert(tk.END, f"│ Заблокирован: {'ДА' if blocked else 'НЕТ'}\n")
            
            if packet_id:
                packet = self.db.get_packet_by_id(packet_id)
                if packet:
                    text_widget.insert(tk.END, f"│ Пакет:      {packet[0]} -> {packet[1]} (порт: {packet[3]})\n")
                    text_widget.insert(tk.END, f"│ Размер:     {packet[4]} bytes\n")
                    if packet[6]:
                        payload_preview = packet[6][:150] + "..." if len(packet[6]) > 150 else packet[6]
                        text_widget.insert(tk.END, f"│ Payload:    {payload_preview}\n")
            
            text_widget.insert(tk.END, f"└────────────────────────────────────────────────────────────────────┘\n\n")
        
        text_widget.configure(state='disabled')
        
        btn_frame = ttk.Frame(detail_window)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        if not self.blacklist.is_blocked(ip):
            ttk.Button(btn_frame, text="🚫 Block This IP", 
                      command=lambda: self.block_ip_direct(ip, detail_window)).pack(side=tk.LEFT, padx=5)
        else:
            ttk.Button(btn_frame, text="🔓 Unblock This IP", 
                      command=lambda: self.unblock_ip_direct(ip, detail_window)).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="✅ Add to Whitelist", 
                  command=lambda: self.whitelist_add_ip_direct(ip, detail_window)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=detail_window.destroy).pack(side=tk.RIGHT, padx=5)
    
    def block_selected_ip(self):
        """Блокировка выбранного IP из таблицы алертов"""
        selected = self.alerts_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Выберите IP для блокировки")
            return
        values = self.alerts_tree.item(selected[0], 'values')
        ip = values[0]
        self.block_ip_direct(ip)
    
    def block_ip_direct(self, ip, window_to_close=None):
        """Постоянная блокировка IP"""
        if ip.startswith(('10.', '192.168.', '172.', '127.')):
            self.log_message(f"[BLOCK] IP {ip} локальный, блокировка не выполнена", "yellow")
            messagebox.showwarning("Warning", f"IP {ip} локальный. Блокировка не выполняется.")
            return
        
        if self.blacklist.is_blocked(ip):
            self.log_message(f"[BLOCK] IP {ip} уже в чёрном списке", "yellow")
            if window_to_close:
                window_to_close.destroy()
            return
        
        self.blacklist.add(ip, "Заблокирован пользователем")
        self.log_message(f"[BLOCK] IP {ip} заблокирован", "red")
        self.force_refresh_blacklist()
        self.force_refresh_alerts()
        
        if window_to_close:
            window_to_close.destroy()
        
        messagebox.showinfo("Blocked", f"IP {ip} заблокирован.")
    
    def unblock_ip_direct(self, ip, window_to_close=None):
        """Разблокировка IP"""
        if self.blacklist.remove(ip):
            self.log_message(f"[BLOCK] IP {ip} разблокирован", "green")
            self.force_refresh_blacklist()
            self.force_refresh_alerts()
            if window_to_close:
                window_to_close.destroy()
    
    def whitelist_add_ip_direct(self, ip, window_to_close=None):
        """Добавление IP в белый список"""
        if self.whitelist.add_ip(ip):
            self.log_message(f"[WHITELIST] IP {ip} добавлен в белый список", "green")
            self.force_refresh_whitelist()
            self.force_refresh_alerts()
            messagebox.showinfo("Success", f"IP {ip} добавлен в белый список")
        if window_to_close:
            window_to_close.destroy()
    
    def unblock_ip(self):
        """Разблокировка выбранного IP из таблицы чёрного списка"""
        selected = self.blacklist_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Выберите IP для разблокировки")
            return
        
        values = self.blacklist_tree.item(selected[0], 'values')
        ip = values[0]
        
        if self.blacklist.remove(ip):
            self.log_message(f"[BLOCK] IP {ip} разблокирован", "green")
            self.force_refresh_blacklist()
            self.force_refresh_alerts()
    
    def check_permissions(self):
        """Проверка прав для захвата трафика"""
        if os.geteuid() != 0:
            self.log_message("[WARNING] Запущено не от root. Захват трафика может не работать!", "yellow")
            self.log_message("[INFO] Используйте: sudo python3 main.py", "yellow")
        else:
            self.log_message("[INFO] Root права обнаружены. Захват трафика доступен.", "green")
    
    def log_message(self, message, color="white"):
        """Добавление сообщения в лог"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {message}\n"
        
        self.log_text.insert(tk.END, formatted)
        self.log_text.see(tk.END)
        logger.info(message)
    
    def clear_logs(self):
        """Очистка логов в GUI"""
        self.log_text.delete(1.0, tk.END)
        self.log_message("[INFO] Логи очищены", "gray")
    
    def update_stats_display_v2(self):
        """Обновление отображения статистики (карточки)"""
        db_stats = self.db.get_stats()
        wl_data = self.whitelist.get_all()
        bl_count = len(self.blacklist.get_all())
        
        ml_status = "ACTIVE" if self.anomaly_detector and self.anomaly_detector.is_trained else "COLLECTING"
        ml_color = '#00ff00' if ml_status == "ACTIVE" else '#ffaa00'
        
        monitoring_status = "ACTIVE" if self.monitoring else "STOPPED"
        monitoring_color = '#00ff00' if self.monitoring else '#ff5555'
        
        # Обновляем карточки
        self.stat_packets.config(text=f"📦 Packets: {db_stats[0]}")
        self.stat_alerts.config(text=f"⚠️ Alerts: {db_stats[1]}")
        self.stat_blocked.config(text=f"🚫 Blocked IPs: {bl_count}")
        
        self.stat_wl_ips.config(text=f"✅ Whitelist IPs: {len(wl_data['ips'])}")
        self.stat_wl_nets.config(text=f"🌐 Whitelist Networks: {len(wl_data['networks'])}")
        
        self.stat_ml.config(text=f"🧠 ML Status: {ml_status}", foreground=ml_color)
        self.stat_mode.config(text=f"🎯 Mode: {self.ml_mode_var.get()}")
        self.stat_monitoring.config(text=f"🟢 Monitoring: {monitoring_status}", foreground=monitoring_color)
        self.stat_capture.config(text=f"📡 Capture Mode: {'REAL' if REAL_CAPTURE_AVAILABLE else 'DEMO'}")
        
        # Запланировать следующее обновление
        self.root.after(3000, self.update_stats_display_v2)
    
    # ==================== УПРАВЛЕНИЕ БД И МОДЕЛЬЮ ====================
    
    def clear_database_keep_lists(self):
        """Очистка БД с сохранением белого и чёрного списков"""
        result = messagebox.askyesno(
            "Подтверждение", 
            "Очистить БД?\n\n"
            "Будут удалены:\n"
            "• Все пакеты\n"
            "• Все алерты\n\n"
            "Будут сохранены:\n"
            "• Белый список IP и сетей\n"
            "• Чёрный список IP\n\n"
            "Продолжить?"
        )
        if not result:
            return
        
        self.log_message("[DB] Очистка базы данных...", "yellow")
        
        import sqlite3
        with sqlite3.connect(self.db.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM packets")
            cursor.execute("DELETE FROM alerts")
            cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('packets', 'alerts')")
            conn.commit()
        
        self.force_refresh_alerts()
        self.log_message("[DB] База данных очищена (списки сохранены)", "green")
        messagebox.showinfo("Готово", "База данных очищена.\nБелый и чёрный списки сохранены.")
    
    def reset_ml_model(self):
        """Сброс ML модели (удаление файла)"""
        result = messagebox.askyesno(
            "Подтверждение", 
            "Сбросить ML модель?\n\n"
            "Это удалит обученную модель.\n"
            "Программа перейдёт в режим сбора данных для обучения.\n\n"
            "Продолжить?"
        )
        if not result:
            return
        
        import os
        from pathlib import Path
        
        model_path = Path(__file__).parent / "models" / "isolation_forest.pkl"
        if model_path.exists():
            os.remove(model_path)
            self.log_message("[ML] Модель удалена", "yellow")
        else:
            self.log_message("[ML] Модель не найдена", "yellow")
        
        if self.anomaly_detector:
            self.anomaly_detector.is_trained = False
            self.anomaly_detector.model = None
            self.anomaly_detector.training_buffer.clear()
        
        self.ml_mode_var.set("train")
        self.log_message("[ML] Режим переключён на Train. Собирайте данные для обучения.", "cyan")
        messagebox.showinfo("Готово", "ML модель сброшена.\nПрограмма теперь в режиме сбора данных.")
    
    def add_alert_and_block(self, src_ip, dst_ip, attack_type, score, packet_id=None):
        """Добавление алерта и автоматическая блокировка при высоком score (>0.85)"""
        # Проверка белого списка
        if self.whitelist.is_whitelisted(src_ip):
            return
        
        # Проверка чёрного списка
        if self.blacklist.is_blocked(src_ip):
            return
        
        # Сохраняем в БД
        self.db.log_alert(src_ip, dst_ip, attack_type, score, packet_id, blocked=0)
        
        # АВТОМАТИЧЕСКАЯ БЛОКИРОВКА при высоком score (>0.85)
        if score > 0.85:
            self.log_message(f"[AUTO-BLOCK] {attack_type} от {src_ip} (score: {score:.2f}) - высокая опасность!", "red")
            self.blacklist.add(src_ip, f"Автоблокировка: {attack_type} (score: {score:.2f})")
            # Обновляем статус блокировки в алерте
            self.db.log_alert(src_ip, dst_ip, attack_type, score, packet_id, blocked=1)
            self.force_refresh_blacklist()
        
        # Обновляем группированную таблицу
        self.force_refresh_alerts()
    
    def train_model_from_db(self):
        """Принудительное обучение модели на данных из БД"""
        if not self.anomaly_detector:
            self.log_message("[ML] Детектор не инициализирован", "red")
            return
        
        db_stats = self.db.get_stats()
        if db_stats[0] < 100:
            self.log_message(f"[ML] Недостаточно данных: {db_stats[0]} пакетов, нужно минимум 100", "red")
            messagebox.showwarning("Warning", f"Недостаточно данных в БД.\nСобрано {db_stats[0]} пакетов, нужно минимум 100.")
            return
        
        self.log_message("[ML] Запуск обучения на данных из БД...", "yellow")
        
        def train():
            success = self.anomaly_detector.train_from_database(
                self.db.db_path, 
                num_packets=3000,
                exclude_attacks=True
            )
            if success:
                self.root.after(0, lambda: self.log_message("[ML] Модель успешно обучена!", "green"))
                self.root.after(0, lambda: messagebox.showinfo("Success", "ML модель обучена!\nТеперь переключитесь в режим Detect вручную."))
            else:
                self.root.after(0, lambda: self.log_message("[ML] Ошибка обучения. Недостаточно чистых данных?", "red"))
        
        threading.Thread(target=train, daemon=True).start()
    
    def packet_capture_worker(self):
        """Поток для реального захвата трафика"""
        if REAL_CAPTURE_AVAILABLE:
            self.log_message("[INFO] Запуск реального захвата трафика", "green")
            self.real_capture_worker()
        else:
            self.log_message("[ERROR] Реальный захват недоступен!", "red")
            self.log_message("[INFO] Убедитесь, что файл packet_capture.py находится в папке src/", "yellow")
            while self.monitoring:
                time.sleep(1)
    
    def real_capture_worker(self):
        """Реальный захват через scapy"""
        try:
            self.capture = RealPacketCapture(
                packet_queue=self.packet_queue,
                log_callback=lambda msg: self.log_message(msg, "gray")
            )
            
            interface = None
            if not self.capture.start_capture(interface=interface):
                self.log_message("[ERROR] Не удалось запустить захват", "red")
                return
            
            self.log_message(f"[INFO] Захват запущен", "green")
            
            while self.monitoring:
                time.sleep(0.5)
            
            if self.capture:
                self.capture.stop_capture()
                
        except Exception as e:
            self.log_message(f"[ERROR] Ошибка захвата: {e}", "red")
    
    def analyze_packet_worker(self):
        """Поток для анализа пакетов"""
        self.log_message("[INFO] Модуль анализа запущен", "green")
        packet_count = 0
        recent_packets = []
        
        while self.monitoring:
            try:
                packet = self.packet_queue.get(timeout=1)
                packet_count += 1
                
                recent_packets.append(packet)
                if len(recent_packets) > 500:
                    recent_packets.pop(0)
                
                packet_id = self.db.log_packet(packet)
                
                src_ip = packet.get('src_ip', 'Unknown')
                dst_ip = packet.get('dst_ip', 'Unknown')
                payload = packet.get('payload', '').lower()
                
                # ===== ПРОВЕРКА БЕЛОГО СПИСКА =====
                if self.whitelist.is_whitelisted(src_ip):
                    continue
                
                # ===== ПРОВЕРКА ЧЁРНОГО СПИСКА =====
                if self.blacklist.is_blocked(src_ip):
                    continue
                
                # ===== СИГНАТУРНЫЙ АНАЛИЗ =====
                attack_detected = False
                attack_type = "Normal"
                score = 0.0
                
                # SQL инъекции
                sql_patterns = [
                    "' or '1'='1", "'or'1'='1", "union select", "drop table", 
                    "1=1'", "or 1=1", "';--", "' or 1=1", "select * from",
                    "information_schema", "order by", "and 1=1", "' union select",
                    "into outfile", "load_file", "or '1'='1", "or 1=1--"
                ]
                for pattern in sql_patterns:
                    if pattern in payload:
                        attack_detected = True
                        attack_type = "SQL Injection"
                        score = 0.95
                        break
                
                # XSS атаки
                if not attack_detected:
                    xss_patterns = [
                        "<script>", "javascript:", "onerror=", "alert(",
                        "<img", "onload=", "onclick=", "onmouseover",
                        "prompt(", "confirm(", "<iframe", "<body onload",
                        "expression(", "vbscript:", "onerror=alert"
                    ]
                    for pattern in xss_patterns:
                        if pattern in payload:
                            attack_detected = True
                            attack_type = "XSS Attack"
                            score = 0.92
                            break
                
                # Command injection
                if not attack_detected:
                    cmd_patterns = [
                        "; ls", "; cat", "| whoami", "`id`", "$(id)",
                        "; id", "|| ls", "&& ls", "| id", "; pwd",
                        "cat /etc/passwd", "whoami", "uname -a", "; nc",
                        "bash -i", "sh -i", "| sh", "; sh"
                    ]
                    for pattern in cmd_patterns:
                        if pattern in payload:
                            attack_detected = True
                            attack_type = "Command Injection"
                            score = 0.93
                            break
                
                # ML анализ
                if not attack_detected and self.anomaly_detector and self.anomaly_detector.is_trained and self.ml_mode_var.get() == "detect":
                    ml_anomaly, ml_score, confidence = self.anomaly_detector.detect(packet, recent_packets)
                    
                    if ml_anomaly and confidence > 0.7:
                        attack_detected = True
                        attack_type = "ML Anomaly"
                        score = ml_score
                        self.log_message(f"[ML] Аномалия от {src_ip}: score={ml_score:.3f}", "cyan")
                
                # Обучение ML (только сбор данных, БЕЗ АВТОМАТИЧЕСКОГО ПЕРЕКЛЮЧЕНИЯ)
                if self.anomaly_detector and not self.anomaly_detector.is_trained and self.ml_mode_var.get() != "detect":
                    trained = self.anomaly_detector.add_packet_to_buffer(packet)
                    if trained:
                        self.log_message("[ML] Модель обучена на собранных данных! Нажмите 'Train Model from DB' для сохранения.", "green")
                        # НЕ переключаем режим автоматически - пользователь сам решит
                
                # Реакция на атаку
                if attack_detected and src_ip not in ['Unknown', '127.0.0.1', '::1']:
                    self.root.after(0, lambda sip=src_ip, dip=dst_ip, at=attack_type, sc=score, pid=packet_id: 
                                   self.add_alert_and_block(sip, dip, at, sc, pid))
                    self.log_message(f"[ALERT] {attack_type} от {src_ip} -> {dst_ip} (score: {score:.2f})", "orange")
                
                # Обновление счётчика
                if packet_count % 50 == 0:
                    db_stats = self.db.get_stats()
                    self.root.after(0, lambda: self.packets_label.config(text=f"Packets: {db_stats[0]}"))
                
            except queue.Empty:
                continue
            except Exception as e:
                self.log_message(f"[ERROR] Ошибка анализа: {e}", "red")
        
        self.log_message("[INFO] Модуль анализа остановлен", "yellow")
    
    def start_monitoring(self):
        """Запуск мониторинга"""
        if self.monitoring:
            return
        
        self.monitoring = True
        
        self.capture_thread = threading.Thread(target=self.packet_capture_worker, daemon=True)
        self.analysis_thread = threading.Thread(target=self.analyze_packet_worker, daemon=True)
        
        self.capture_thread.start()
        self.analysis_thread.start()
        
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_label.config(text="● Monitoring Active", foreground="green")
        self.train_btn.config(state=tk.NORMAL)
        self.clear_db_btn.config(state=tk.NORMAL)
        self.reset_model_btn.config(state=tk.NORMAL)
        
        self.log_message("[INFO] Система мониторинга запущена", "green")
    
    def stop_monitoring(self):
        """Остановка мониторинга"""
        if not self.monitoring:
            return
        
        self.monitoring = False
        
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=3)
        if self.analysis_thread and self.analysis_thread.is_alive():
            self.analysis_thread.join(timeout=3)
        
        if self.capture:
            try:
                self.capture.stop_capture()
            except:
                pass
            self.capture = None
        
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="● Stopped", foreground="red")
        self.train_btn.config(state=tk.NORMAL)
        self.clear_db_btn.config(state=tk.NORMAL)
        self.reset_model_btn.config(state=tk.NORMAL)
        
        self.log_message("[INFO] Система мониторинга остановлена", "yellow")
    
    def update_gui(self):
        """Периодическое обновление GUI"""
        db_stats = self.db.get_stats()
        self.packets_label.config(text=f"Packets: {db_stats[0]}")
        
        # Обновляем чёрный список
        self.force_refresh_blacklist()
        
        self.root.after(3000, self.update_gui)


def main():
    """Точка входа"""
    print("[DEBUG] Создание корневого окна tkinter...")
    root = tk.Tk()
    print("[DEBUG] Корневое окно создано, создание приложения...")
    app = DarkTraceLight(root)
    print("[DEBUG] Приложение создано, запуск mainloop...")
    
    def on_closing():
        print("[DEBUG] Закрытие окна...")
        if app.monitoring:
            app.stop_monitoring()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()
    print("[DEBUG] mainloop завершён")


if __name__ == "__main__":
    print("[DEBUG] Программа запущена")
    if sys.platform.startswith('linux') and os.geteuid() != 0:
        print("\n" + "="*60)
        print("⚠️  ВНИМАНИЕ: Для захвата реального трафика нужны root права")
        print("   Запустите: sudo python3 main.py")
        print("="*60 + "\n")
    
    main()