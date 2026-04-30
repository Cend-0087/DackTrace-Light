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
from datetime import datetime
import logging
from pathlib import Path

# Настройка путей
BASE_DIR = Path(__file__).parent
LOG_DIR = BASE_DIR / "logs"
DB_DIR = BASE_DIR / "database"

LOG_DIR.mkdir(exist_ok=True)
DB_DIR.mkdir(exist_ok=True)

# Добавляем src в путь для импорта модулей
sys.path.insert(0, str(BASE_DIR / "src"))

# Попытка импорта реального захвата
try:
    from packet_capture import RealPacketCapture
    REAL_CAPTURE_AVAILABLE = True
    print("[OK] RealPacketCapture модуль загружен")
except ImportError as e:
    REAL_CAPTURE_AVAILABLE = False
    print(f"[WARN] RealPacketCapture не найден: {e}")

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


class Database:
    """Работа с SQLite базой данных"""
    
    def __init__(self, db_path="database/darktrace.db"):
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
                    payload TEXT
                );
                
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT,
                    attack_type TEXT,
                    anomaly_score REAL,
                    blocked INTEGER DEFAULT 1,
                    packet_id INTEGER,
                    details TEXT
                );
                
                CREATE TABLE IF NOT EXISTS blacklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE,
                    reason TEXT,
                    blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME
                );
                
                CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_packets_time ON packets(timestamp);
                CREATE INDEX IF NOT EXISTS idx_blacklist_ip ON blacklist(ip);
            ''')
    
    def log_packet(self, packet):
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute('''
                INSERT INTO packets (src_ip, dst_ip, src_port, dst_port, protocol, length, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                RETURNING id
            ''', (
                packet.get('src_ip'), packet.get('dst_ip'),
                packet.get('src_port'), packet.get('dst_port'),
                str(packet.get('protocol', '')),
                packet.get('length', 0),
                packet.get('payload', '')[:1000]
            ))
            return cur.fetchone()[0]
    
    def log_alert(self, src_ip, attack_type, score, packet_id=None, details=None):
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO alerts (src_ip, attack_type, anomaly_score, packet_id, details)
                VALUES (?, ?, ?, ?, ?)
            ''', (src_ip, attack_type, score, packet_id, details))
    
    def add_to_blacklist(self, ip, reason, duration_minutes=5):
        import sqlite3
        from datetime import datetime, timedelta
        expires = datetime.now() + timedelta(minutes=duration_minutes)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO blacklist (ip, reason, expires_at)
                VALUES (?, ?, ?)
            ''', (ip, reason, expires))
    
    def get_blacklist(self):
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute('SELECT ip FROM blacklist WHERE expires_at > datetime("now")')
            return [row[0] for row in cur.fetchall()]
    
    def get_stats(self):
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute('''
                SELECT 
                    (SELECT COUNT(*) FROM packets) as total_packets,
                    (SELECT COUNT(*) FROM alerts) as total_alerts,
                    (SELECT COUNT(*) FROM alerts WHERE blocked=1) as blocked_count,
                    (SELECT COUNT(*) FROM blacklist WHERE expires_at > datetime("now")) as active_blocks
            ''')
            return cur.fetchone()


import sqlite3


class DarkTraceLight:
    """Главный класс приложения"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("DarkTrace Light - Network Anomaly Detection")
        self.root.geometry("1200x700")
        self.root.configure(bg='#1e1e1e')
        
        # Инициализация БД
        self.db = Database()
        
        # Настройка стилей для тёмной темы
        self.setup_styles()
        
        # Очереди для потоков
        self.packet_queue = queue.Queue(maxsize=1000)
        self.alert_queue = queue.Queue()
        
        # Флаги состояния
        self.monitoring = False
        self.capture_thread = None
        self.analysis_thread = None
        self.capture = None
        self.anomaly_detector = None
        
        # Счётчики для статистики
        self.stats = {
            'packets_total': 0,
            'anomalies_detected': 0,
            'attacks_blocked': 0,
            'blacklisted_ips': set()
        }
        
        # Создание GUI
        self.setup_gui()
        
        # Запуск обновления интерфейса
        self.update_gui()
        
        # Проверка прав
        self.check_permissions()
        
        # Загрузка ML модели
        self.init_ml_model()
        
        logger.info("DarkTrace Light инициализирован")
    
    def init_ml_model(self):
        """Инициализация ML модели"""
        try:
            from anomaly_detector import AnomalyDetector
            self.anomaly_detector = AnomalyDetector(contamination=0.02)  # Только 2% аномалий
            # Пытаемся загрузить существующую модель
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
    
    def setup_whitelist_tab(self):
        """Настройка вкладки с белым списком"""
        self.whitelist_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.whitelist_frame, text="Whitelist")

        # Верхняя панель с кнопками добавления
        add_frame = ttk.LabelFrame(self.whitelist_frame, text="Add to Whitelist", padding=5)
        add_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(add_frame, text="IP Address:").grid(row=0, column=0, padx=5, pady=5)
        self.whitelist_ip_entry = ttk.Entry(add_frame, width=20)
        self.whitelist_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(add_frame, text="Add IP", command=self.add_ip_to_whitelist).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(add_frame, text="Network Prefix:").grid(row=1, column=0, padx=5, pady=5)
        self.whitelist_network_entry = ttk.Entry(add_frame, width=20)
        self.whitelist_network_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(add_frame, text="Add Network", command=self.add_network_to_whitelist).grid(row=1, column=2, padx=5, pady=5)

        # Таблица для отображения белого списка
        columns = ('Type', 'Value', 'Actions')
        self.whitelist_tree = ttk.Treeview(self.whitelist_frame, columns=columns, show='headings', height=15)

        self.whitelist_tree.heading('Type', text='Type')
        self.whitelist_tree.heading('Value', text='Value')
        self.whitelist_tree.heading('Actions', text='Actions')

        self.whitelist_tree.column('Type', width=100)
        self.whitelist_tree.column('Value', width=400)
        self.whitelist_tree.column('Actions', width=100)

        self.whitelist_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Кнопка обновления
        refresh_btn = ttk.Button(self.whitelist_frame, text="Refresh", command=self.refresh_whitelist)
        refresh_btn.pack(pady=5)

        # Инициализация менеджера белого списка
        from whitelist import WhitelistManager
        self.whitelist_manager = WhitelistManager()
        self.refresh_whitelist()

    def add_ip_to_whitelist(self):
        """Добавление IP в белый список"""
        ip = self.whitelist_ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Warning", "Введите IP адрес")
            return
        
        if self.whitelist_manager.add_ip(ip):
            self.log_message(f"[WHITELIST] IP {ip} добавлен в белый список", "green")
            self.whitelist_ip_entry.delete(0, tk.END)
            self.refresh_whitelist()
        else:
            messagebox.showerror("Error", "Не удалось добавить IP")
    
    def add_network_to_whitelist(self):
        """Добавление сети в белый список"""
        network = self.whitelist_network_entry.get().strip()
        if not network:
            messagebox.showwarning("Warning", "Введите префикс сети (например, 192.168.)")
            return
        
        if self.whitelist_manager.add_network(network):
            self.log_message(f"[WHITELIST] Сеть {network} добавлена в белый список", "green")
            self.whitelist_network_entry.delete(0, tk.END)
            self.refresh_whitelist()
        else:
            messagebox.showerror("Error", "Не удалось добавить сеть")
    
    def remove_from_whitelist(self, value, item_type):
        """Удаление из белого списка"""
        if item_type == "IP":
            if self.whitelist_manager.remove_ip(value):
                self.log_message(f"[WHITELIST] IP {value} удалён из белого списка", "yellow")
                self.refresh_whitelist()
        elif item_type == "Network":
            if self.whitelist_manager.remove_network(value.rstrip('.')):
                self.log_message(f"[WHITELIST] Сеть {value} удалена из белого списка", "yellow")
                self.refresh_whitelist()
    
    def refresh_whitelist(self):
        """Обновление отображения белого списка"""
        # Очищаем таблицу
        for item in self.whitelist_tree.get_children():
            self.whitelist_tree.delete(item)
        
        data = self.whitelist_manager.get_all()
        
        # Добавляем IP
        for ip in data['ips']:
            item = self.whitelist_tree.insert('', 'end', values=('IP', ip, '✖'))
            self.whitelist_tree.set(item, 'Actions', '✖')
        
        # Добавляем сети
        for network in data['networks']:
            item = self.whitelist_tree.insert('', 'end', values=('Network', network, '✖'))
            self.whitelist_tree.set(item, 'Actions', '✖')
        
        # Назначаем обработчик клика для удаления
        self.whitelist_tree.bind('<ButtonRelease-1>', self.on_whitelist_click)
    
    def on_whitelist_click(self, event):
        """Обработка клика по элементу белого списка"""
        region = self.whitelist_tree.identify_region(event.x, event.y)
        if region == 'cell':
            column = self.whitelist_tree.identify_column(event.x)
            if column == '#3':  # Колонка Actions
                item = self.whitelist_tree.identify_row(event.y)
                if item:
                    values = self.whitelist_tree.item(item, 'values')
                    if values and len(values) >= 2:
                        item_type = values[0]
                        value = values[1]
                        if messagebox.askyesno("Confirm", f"Remove {value} from whitelist?"):
                            self.remove_from_whitelist(value, item_type)

    def setup_gui(self):
        """Создание графического интерфейса"""
        # Верхняя панель с кнопками
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
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
        
        # Статусная строка
        self.status_label = ttk.Label(control_frame, text="● Stopped", foreground="red")
        self.status_label.pack(side=tk.LEFT, padx=20)
        
        # Счётчики
        stats_frame = ttk.Frame(control_frame)
        stats_frame.pack(side=tk.RIGHT, padx=5)
        
        self.packets_label = ttk.Label(stats_frame, text="Packets: 0")
        self.packets_label.pack(side=tk.LEFT, padx=5)
        
        self.alerts_label = ttk.Label(stats_frame, text="Alerts: 0", foreground="orange")
        self.alerts_label.pack(side=tk.LEFT, padx=5)
        
        self.blocked_label = ttk.Label(stats_frame, text="Blocked: 0", foreground="red")
        self.blocked_label.pack(side=tk.LEFT, padx=5)
        
        # Notebook (вкладки)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Вкладка 1: Логи
        self.log_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.log_frame, text="Live Logs")
        self.setup_log_tab()
        
        # Вкладка 2: Алерты
        self.alerts_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.alerts_frame, text="Alerts")
        self.setup_alerts_tab()
        
        # Вкладка 3: Статистика
        self.stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.stats_frame, text="Statistics")
        self.setup_stats_tab()
        
        # Вкладка 4: Чёрный список
        self.blacklist_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.blacklist_frame, text="Blacklist")
        self.setup_blacklist_tab()

        self.setup_whitelist_tab()
    
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
        """Настройка вкладки с алертами"""
        columns = ('Time', 'Source IP', 'Attack Type', 'Status', 'Anomaly Score')
        self.alerts_tree = ttk.Treeview(self.alerts_frame, columns=columns, show='headings')
        
        for col in columns:
            self.alerts_tree.heading(col, text=col)
            self.alerts_tree.column(col, width=150)
        
        self.alerts_tree.pack(fill=tk.BOTH, expand=True)
        
        export_btn = ttk.Button(self.alerts_frame, text="Export to CSV", command=self.export_alerts)
        export_btn.pack(pady=5)
    
    def setup_stats_tab(self):
        """Настройка вкладки со статистикой"""
        label = ttk.Label(self.stats_frame, text="Network Statistics Dashboard", font=('Arial', 14))
        label.pack(pady=20)
        
        self.stats_text = tk.Text(self.stats_frame, bg='#1e1e1e', fg='#ffffff', height=20)
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.update_stats_display()
    
    def setup_blacklist_tab(self):
        """Настройка вкладки с чёрным списком"""
        columns = ('IP Address', 'Reason', 'Blocked At')
        self.blacklist_tree = ttk.Treeview(self.blacklist_frame, columns=columns, show='headings')
        
        for col in columns:
            self.blacklist_tree.heading(col, text=col)
            self.blacklist_tree.column(col, width=200)
        
        self.blacklist_tree.pack(fill=tk.BOTH, expand=True)
        
        unblock_btn = ttk.Button(self.blacklist_frame, text="Unblock Selected IP", command=self.unblock_ip)
        unblock_btn.pack(pady=5)
    
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
    
    def export_alerts(self):
        """Экспорт алертов в CSV"""
        filename = f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        try:
            with open(filename, 'w') as f:
                f.write("Time,Source IP,Attack Type,Status,Anomaly Score\n")
                for item in self.alerts_tree.get_children():
                    values = self.alerts_tree.item(item)['values']
                    f.write(f"{values[0]},{values[1]},{values[2]},{values[3]},{values[4]}\n")
            self.log_message(f"[INFO] Экспортировано {len(self.alerts_tree.get_children())} алертов в {filename}", "green")
            messagebox.showinfo("Export", f"Exported to {filename}")
        except Exception as e:
            self.log_message(f"[ERROR] Ошибка экспорта: {e}", "red")
    
    def update_stats_display(self):
        """Обновление отображения статистики"""
        db_stats = self.db.get_stats()
        
        ml_status = "ACTIVE" if self.anomaly_detector and self.anomaly_detector.is_trained else "COLLECTING"
        
        stats_text = f"""
╔══════════════════════════════════════════════╗
║         DARKTRACE LIGHT STATISTICS           ║
╠══════════════════════════════════════════════╣
║ Total Packets:        {db_stats[0]:<30} ║
║ Total Alerts:         {db_stats[1]:<30} ║
║ Attacks Blocked:      {db_stats[2]:<30} ║
║ Active Blocks:        {db_stats[3]:<30} ║
╠══════════════════════════════════════════════╣
║ ML Status:            {ml_status:<30} ║
║ Mode:                 {self.ml_mode_var.get():<30} ║
╠══════════════════════════════════════════════╣
║ Monitoring Active:    {'YES' if self.monitoring else 'NO':<30} ║
║ Capture Mode:         {'REAL' if REAL_CAPTURE_AVAILABLE else 'DEMO':<30} ║
╚══════════════════════════════════════════════╝
"""
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(1.0, stats_text)
        
        if self.monitoring:
            self.root.after(2000, self.update_stats_display)
    
    def unblock_ip(self):
        """Разблокировка выбранного IP"""
        selected = self.blacklist_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Выберите IP для разблокировки")
            return
        
        ip = self.blacklist_tree.item(selected[0])['values'][0]
        self.stats['blacklisted_ips'].discard(ip)
        self.blacklist_tree.delete(selected[0])
        
        # Реальная разблокировка через iptables
        try:
            from firewall import Firewall
            Firewall.unblock_ip(ip)
            self.log_message(f"[FW] IP {ip} разблокирован в iptables", "green")
        except ImportError:
            pass
        
        self.log_message(f"[INFO] IP {ip} разблокирован", "green")
    
    def add_alert(self, ip, attack_type, score, packet_id=None):
        """Добавление алерта в таблицу и БД"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        status = "Blocked" if ip in self.stats['blacklisted_ips'] else "Detected"
        
        self.alerts_tree.insert("", 0, values=(
            timestamp, ip, attack_type, status, f"{score:.2f}"
        ))
        
        self.stats['anomalies_detected'] += 1
        self.alerts_label.config(text=f"Alerts: {self.stats['anomalies_detected']}")
        
        # Сохраняем в БД
        self.db.log_alert(ip, attack_type, score, packet_id)
        
        # Если IP не в чёрном списке - блокируем
        if ip not in self.stats['blacklisted_ips']:
            self.stats['blacklisted_ips'].add(ip)
            self.stats['attacks_blocked'] += 1
            self.blocked_label.config(text=f"Blocked: {self.stats['attacks_blocked']}")
            self.db.add_to_blacklist(ip, attack_type, duration_minutes=5)
            
            # Реальная блокировка через iptables (не для локальных IP)
            if not ip.startswith(('10.', '192.168.', '172.')):
                try:
                    from firewall import Firewall
                    Firewall.block_ip(ip, duration_seconds=300)
                    self.log_message(f"[FW] Реальная блокировка {ip} через iptables", "red")
                except ImportError:
                    self.log_message(f"[FW] Модуль firewall не найден", "yellow")
            
            self.add_to_blacklist(ip, attack_type)
    
    def add_to_blacklist(self, ip, reason):
        """Добавление IP в чёрный список в GUI"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.blacklist_tree.insert("", 0, values=(ip, reason, timestamp))
    
    def train_model_from_db(self):
        """Принудительное обучение модели на данных из БД"""
        if not self.anomaly_detector:
            self.log_message("[ML] Детектор не инициализирован", "red")
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
            else:
                self.root.after(0, lambda: self.log_message("[ML] Ошибка обучения. Недостаточно данных?", "red"))
        
        threading.Thread(target=train, daemon=True).start()
    
    def packet_capture_worker(self):
        """Поток для реального захвата трафика или имитации"""
        if REAL_CAPTURE_AVAILABLE:
            self.log_message("[INFO] Запуск реального захвата трафика", "green")
            self.real_capture_worker()
        else:
            self.log_message("[INFO] Режим имитации трафика", "yellow")
            self.simulate_packets_worker()
    
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
                self.simulate_packets_worker()
                return
            
            self.log_message(f"[INFO] Захват запущен", "green")
            
            while self.monitoring:
                time.sleep(0.5)
            
            if self.capture:
                self.capture.stop_capture()
                
        except Exception as e:
            self.log_message(f"[ERROR] Ошибка захвата: {e}", "red")
            self.simulate_packets_worker()
    
    def simulate_packets_worker(self):
        """Имитация пакетов для демонстрации"""
        self.log_message("[INFO] Режим имитации трафика", "yellow")
        
        test_packets = [
            ("192.168.1.100", "192.168.1.1", "GET /index.html HTTP/1.1", 512, 80),
            ("192.168.1.101", "192.168.1.1", "POST /login.php HTTP/1.1", 256, 80),
            ("192.168.1.50", "192.168.1.1", "GET /page?id=1' OR '1'='1", 128, 80),
            ("192.168.1.102", "192.168.1.1", "GET /search?q=test", 64, 80),
            ("10.0.0.5", "192.168.1.1", "<script>alert('xss')</script>", 96, 80),
        ]
        
        packet_index = 0
        while self.monitoring:
            pkt = test_packets[packet_index % len(test_packets)]
            packet_index += 1
            
            self.packet_queue.put({
                'timestamp': time.time(),
                'src_ip': pkt[0],
                'dst_ip': pkt[1],
                'src_port': 54321,
                'dst_port': pkt[4],
                'protocol': 6,
                'length': pkt[3],
                'payload': pkt[2],
            })
            
            self.stats['packets_total'] += 1
            self.root.after(0, lambda: self.packets_label.config(text=f"Packets: {self.stats['packets_total']}"))
            time.sleep(0.5)
    
    def analyze_packet_worker(self):
        """Поток для анализа пакетов (с белым списком)"""
        self.log_message("[INFO] Модуль анализа запущен", "green")
        packet_count = 0
        recent_packets = []
        
        # Белый список сетей (Google, Cloudflare, Akamai, Fastly, Microsoft)
        whitelist_networks = [
            '8.8.8.8', '1.1.1.1', '8.8.4.4',
            '74.125.', '173.194.', '172.217.', '64.233.', '142.251.',
            '108.177.', '34.160.', '34.107.', '34.49.',
            '151.101.', '150.171.', '23.35.', '20.44.',
            '13.107.', '13.33.', '3.174.'
        ]
        
        while self.monitoring:
            try:
                packet = self.packet_queue.get(timeout=1)
                packet_count += 1
                
                # Сохраняем в историю
                recent_packets.append(packet)
                if len(recent_packets) > 500:
                    recent_packets.pop(0)
                
                # Логируем пакет в БД
                packet_id = self.db.log_packet(packet)
                
                src_ip = packet.get('src_ip', 'Unknown')
                dst_ip = packet.get('dst_ip', 'Unknown')
                payload = packet.get('payload', '').lower()
                dst_port = packet.get('dst_port', 0)
                
                # ===== ПРОВЕРКА БЕЛОГО СПИСКА =====
                is_whitelisted = False
                for network in whitelist_networks:
                    if src_ip.startswith(network):
                        is_whitelisted = True
                        break
                
                # Легитимные порты
                if dst_port in [80, 443, 53, 22, 8080, 8443, 123]:
                    is_whitelisted = True
                
                # Локальные IP тоже пропускаем
                if src_ip.startswith(('10.', '192.168.', '172.')):
                    is_whitelisted = True
                
                if is_whitelisted:
                    if packet_count % 200 == 0:
                        self.log_message(f"[INFO] Белый список: пропущен {src_ip}:{dst_port}", "gray")
                    continue
                
                # == СИГНАТУРНЫЙ АНАЛИЗ ==
                attack_detected = False
                attack_type = "Normal"
                signature_score = 0.0
                
                sql_patterns = ["' or '1'='1", "'or'1'='1", "union select", "drop table", "1=1'"]
                for pattern in sql_patterns:
                    if pattern in payload:
                        attack_detected = True
                        attack_type = "SQL Injection"
                        signature_score = 0.95
                        break
                
                if not attack_detected:
                    xss_patterns = ["<script>", "javascript:", "onerror=", "alert("]
                    for pattern in xss_patterns:
                        if pattern in payload:
                            attack_detected = True
                            attack_type = "XSS Attack"
                            signature_score = 0.92
                            break
                
                if not attack_detected:
                    cmd_patterns = ["; ls", "; cat", "| whoami", "`id`"]
                    for pattern in cmd_patterns:
                        if pattern in payload:
                            attack_detected = True
                            attack_type = "Command Injection"
                            signature_score = 0.93
                            break
                
                # == ML АНАЛИЗ (только если нет сигнатурной атаки) ==
                if not attack_detected and self.anomaly_detector and self.anomaly_detector.is_trained and self.ml_mode_var.get() == "detect":
                    ml_anomaly, ml_score, confidence = self.anomaly_detector.detect(packet, recent_packets)
                    
                    if ml_anomaly and confidence > 0.7:
                        attack_detected = True
                        attack_type = "ML Anomaly"
                        signature_score = ml_score
                        self.log_message(f"[ML] Аномалия от {src_ip}: score={ml_score:.3f}, уверенность={confidence:.2f}", "cyan")
                
                # == ОБУЧЕНИЕ (если нет модели) ==
                if self.anomaly_detector and not self.anomaly_detector.is_trained and self.ml_mode_var.get() != "detect":
                    trained = self.anomaly_detector.add_packet_to_buffer(packet)
                    if trained:
                        self.log_message("[ML] Модель обучена на собранных данных! Переключитесь в режим Detect.", "green")
                        self.root.after(0, lambda: self.ml_mode_var.set("detect"))
                
                # == РЕАКЦИЯ НА АТАКУ ==
                if attack_detected and src_ip not in ['Unknown', '127.0.0.1', '::1']:
                    self.root.after(0, lambda ip=src_ip, at=attack_type, sc=signature_score, pid=packet_id: 
                                   self.add_alert(ip, at, sc, pid))
                    self.log_message(f"[ALERT] {attack_type} от {src_ip} (score: {signature_score:.2f})", "orange")
                
                # Обновляем счётчик пакетов
                if packet_count % 100 == 0:
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
        self.start_time = time.time()
        
        # Сброс счётчиков
        self.stats = {
            'packets_total': 0,
            'anomalies_detected': 0,
            'attacks_blocked': 0,
            'blacklisted_ips': set()
        }
        
        self.capture_thread = threading.Thread(target=self.packet_capture_worker, daemon=True)
        self.analysis_thread = threading.Thread(target=self.analyze_packet_worker, daemon=True)
        
        self.capture_thread.start()
        self.analysis_thread.start()
        
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_label.config(text="● Monitoring Active", foreground="green")
        self.train_btn.config(state=tk.NORMAL)
        
        # Очищаем старые алерты
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        
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
        self.train_btn.config(state=tk.DISABLED)
        
        self.log_message("[INFO] Система мониторинга остановлена", "yellow")
    
    def update_gui(self):
        """Периодическое обновление GUI"""
        db_stats = self.db.get_stats()
        self.packets_label.config(text=f"Packets: {db_stats[0]}")
        self.alerts_label.config(text=f"Alerts: {db_stats[1]}")
        self.blocked_label.config(text=f"Blocked: {db_stats[2]}")
        
        self.root.after(100, self.update_gui)


def main():
    """Точка входа"""
    root = tk.Tk()
    app = DarkTraceLight(root)
    
    def on_closing():
        if app.monitoring:
            app.stop_monitoring()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()


if __name__ == "__main__":
    if sys.platform.startswith('linux') and os.geteuid() != 0:
        print("\n" + "="*60)
        print("⚠️  ВНИМАНИЕ: Для захвата реального трафика нужны root права")
        print("   Запустите: sudo python3 main.py")
        print("="*60 + "\n")
    
    main()