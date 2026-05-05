# src/__init__.py
from .packet_capture import RealPacketCapture
from .anomaly_detector import AnomalyDetector

__all__ = ['RealPacketCapture', 'AnomalyDetector']


print("[DEBUG] Инициализация менеджера белого списка...")
if WHITELIST_AVAILABLE:
    try:
        self.whitelist_manager = WhitelistManager()
        wl_data = self.whitelist_manager.get_all()
        self.log_message(f"[WHITELIST] Загружено {len(wl_data['ips'])} IP и {len(wl_data['networks'])} сетей", "gray")
    except Exception as e:
        print(f"[ERROR] Ошибка WhitelistManager: {e}")
        self.whitelist_manager = None
else:
    self.whitelist_manager = None