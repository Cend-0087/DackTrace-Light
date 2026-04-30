import subprocess
import threading
import time
import os

class Firewall:
    @staticmethod
    def block_ip(ip, duration_seconds=300):
        """Реальная блокировка IP через iptables"""
        if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.'):
            print(f"[FW] Пропускаем локальный IP: {ip}")
            return False
        
        try:
            # Проверяем, существует ли уже правило
            check = subprocess.run(
                f"iptables -C INPUT -s {ip} -j DROP 2>/dev/null",
                shell=True
            )
            if check.returncode == 0:
                return True
            
            # Добавляем правило
            subprocess.run(
                f"iptables -I INPUT 1 -s {ip} -j DROP",
                shell=True, check=True
            )
            print(f"[FW] IP {ip} заблокирован на {duration_seconds}с")
            
            # Автоматическая разблокировка
            def unblock():
                time.sleep(duration_seconds)
                subprocess.run(
                    f"iptables -D INPUT -s {ip} -j DROP 2>/dev/null",
                    shell=True
                )
                print(f"[FW] IP {ip} разблокирован")
            
            threading.Thread(target=unblock, daemon=True).start()
            return True
            
        except Exception as e:
            print(f"[FW] Ошибка блокировки {ip}: {e}")
            return False
    
    @staticmethod
    def unblock_ip(ip):
        """Ручная разблокировка"""
        try:
            subprocess.run(f"iptables -D INPUT -s {ip} -j DROP", shell=True)
            return True
        except:
            return False
    
    @staticmethod
    def get_blocked_ips():
        """Список реально заблокированных IP"""
        result = subprocess.run(
            "iptables -L INPUT -n 2>/dev/null | grep DROP | awk '{print $4}'",
            shell=True, capture_output=True, text=True
        )
        return [line.strip() for line in result.stdout.split('\n') if line.strip()]