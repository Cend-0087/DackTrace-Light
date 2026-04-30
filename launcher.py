#!/usr/bin/env python3
"""
Launcher for DarkTrace Light with GUI password prompt
"""

import subprocess
import os
import sys
from pathlib import Path

# Получаем путь к проекту
PROJECT_DIR = Path(__file__).parent
PYTHON_PATH = PROJECT_DIR / ".venv" / "bin" / "python"
MAIN_PATH = PROJECT_DIR / "main.py"

# Команда для запуска
cmd = f'pkexec env DISPLAY={os.environ.get("DISPLAY", ":0")} XAUTHORITY={os.environ.get("XAUTHORITY", "")} {PYTHON_PATH} {MAIN_PATH}'

# Запуск с графическим диалогом пароля
try:
    subprocess.run(cmd, shell=True, check=True)
except subprocess.CalledProcessError as e:
    print(f"Ошибка запуска: {e}")
    input("Нажмите Enter для выхода...")