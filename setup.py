#!/usr/bin/env python3
"""
Setup script for DarkTrace Light
Установка программы как пакета
"""

from setuptools import setup, find_packages

# Читаем requirements.txt если есть
with open("requirements.txt", "r") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    # Имя пакета (будет видно в pip list)
    name="darktrace-light",
    
    # Версия
    version="1.0.0",
    
    # Автор
    author="Your Name",
    description="Open Source Network Anomaly Detection System",
    
    # Какие папки включать в пакет
    packages=find_packages(),
    
    # Зависимости
    install_requires=requirements,
    
    # Точка входа (команда для запуска)
    entry_points={
        "console_scripts": [
            "darktrace = main:main",  # darktrace -> вызовет main() из main.py
        ],
    },
    
    # Метаданные
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.8",
)