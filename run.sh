#!/bin/bash
# DarkTrace Light - Запуск программы

# Переход в директорию скрипта
cd "$(dirname "$0")"

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "     DarkTrace Light - Network IDS"
echo "=========================================="
echo ""

# Проверка прав root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}⚠️  Ошибка: Программа требует root права!${NC}"
    echo -e "${YELLOW}Запустите: sudo ./run.sh${NC}"
    exit 1
fi

# Проверка виртуального окружения
if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}📦 Виртуальное окружение не найдено. Создаём...${NC}"
    python3 -m venv .venv
    echo -e "${GREEN}✅ Виртуальное окружение создано${NC}"
fi

# Активация и установка зависимостей
echo -e "${YELLOW}📦 Проверка зависимостей...${NC}"
source .venv/bin/activate
pip install -q -r requirements.txt

echo -e "${GREEN}✅ Готово!${NC}"
echo ""

# Запуск
echo -e "${GREEN}▶ Запуск DarkTrace Light...${NC}"
python main.py