#!/bin/bash
# DarkTrace Light - Установка

cd "$(dirname "$0")"

echo "=========================================="
echo "     DarkTrace Light - Установка"
echo "=========================================="

# Проверка Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 не установлен!"
    echo "Установите: sudo apt install python3 python3-venv python3-pip"
    exit 1
fi

# Создание venv
echo "📦 Создание виртуального окружения..."
python3 -m venv .venv
source .venv/bin/activate

# Установка зависимостей
echo "📦 Установка зависимостей..."
pip install --upgrade pip
pip install -r requirements.txt

# Создание скрипта запуска
cat > darktrace << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
sudo .venv/bin/python main.py
EOF
chmod +x darktrace

echo ""
echo "✅ Установка завершена!"
echo ""
echo "Для запуска: ./darktrace"
echo "Или: sudo ./run.sh"