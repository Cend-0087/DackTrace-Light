#!/usr/bin/env python3
"""
Anomaly Detection Module using Isolation Forest
Обнаружение аномалий в сетевом трафике с помощью машинного обучения
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from collections import deque
import time
import pickle
import sqlite3
from pathlib import Path

class AnomalyDetector:
    """Детектор аномалий на основе Isolation Forest"""
    
    def __init__(self, contamination=0.01, max_samples=256):
        """
        Инициализация детектора
        contamination: ожидаемая доля аномалий в данных (0.05 = 5%)
        max_samples: максимальное количество образцов для обучения
        """
        self.contamination = contamination
        self.max_samples = max_samples
        self.model = None
        self.is_trained = False
        self.training_buffer = deque(maxlen=1000)
        self.training_samples_needed = 500  # Увеличил до 500 пакетов
        self.feature_names = [
            'packet_length_log',
            'payload_ratio',
            'packet_rate',
            'is_uncommon_port',
            'is_tcp',
            'has_dangerous_keywords'
        ]
        
    def extract_features(self, packet, recent_packets):
        """
        Извлечение признаков из пакета и истории
        Возвращает вектор признаков для ML модели
        """
        features = []
        
        # 1. Длина пакета (логарифмическая шкала, чтобы учитывать и мелкие и крупные)
        length = packet.get('length', 0)
        features.append(min(np.log1p(length) / 8.0, 1.0))
        
        # 2. Соотношение размера payload к размеру пакета
        payload_len = len(packet.get('payload', ''))
        payload_ratio = payload_len / (length + 1)
        features.append(min(payload_ratio, 1.0))
        
        # 3. Частота пакетов за секунду (для обнаружения DoS)
        packet_rate = self.calculate_packet_rate(recent_packets)
        features.append(min(packet_rate / 50.0, 1.0))
        
        # 4. Нестандартный порт (не 80,443,53,22,8080)
        dst_port = packet.get('dst_port', 0)
        is_uncommon_port = 1.0 if dst_port not in [80, 443, 53, 22, 8080, 3306, 5432, 25, 110] else 0.0
        features.append(is_uncommon_port)
        
        # 5. Флаг TCP (большинство аномалий - TCP)
        protocol = packet.get('protocol', 0)
        is_tcp = 1.0 if protocol == 6 else 0.0
        features.append(is_tcp)
        
        # 6. Содержит ли payload опасные ключевые слова
        payload = packet.get('payload', '').lower()
        dangerous_keywords = [
            '<script', 'javascript:', 'eval(', 'onerror=',
            'union select', 'drop table', 'or 1=1', "' or '",
            'exec(', 'system(', '; ls', '| whoami', '`id`',
            '../', '..\\'
        ]
        has_dangerous = 1.0 if any(kw in payload for kw in dangerous_keywords) else 0.0
        features.append(has_dangerous)
        
        return np.array(features).reshape(1, -1)
    
    def calculate_packet_rate(self, packets):
        """Частота пакетов за последнюю секунду"""
        if not packets:
            return 0
        now = time.time()
        recent = [p for p in packets if now - p.get('timestamp', 0) < 1.0]
        return len(recent)
    
    def is_whitelisted(self, ip, dst_port):
        """Проверка, не является ли IP/порт легитимным"""
        # Google, Cloudflare, Akamai, Fastly, Microsoft
        whitelist_networks = [
            '8.8.8.8', '1.1.1.1',
            '74.125.', '173.194.', '172.217.', '64.233.', '142.251.',
            '108.177.', '34.160.', '34.107.', '34.49.',
            '151.101.', '150.171.', '23.35.', '20.44.'
        ]
        
        for network in whitelist_networks:
            if ip.startswith(network):
                return True
        
        # Легитимные порты
        if dst_port in [80, 443, 53, 8080, 8443]:
            return True
        
        return False
    
    def add_packet_to_buffer(self, packet):
        """Добавление пакета в буфер для обучения"""
        features = self.extract_features(packet, [])
        self.training_buffer.append((packet, features))
        
        if not self.is_trained and len(self.training_buffer) >= self.training_samples_needed:
            self.train_model()
            return True
        return False
    
    def train_model(self):
        """Обучение модели Isolation Forest на накопленных данных"""
        print(f"[ML] Обучение модели на {len(self.training_buffer)} образцах...")
        
        X_train = []
        for packet, _ in list(self.training_buffer):
            # Извлекаем признаки с историей
            recent = [p for p, _ in list(self.training_buffer)[-50:]]
            features = self.extract_features(packet, recent)
            X_train.append(features.flatten())
        
        if len(X_train) < self.training_samples_needed:
            print(f"[ML] Недостаточно данных: {len(X_train)} < {self.training_samples_needed}")
            return False
        
        X_train = np.array(X_train)
        
        self.model = IsolationForest(
            contamination=self.contamination,
            max_samples=self.max_samples,
            random_state=42,
            n_estimators=100
        )
        
        self.model.fit(X_train)
        self.is_trained = True
        
        # Сохраняем модель
        model_path = Path(__file__).parent.parent / "models"
        model_path.mkdir(exist_ok=True)
        with open(model_path / "isolation_forest.pkl", 'wb') as f:
            pickle.dump(self.model, f)
        
        print(f"[ML] Модель обучена! Аномалии: {self.contamination*100:.1f}%")
        return True
    
    def train_from_database(self, db_path, num_packets=2000, exclude_attacks=True):
        """
        Обучение модели на исторических данных из БД
        db_path: путь к файлу SQLite
        num_packets: сколько пакетов использовать для обучения
        exclude_attacks: исключать ли пакеты, связанные с атаками
        """
        print(f"[ML] Загрузка {num_packets} пакетов из БД для обучения...")
        
        try:
            conn = sqlite3.connect(db_path)
            
            if exclude_attacks:
                # Берём пакеты, которые не привели к алертам
                query = '''
                    SELECT src_ip, dst_ip, src_port, dst_port, protocol, length, payload 
                    FROM packets 
                    WHERE id NOT IN (SELECT DISTINCT packet_id FROM alerts WHERE packet_id IS NOT NULL)
                    ORDER BY timestamp DESC
                    LIMIT ?
                '''
            else:
                query = '''
                    SELECT src_ip, dst_ip, src_port, dst_port, protocol, length, payload 
                    FROM packets 
                    ORDER BY timestamp DESC
                    LIMIT ?
                '''
            
            cur = conn.execute(query, (num_packets,))
            rows = cur.fetchall()
            conn.close()
            
            if len(rows) < 100:
                print(f"[ML] Недостаточно данных в БД: {len(rows)} < 100")
                return False
            
            # Преобразуем в список словарей
            packets = []
            for row in rows:
                packets.append({
                    'src_ip': row[0],
                    'dst_ip': row[1],
                    'src_port': row[2],
                    'dst_port': row[3],
                    'protocol': row[4],
                    'length': row[5],
                    'payload': row[6] or ''
                })
            
            # Извлекаем признаки
            X_train = []
            for i, packet in enumerate(packets):
                # Для каждого пакета используем предыдущие как историю
                recent = packets[max(0, i-50):i] if i > 0 else []
                features = self.extract_features(packet, recent)
                X_train.append(features.flatten())
            
            X_train = np.array(X_train)
            
            # Обучаем модель
            self.model = IsolationForest(
                contamination=self.contamination,
                max_samples=self.max_samples,
                random_state=42,
                n_estimators=100
            )
            
            self.model.fit(X_train)
            self.is_trained = True
            
            # Сохраняем модель
            model_path = Path(__file__).parent.parent / "models"
            model_path.mkdir(exist_ok=True)
            with open(model_path / "isolation_forest.pkl", 'wb') as f:
                pickle.dump(self.model, f)
            
            print(f"[ML] Модель обучена на {len(rows)} пакетах из БД!")
            print(f"[ML] Размерность признаков: {X_train.shape[1]}")
            return True
            
        except Exception as e:
            print(f"[ML] Ошибка обучения из БД: {e}")
            return False
    
    def detect(self, packet, recent_packets):
        """
        Обнаружение аномалии
        Возвращает: (is_anomaly, anomaly_score, confidence)
        """
        if not self.is_trained:
            return False, 0.0, 0.0
        
        try:
            features = self.extract_features(packet, recent_packets)
            prediction = self.model.predict(features)[0]
            scores = self.model.score_samples(features)
            anomaly_score = scores[0]
            
            # Нормализуем в [0,1], где 1 - очень аномально
            normalized_score = 1.0 / (1.0 + np.exp(-anomaly_score))
            
            is_anomaly = (prediction == -1)
            
            # Уверенность на основе отклонения от порога
            if is_anomaly:
                confidence = min(abs(anomaly_score) / 0.3, 1.0)
            else:
                confidence = 0.5
            
            return is_anomaly, normalized_score, confidence
            
        except Exception as e:
            print(f"[ML] Ошибка обнаружения: {e}")
            return False, 0.0, 0.0
    
    def load_model(self, model_path=None):
        """Загрузка обученной модели"""
        if not model_path:
            model_path = Path(__file__).parent.parent / "models" / "isolation_forest.pkl"
        
        if Path(model_path).exists():
            try:
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
                self.is_trained = True
                print(f"[ML] Модель загружена из {model_path}")
                return True
            except Exception as e:
                print(f"[ML] Ошибка загрузки модели: {e}")
        return False
    
    def get_model_info(self):
        """Информация о модели"""
        if not self.is_trained:
            return "Модель не обучена"
        return f"Isolation Forest | Аномалии: {self.contamination*100:.1f}% | Признаков: {len(self.feature_names)}"