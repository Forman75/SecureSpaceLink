# Secure Space‑Link Emulator

**Моделирование атак на каналы передачи данных в системах дистанционного зондирования Земли**

Этот проект реализует программную модель передачи данных между спутником и наземной станцией с возможностью эмуляции атак типа `tampering`, `drop` и `inject`, а также с применением криптографической защиты (AES‑256‑GCM и HMAC‑SHA256).

---

## 📌 Назначение

Данный эмулятор разработан в рамках научной работы для моделирования угроз информационной безопасности в космических системах дистанционного зондирования.

Он позволяет:

- Эмулировать типичные атаки «Man-in-the-Middle»
- Включать/отключать шифрование и проверку целостности
- Исследовать битовую ошибку (BER) и визуальные искажения изображения
- Генерировать графики и сравнивать защищённые и незащищённые каналы

---

## ⚙️ Возможности

- 📦 Tamper / Drop / Inject атаки
- 🔐 AES-256 шифрование (режим GCM)
- 🔑 Контроль целостности HMAC-SHA256
- 🖼️ Визуализация оригинального и искажённого изображения
- 📊 Расчёт BER, вывод графиков

---

## 🚀 Быстрый запуск

```bash
pip install -r requirements.txt
python main.py --gui
```
