# 🚫 IP Blocklist

[![Aggregate](https://img.shields.io/github/actions/workflow/status/TestingAvail/ipblocklist/update-ip.yml?branch=main&label=aggregate&logo=github-actions)](https://github.com/TestingAvail/ipblocklist/actions/workflows/update-ip.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Автоматически собираемый список IPv4-адресов и подсетей из публичных источников угроз: сканеры, ботнеты, брутфорс, Tor exit-узлы и диапазоны bogon. Используется для блокировки на уровне фаервола.

## 📥 Скачивание

Файлы публикуются в папке `public/` и в релизах репозитория:

| Файл | Содержимое |
| :--- | :--- |
| `public/ips.txt` | Один IP или CIDR на строку |
| `public/ips.txt.sha256` | Контрольная сумма `ips.txt` |

```bash
curl -sSL -o ips.txt https://raw.githubusercontent.com/TestingAvail/ipblocklist/main/public/ips.txt
curl -sSL -o ips.txt.sha256 https://raw.githubusercontent.com/TestingAvail/ipblocklist/main/public/ips.txt.sha256
sha256sum -c ips.txt.sha256
```

## 🚀 Пример использования с ipset

```bash
ipset create blocklist hash:net -exist
while read -r entry; do
    ipset add blocklist "$entry" -exist
done < ips.txt
iptables -I INPUT -m set --match-set blocklist src -j DROP
```

Перед применением на боевом сервере проверьте список в режиме логирования (`-j LOG`) и добавьте в исключения свои подсети.

## ⚙️ Как это работает

1. Workflow `.github/workflows/update-ip.yml` запускается каждый день в 03:15 UTC, при пуше в `main` и вручную.
2. Скрипт скачивает 12 источников: AS Network List, Spamhaus DROP, FireHOL level 1, Emerging Threats, CINS Score, Tor bulk exit list, blocklist.de, DShield, Feodo Tracker, GreenSnow, Team Cymru fullbogons и Binary Defense.
3. Из всех файлов извлекаются IPv4-адреса и CIDR-подсети, затем выполняется дедупликация и сортировка.
4. Удаляются служебные диапазоны `0.0.0.0/8`, `0.0.0.0/32` и `127.0.0.0/8`.
5. Результат сохраняется в `public/ips.txt`, коммитится в репозиторий и публикуется в релизе и на GitHub Pages.

## ⚠️ Ложные срабатывания

Блокировка по IP может задеть легитимные сервисы. Облачные провайдеры и динамические IP часто переиспользуются, а компрометированный узел может позже оказаться у обычного пользователя. Перед использованием:

- тестируйте список в режиме логирования;
- исключайте свои подсети, внутренние диапазоны (RFC 1918) и инфраструктуру провайдера;
- учитывайте, что список включает bogon-диапазоны, поэтому часть адресов может не использоваться в интернете вовсе.

## 🛠️ Локальный запуск

```bash
git clone https://github.com/TestingAvail/ipblocklist.git
cd ipblocklist
python3 - << 'EOF'
# см. блок "Generate and Aggregate IPs" в .github/workflows/update-ip.yml
EOF
```

Скрипт агрегации встроен прямо в workflow, отдельного файла нет.

## 📄 Лицензия

Распространяется под лицензией MIT. См. [LICENSE](LICENSE).
