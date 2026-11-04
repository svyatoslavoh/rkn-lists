# Списки заблокированных в РФ доменов и подсетей

Готовые текстовые списки для раздельного туннелирования на роутере: всё, что в них, — отправлять в VPN, остальное напрямую.

## Файлы

| Файл | Что внутри | Строк |
|---|---|---|
| `rkn-domains.txt` | домены, по одному в строке, без схем и путей | ~73 600 |
| `rkn-ips.txt` | подсети IPv4 в формате CIDR, схлопнутые | ~18 100 |
| `rkn-domains-lite.txt` | только крупные сервисы (YouTube, Telegram, Instagram, Discord, WhatsApp и т.д.) — для слабых роутеров | ~160 |

## Что вырезано

Казино, ставки, покер, взрослое, дейтинг, аптечная рассылка, торренты и даркнет-маркетплейсы. Остальное оставлено как есть — это выжимка реестра, а не «самые популярные сайты».

## Источники

- домены — [1andrevich/Re-filter-lists](https://github.com/1andrevich/Re-filter-lists) (`domains_all.lst`), обновляется сообществом по реестру;
- подсети — [antifilter.download](https://antifilter.download) (`ipsum.lst`).

Список не «истина в последней инстанции»: реестр меняется ежедневно, а часть блокировок идёт через ТСПУ без записи в реестр — такие адреса сюда не попадают.

## Как использовать

**Keenetic / OpenWrt / MikroTik**: загрузить домены как список для маршрутизации по домену, подсети — как список адресов. В Keenetic это «Маршруты → Списки», в OpenWrt — `ipset`/`nftset` + dnsmasq, в MikroTik — `address-list`.

**dnsmasq на OpenWrt** (домены через ipset):

```sh
# /etc/dnsmasq.conf
ipset=/youtube.com/googlevideo.com/telegram.org/vpn
```

Списком целиком удобнее через `dnsmasq-full` + скрипт, который читает `rkn-domains.txt` и делает `nftset`.

## Обновление

Списки собраны скриптом `build.py` (в этом же репозитории): он качает источники, нормализует, фильтрует мусор, схлопывает подсети и пишет файлы заново.

```sh
python3 build.py .
```

Раз в неделю достаточно. Дату сборки смотрите в коммите.

## Ссылки для роутера

```
https://raw.githubusercontent.com/svyatoslavoh/rkn-lists/main/rkn-domains.txt
https://raw.githubusercontent.com/svyatoslavoh/rkn-lists/main/rkn-ips.txt
https://raw.githubusercontent.com/svyatoslavoh/rkn-lists/main/rkn-domains-lite.txt
```
