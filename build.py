#!/usr/bin/env python3
"""Сборка списков заблокированных в РФ доменов и подсетей для роутера.

Источники (обновляются сообществом):
  - 1andrevich/Re-filter-lists — domains_all.lst (выжимка реестра, без мусора)
  - antifilter.download — ipsum.lst (подсети)
Всё нормализуется, фильтруется от казино/взрослого/фармы, дедуплицируется.
"""
import ipaddress
import re
import sys
import urllib.request

REF_DOMAINS = "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/domains_all.lst"
AF_IPS = "https://antifilter.download/list/ipsum.lst"

# то, что владелец просил не тащить: казино, ставки, взрослое, аптечная рассылка
JUNK = re.compile(
    r"(casino|kazino|казино|bet[0-9]|betting|bookmaker|poker|slot[sz]?[0-9-]|jackpot|roulette|"
    r"gambl|1xbet|mostbet|melbet|leonbet|pin-up|pinup|vulkan|joycasino|playfortuna|"
    r"porn|xxx|xhamster|xvideos|pornhub|brazzers|redtube|youporn|hentai|nude|escort|"
    r"adult|sexy?[0-9-]|sex[0-9-]|intim|prostitut|"
    r"viagra|cialis|levitra|pharmacy|aptek|лекарств|"
    r"dating|hookup|onlyfans|fansly|stripchat|bongacams|chaturbate|"
    r"torrent|torlink|rutracker|nnmclub|rutor|"
    r"hydra|kraken|blacksprut|mega[-.]?dark|onion)",
    re.I,
)

# крупные сервисы, которые точно нужны в списке раздельного туннелирования
CURATED = """
youtube.com
youtu.be
googlevideo.com
ytimg.com
yt3.ggpht.com
youtube-nocookie.com
youtubei.googleapis.com
ggpht.com
telegram.org
t.me
telegram.me
tdesktop.com
telesco.pe
telegram.dog
instagram.com
cdninstagram.com
facebook.com
fbcdn.net
fb.com
fbsbx.com
twitter.com
x.com
twimg.com
t.co
discord.com
discord.gg
discordapp.com
discordapp.net
discord.media
whatsapp.com
whatsapp.net
signal.org
whispersystems.org
reddit.com
redd.it
redditmedia.com
linkedin.com
licdn.com
medium.com
patreon.com
soundcloud.com
spotify.com
proton.me
protonmail.com
tutanota.com
mastodon.social
threads.net
bsky.app
bbc.com
bbc.co.uk
dw.com
meduza.io
svoboda.org
golosameriki.com
currenttime.tv
torproject.org
github.io
""".strip().split()

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def fetch(url, timeout=180):
    req = urllib.request.Request(url, headers={"User-Agent": "rkn-lists/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def norm_domain(raw):
    s = raw.strip().strip('"\'') .lower()
    if not s or s.startswith("#"):
        return None
    s = re.sub(r"^[a-z]+://", "", s)
    s = s.split("/")[0].split(":")[0].strip(".")
    if s.startswith("*."):
        s = s[2:]
    if not s or " " in s or "_" in s:
        return None
    if not DOMAIN_RE.match(s):
        return None
    if any(ch.isdigit() for ch in s.split(".")[-1]):
        return None  # IP-адрес, не домен
    return s


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "lists"

    print("качаю домены…", flush=True)
    dom_raw = fetch(REF_DOMAINS).splitlines()

    doms, skipped_junk, skipped_bad = set(), 0, 0
    for line in dom_raw:
        d = norm_domain(line)
        if not d:
            skipped_bad += 1
            continue
        if JUNK.search(d):
            skipped_junk += 1
            continue
        doms.add(d)

    curated_added = 0
    for d in CURATED:
        if not JUNK.search(d) and d not in doms:
            doms.add(d)
            curated_added += 1

    print("качаю подсети…", flush=True)
    ips_raw = fetch(AF_IPS).splitlines()
    nets = set()
    for line in ips_raw:
        s = line.strip().strip('"\'')
        if not s or s.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            continue
        if net.version != 4 or net.is_private or net.is_loopback or net.is_link_local:
            continue
        nets.add(net)

    def write(name, items):
        path = f"{out_dir}/{name}"
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(items) + "\n")
        print(f"{path}: {len(items)} строк")

    # схлопываем подсети: 1.2.3.0/24 + 1.2.3.0/25 → 1.2.3.0/24
    collapsed = list(ipaddress.collapse_addresses(sorted(nets, key=lambda n: (n.version, int(n.network_address), n.prefixlen))))

    write("rkn-domains.txt", sorted(doms))
    write("rkn-ips.txt", [str(n) for n in collapsed])

    # компактный набор для слабых роутеров: только крупные сервисы
    lite = sorted(d for d in doms if any(d == c or d.endswith("." + c) for c in CURATED))
    write("rkn-domains-lite.txt", lite)

    print(f"отброшено мусора: {skipped_junk}, невалидных: {skipped_bad}, "
          f"добавлено вручную: {curated_added}")


if __name__ == "__main__":
    main()
