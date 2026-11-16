#!/usr/bin/env python3
"""Сборка списков для раздельного туннелирования на роутере (компактный набор).

Что собирается по умолчанию (маленькие файлы, нормально грузятся в роутер):

  rkn-domains-lite.txt — домены ключевых сервисов (YouTube, Telegram, Meta,
                          X, Discord, WhatsApp, ИИ-сервисы, взрослые сайты и т.д.)
  rkn-ips.txt          — подсети только этих сервисов (официальные диапазоны
                          Google/YouTube, Telegram, Meta, X, Discord, Cloudflare-край
                          в пределах реестра)

Полный набор реестра (десятки тысяч строк) собирается флагом --full:
  rkn-domains.txt      — все домены реестра
  rkn-ips-full.txt     — все подсети из antifilter

Источники:
  - 1andrevich/Re-filter-lists — domains_all.lst (выжимка реестра)
  - antifilter.download — ipsum.lst (подсети реестра)
  - gstatic goog.json — официальные диапазоны Google/YouTube
  - core.telegram.org/resources/cidr.txt — официальные диапазоны Telegram
  - stat.ripe.net — анонсированные префиксы AS (Meta, X, Discord, Telegram)
"""
import ipaddress
import json
import re
import sys
import urllib.request

REF_DOMAINS = "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/domains_all.lst"
AF_IPS = "https://antifilter.download/list/ipsum.lst"
GOOG_JSON = "https://www.gstatic.com/ipranges/goog.json"
TG_CIDR = "https://core.telegram.org/resources/cidr.txt"
RIPE_ASN = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"

# сервисы, чьи подсети тянем целиком (ASN)
SERVICE_ASN = {
    32934: "Meta (Facebook, Instagram, WhatsApp, Threads)",
    13414: "X (Twitter)",
    49581: "Discord",
    62041: "Telegram",
    59930: "Telegram",
}

# Cloudflare берём не целиком (тысячи префиксов на миллионы сайтов), а только те
# диапазоны, что попали в реестр блокировок — за ними ChatGPT, Claude и часть ИИ.
CF_ASN = 13335

JUNK = re.compile(
    r"(casino|kazino|казино|bet[0-9]|betting|bookmaker|poker|slot[sz]?[0-9-]|jackpot|roulette|"
    r"gambl|1xbet|mostbet|melbet|leonbet|pin-up|pinup|vulkan|joycasino|playfortuna|"
    r"viagra|cialis|levitra|pharmacy|aptek|лекарств|"
    r"dating|hookup|"
    r"torrent|torlink|rutracker|nnmclub|rutor|"
    r"hydra|kraken|blacksprut|mega[-.]?dark|onion)",
    re.I,
)

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
accounts.google.com
myaccount.google.com
accounts.youtube.com
oauth2.googleapis.com
www.googleapis.com
googleapis.com
gstatic.com
www.gstatic.com
ssl.gstatic.com
gvt1.com
gvt2.com
gvt3.com
dl.google.com
android.clients.google.com
play.google.com
devices.google.com
g.co
firebaseinstallations.googleapis.com
fcm.googleapis.com
googleusercontent.com
google-analytics.com
googletagmanager.com
google.com
google.ru
gemini.google.com
aistudio.google.com
generativelanguage.googleapis.com
alkalimakersuite-pa.clients6.google.com
notebooklm.google.com
chatgpt.com
chat.openai.com
api.openai.com
openai.com
claude.ai
api.anthropic.com
anthropic.com
copilot.microsoft.com
perplexity.ai
huggingface.co
grok.com
api.x.ai
poe.com
you.com
deepseek.com
pornhub.com
xvideos.com
xhamster.com
xnxx.com
xhamster2.com
redtube.com
youporn.com
brazzers.com
spankbang.com
eporner.com
txxx.com
beeg.com
hqporner.com
onlyfans.com
fansly.com
chaturbate.com
stripchat.com
bongacams.com
livejasmin.com
cam4.com
javhd.com
hentaihaven.xxx
e-hentai.org
nhentai.net
rule34.xxx
erome.com
motherless.com
literotica.com
""".strip().split()

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def fetch(url, timeout=180):
    req = urllib.request.Request(url, headers={"User-Agent": "rkn-lists/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def norm_domain(raw):
    s = raw.strip().strip('"\'').lower()
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
        return None
    return s


def asn_prefixes(asn):
    """Анонсированные IPv4-префиксы автономной системы (RIPE RIS)."""
    try:
        data = json.loads(fetch(RIPE_ASN.format(asn=asn), timeout=120))
    except Exception as e:
        print(f"  AS{asn}: не удалось получить ({e})", flush=True)
        return []
    out = []
    for item in data.get("data", {}).get("prefixes", []):
        p = item.get("prefix", "")
        if ":" in p:
            continue
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError:
            continue
        if net.version == 4 and not (net.is_private or net.is_loopback or net.is_link_local):
            out.append(net)
    print(f"  AS{asn}: {len(out)} префиксов", flush=True)
    return out


def collapse(nets):
    return list(ipaddress.collapse_addresses(
        sorted(set(nets), key=lambda n: (n.version, int(n.network_address), n.prefixlen))))


def write(path, items):
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(items) + "\n")
    print(f"{path}: {len(items)} строк", flush=True)


def main():
    out_dir = "lists"
    full = "--full" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if args:
        out_dir = args[0]

    print("качаю домены реестра…", flush=True)
    doms, skipped_junk, skipped_bad = set(), 0, 0
    try:
        for line in fetch(REF_DOMAINS).splitlines():
            d = norm_domain(line)
            if not d:
                skipped_bad += 1
                continue
            if JUNK.search(d):
                skipped_junk += 1
                continue
            doms.add(d)
    except Exception as e:
        print("  реестр доменов недоступен:", e, flush=True)

    for d in CURATED:
        if not JUNK.search(d):
            doms.add(d)

    lite = sorted(d for d in doms if any(d == c or d.endswith("." + c) for c in CURATED))
    # если реестр не скачался — lite всё равно соберётся из CURATED
    print(f"  доменов всего: {len(doms)}, в компактном наборе: {len(lite)}", flush=True)

    print("качаю подсети реестра…", flush=True)
    reg_nets = set()
    try:
        for line in fetch(AF_IPS).splitlines():
            s = line.strip().strip('"\'')
            if not s or s.startswith("#"):
                continue
            try:
                net = ipaddress.ip_network(s, strict=False)
            except ValueError:
                continue
            if net.version != 4 or net.is_private or net.is_loopback or net.is_link_local:
                continue
            reg_nets.add(net)
    except Exception as e:
        print("  реестр подсетей недоступен:", e, flush=True)
    print(f"  подсетей в реестре: {len(reg_nets)}", flush=True)

    print("качаю официальные диапазоны сервисов…", flush=True)
    svc = []
    try:
        goog = json.loads(fetch(GOOG_JSON))
        g4 = []
        for p in goog.get("prefixes") or []:
            if "ipv4Prefix" in p:
                try:
                    g4.append(ipaddress.ip_network(p["ipv4Prefix"], strict=False))
                except ValueError:
                    pass
        print(f"  Google: {len(g4)}", flush=True)
        svc += g4
    except Exception as e:
        print("  Google недоступен:", e, flush=True)
    try:
        tg = [ipaddress.ip_network(x.strip(), strict=False)
              for x in fetch(TG_CIDR).splitlines() if x.strip() and ":" not in x]
        print(f"  Telegram cidr.txt: {len(tg)}", flush=True)
        svc += tg
    except Exception as e:
        print("  Telegram недоступен:", e, flush=True)
    for asn in SERVICE_ASN:
        svc += asn_prefixes(asn)

    # Cloudflare только в пределах реестра — иначе в туннель уедет пол-интернета
    cf = [n for n in asn_prefixes(CF_ASN) if any(n.overlaps(r) for r in reg_nets)]
    print(f"  Cloudflare (только из реестра): {len(cf)}", flush=True)
    svc += cf

    write(f"{out_dir}/rkn-domains-lite.txt", lite)
    write(f"{out_dir}/rkn-ips.txt", [str(n) for n in collapse(svc)])

    if full:
        write(f"{out_dir}/rkn-domains.txt", sorted(doms))
        write(f"{out_dir}/rkn-ips-full.txt", [str(n) for n in collapse(reg_nets | set(svc))])

    print(f"отброшено мусора: {skipped_junk}, невалидных: {skipped_bad}", flush=True)


if __name__ == "__main__":
    main()
