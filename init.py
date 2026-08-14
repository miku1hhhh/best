#!/usr/bin/env python3
"""
自动爬取 Tracker 列表 → 查询指定种子的做种人数（缝合版）
支持从多个源获取 Tracker，并批量查询做种/下载人数
"""

import re
import socket
import struct
import random
import concurrent.futures
import requests
from urllib.parse import urlparse, parse_qs

# ---------- 用户配置 ----------
# Tracker 源列表（可任意增删）
TRACKER_SOURCES = [
    "https://cdn.jsdmirror.com/gh/XIU2/TrackersListCollection/best.txt",   # 你指定的源
    "https://cdn.jsdelivr.net/gh/ngosang/trackerslist@master/trackers_all.txt",
    "https://cdn.jsdelivr.net/gh/ngosang/trackerslist@master/trackers_all_ip.txt",
    "https://tracker.adysec.com/trackers_best.txt",
]

# 要查询的磁力链接（可换成任意种子）
MAGNET_LINK = "magnet:?xt=urn:btih:5c9f6cfc05f1a7ed5cd635eb66a7b67315c61c72&dn=ubuntu-22.04.5-desktop-amd64.iso"

# 超时与并发设置
HTTP_TIMEOUT = 8
UDP_TIMEOUT = 6
MAX_WORKERS = 20          # 并发数

# ---------- 核心逻辑 ----------
def extract_info_hash(magnet):
    match = re.search(r'xt=urn:btih:([a-fA-F0-9]{40})', magnet)
    if not match:
        raise ValueError("无法提取 info_hash")
    return match.group(1).lower()

INFO_HASH_HEX = extract_info_hash(MAGNET_LINK)
INFO_HASH_BIN = bytes.fromhex(INFO_HASH_HEX)
PEER_ID = b'-TR0000-000000000000'

# 从源爬取 Tracker
def fetch_trackers_from_url(url):
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        # 提取所有 http/https/udp 开头的 URL
        pattern = r'(https?://[^\s]+|udp://[^\s]+)'
        trackers = re.findall(pattern, resp.text)
        # 清理尾部逗号
        return [t.rstrip(',') for t in trackers]
    except Exception as e:
        print(f"⚠️ 获取 {url} 失败: {e}")
        return []

def fetch_all_trackers(sources):
    all_set = set()
    for src in sources:
        print(f"📥 爬取: {src}")
        trackers = fetch_trackers_from_url(src)
        print(f"   → 获取 {len(trackers)} 个")
        all_set.update(trackers)
    print(f"✅ 合并去重后共 {len(all_set)} 个 Tracker\n")
    return list(all_set)

# ---------- HTTP 查询（真实 info_hash） ----------
def query_http_tracker(url):
    try:
        from requests.utils import quote
        params = {
            "info_hash": INFO_HASH_BIN,
            "peer_id": PEER_ID,
            "port": 6881,
            "uploaded": 0,
            "downloaded": 0,
            "left": 0,
            "event": "started",
            "compact": 1,
        }
        query_parts = []
        for k, v in params.items():
            if isinstance(v, bytes):
                query_parts.append(f"{k}={quote(v, safe='')}")
            else:
                query_parts.append(f"{k}={v}")
        query_string = '&'.join(query_parts)
        parsed = urlparse(url)
        test_url = parsed._replace(query=query_string).geturl()

        resp = requests.get(test_url, timeout=HTTP_TIMEOUT,
                            headers={"User-Agent": "TrackerChecker/1.0"})
        if resp.status_code != 200:
            return None
        content = resp.content.rstrip(b'\r\n')
        try:
            import bencode
            data = bencode.bdecode(content)
        except:
            return None
        complete = data.get('complete', 0)
        incomplete = data.get('incomplete', 0)
        return (complete, incomplete)
    except:
        return None

# ---------- UDP 查询（完整 announce） ----------
def query_udp_tracker(url):
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 6969
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(UDP_TIMEOUT)
    try:
        # Connect
        protocol_id = 0x41727101980
        action = 0
        trans_id = random.randint(1, 0xFFFFFFFF)
        packet = struct.pack('>QII', protocol_id, action, trans_id)
        sock.sendto(packet, (host, port))
        data, _ = sock.recvfrom(65535)
        if len(data) < 16:
            return None
        resp_action, resp_tid, conn_id = struct.unpack('>IIQ', data[:16])
        if resp_action != 0 or resp_tid != trans_id:
            return None

        # Announce
        action = 1
        trans_id = random.randint(1, 0xFFFFFFFF)
        announce_packet = struct.pack('>QII20s20sQQQIIIHH',
            conn_id, action, trans_id,
            INFO_HASH_BIN, PEER_ID,
            0, 0, 0,      # downloaded, left, uploaded
            2, 0, random.randint(1, 0xFFFFFFFF), 50, 6881  # event, ip, key, num_want, port
        )
        sock.sendto(announce_packet, (host, port))
        data, _ = sock.recvfrom(65535)
        if len(data) < 20:
            return None
        resp_action, resp_tid = struct.unpack('>II', data[:8])
        if resp_action != 1 or resp_tid != trans_id:
            return None
        interval, leechers, seeders = struct.unpack('>III', data[8:20])
        return (seeders, leechers)
    except:
        return None
    finally:
        sock.close()

# ---------- 统一入口 ----------
def query_tracker(url):
    if url.startswith(('http://', 'https://')):
        return query_http_tracker(url)
    elif url.startswith('udp://'):
        return query_udp_tracker(url)
    else:
        return None

# ---------- 主程序 ----------
def main():
    print("🚀 自动爬取 Tracker 并查询种子做种人数\n")
    # 1. 爬取 Tracker
    trackers = fetch_all_trackers(TRACKER_SOURCES)
    if not trackers:
        print("❌ 未获取到任何 Tracker，请检查网络或源地址")
        return

    print(f"📋 共 {len(trackers)} 个 Tracker 待检测")
    print(f"🔍 查询种子: {MAGNET_LINK[:80]}...")
    print(f"📦 Info Hash: {INFO_HASH_HEX}\n")

    # 2. 并发查询
    results = []
    total = len(trackers)
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(query_tracker, url): url for url in trackers}
        for idx, future in enumerate(concurrent.futures.as_completed(future_to_url), 1):
            url = future_to_url[future]
            try:
                result = future.result()
                if result:
                    results.append((url, result[0], result[1]))
            except:
                pass
            if idx % 20 == 0 or idx == total:
                print(f"进度: {idx}/{total} ({idx/total*100:.1f}%)", end='\r')

    print("\n\n📊 查询完成！")
    print(f"成功获取到 {len(results)} 个 Tracker 的种子信息")
    if results:
        total_seeders = sum(r[1] for r in results)
        total_leechers = sum(r[2] for r in results)
        print(f"总做种人数（粗略总和）: {total_seeders}")
        print(f"总下载人数（粗略总和）: {total_leechers}")
        # 按做种人数降序显示
        sorted_res = sorted(results, key=lambda x: x[1], reverse=True)
        print("\n🏆 做种人数最多的 Tracker (Top 15):")
        for url, s, l in sorted_res[:15]:
            print(f"  {s:>4} 做种, {l:>4} 下载 -> {url}")
        # 保存所有结果到文件
        with open("seeders_results.txt", "w", encoding='utf-8') as f:
            f.write("做种人数\t下载人数\tTracker\n")
            for url, s, l in sorted_res:
                f.write(f"{s}\t{l}\t{url}\n")
        print("\n💾 全部结果已保存到 seeders_results.txt")
    else:
        print("⚠️ 没有获取到任何数据，可能种子冷门或网络问题。")

if __name__ == "__main__":
    main()
