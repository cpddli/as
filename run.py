#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cf-ip-scanner — 从 ASN 拉取 IP，masscan 扫描，检测 Cloudflare 反代节点
用法: python3 run.py AS209242 [AS3214 ...]
"""
import sys, os, subprocess, json, urllib.request, urllib.error, multiprocessing, socket, time, re, threading, ipaddress, random
import gzip, shutil
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── 🌟 自动检查与修复 Apt 依赖 🌟 ──
def install_apt_deps():
    """检测并自动安装 python3-maxminddb 依赖"""
    try:
        import maxminddb
    except ImportError:
        print("  ⚠️ 检测到缺少 maxminddb 依赖，正在尝试通过 apt 自动安装...")
        sudo = [] if os.geteuid() == 0 else ["sudo"]
        try:
            # 刷新 apt 并静默安装 python3-maxminddb
            subprocess.run(sudo + ["apt-get", "update", "-qq"], check=True)
            subprocess.run(sudo + ["apt-get", "install", "-y", "-qq", "python3-maxminddb"], check=True)
            print("  ✅ maxminddb 依赖安装成功！\n")
        except Exception as e:
            print(f"  ❌ 自动安装依赖失败: {e}")
            print("  请手动运行: sudo apt update && sudo apt install -y python3-maxminddb")
            sys.exit(1)

# 执行依赖检测
install_apt_deps()
import maxminddb

# ── 🌟 核心配置 🌟 ──
MASSCAN_RATE = 1000
CF_SCANNER_CONC = 40
API_CONCURRENT = 15
API_CHUNK = 300

BASE       = Path(__file__).parent.resolve()
CF_SCANNER = BASE / "cf-scanner"
VERIFY_PY  = BASE / "verify.py"
API_URL    = "https://api.250887.xyz/check"
TG_CONFIG_FILE = BASE / "tg_config.json"
TG_API_BASE    = "https://tg.250887.xyz"
# 彻底抛弃 Worker 接口，改为本地数据库

if CF_SCANNER.is_file():
    CF_SCANNER.chmod(0o755)

# ── 安全输入 ──
def safe_input(prompt_text):
    print(prompt_text, end='', flush=True)
    try:
        if not sys.stdin.isatty():
            try:
                with open("/dev/tty", "r") as tty:
                    return tty.readline().strip()
            except Exception:
                pass
        return input().strip()
    except (EOFError, KeyboardInterrupt):
        return ""

# ── 公网/局域网 IP 获取 ──
def get_public_ip():
    apis = [("https://api.ipify.org", 5), ("https://api-ipv4.ip.sb/ip", 5)]
    for url, timeout in apis:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            return urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8").strip()
        except Exception:
            continue
    return "127.0.0.1"

def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    return "127.0.0.1"

# ── Telegram 模块 ──
def load_tg_config():
    if TG_CONFIG_FILE.exists():
        try:
            with open(TG_CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"enabled": False, "token": "", "chat_id": ""}

def check_or_init_tg_config():
    if not TG_CONFIG_FILE.exists():
        print("  [Telegram Bot 设置]")
        choice = safe_input("  首次运行，是否绑定 Telegram Bot？(y/N，按回车跳过): ").lower()
        if choice == "y":
            token = safe_input("  请输入 TG Bot Token: ")
            chat_id = safe_input("  请输入 TG Chat ID: ")
            if token and chat_id:
                cfg = {"enabled": True, "token": token, "chat_id": chat_id}
                try:
                    with open(TG_CONFIG_FILE, "w", encoding="utf-8") as f:
                        json.dump(cfg, f, ensure_ascii=False, indent=2)
                    print("  ✅ Telegram Bot 绑定成功！\n")
                    return cfg
                except Exception:
                    pass
        cfg = {"enabled": False, "token": "", "chat_id": ""}
        try:
            with open(TG_CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
        return cfg
    return load_tg_config()

def send_tg_document(file_path, caption=""):
    cfg = load_tg_config()
    token, chat_id = cfg.get("token"), cfg.get("chat_id")
    if not token or not chat_id: return False
    url = f"{TG_API_BASE}/bot{token}/sendDocument"
    file_path = Path(file_path)
    if not file_path.exists(): return False
    
    print(f"  正在发送 [{file_path.name}] 至 Telegram...")
    try:
        cmd = ["curl", "-s", "-X", "POST", url, "-F", f"chat_id={chat_id}", "-F", f"document=@{file_path}"]
        if caption: cmd.extend(["-F", f"caption={caption}"])
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode == 0 and "\"ok\":true" in r.stdout.replace(" ", "").lower():
            print("  ✅ 成功发送文件至 Telegram！")
            return True
    except Exception:
        pass
    return False

# ── 🌟 自动管理离线数据库 (DB-IP) 🌟 ──
def ensure_local_mmdb():
    """检查本地数据库，若无或过期则自动下载最新月度版"""
    now = datetime.now()
    # 尝试当前月和上个月
    for i in range(2):
        # 针对 DB-IP 发布的月份格式调整
        target_date = now - timedelta(days=28 * i)
        ym_str = target_date.strftime("%Y-%m")
        filename = f"dbip-country-lite-{ym_str}.mmdb"
        mmdb_path = BASE / filename

        # 如果文件已存在，直接使用，清理旧版
        if mmdb_path.exists():
            for f in BASE.glob("dbip-country-lite-*.mmdb"):
                if f != mmdb_path:
                    try: f.unlink()
                    except: pass
            return mmdb_path

        url = f"https://download.db-ip.com/free/{filename}.gz"
        gz_path = BASE / f"{filename}.gz"

        print(f"  正在下载 {ym_str} 版离线 GeoIP 数据库 (约 10MB)...")
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as resp, open(gz_path, 'wb') as out_file:
                shutil.copyfileobj(resp, out_file)

            print("  解压中...")
            with gzip.open(gz_path, 'rb') as f_in, open(mmdb_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
            gz_path.unlink()

            print("  ✅ 离线数据库就绪！\n")
            # 清理旧版
            for f in BASE.glob("dbip-country-lite-*.mmdb"):
                if f != mmdb_path:
                    try: f.unlink()
                    except: pass
            return mmdb_path
            
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue # 当前月份未发布，尝试下载上个月的
            else:
                print(f"  ⚠️ 下载异常 ({e.code})")
        except Exception as e:
            print(f"  ⚠️ 下载网络错误: {e}")
            if gz_path.exists(): gz_path.unlink()
            
    print("  ❌ 无法获取离线 IP 库，跳过精准筛选。")
    return None

# ── Step 1: ASN → CIDR ──
def fetch_prefixes(asns):
    raw_cidrs = []
    API_DOMAIN = "https://as.250887.xyz"

    for asn in asns:
        url = f"{API_DOMAIN}/AS{asn}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        success = False
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    text = resp.read().decode('utf-8').strip()
                    lines = [line.strip() for line in text.splitlines() if line.strip() and ":" not in line]
                    raw_cidrs.extend(lines)
                    print(f"  AS{asn} → 获取到 {len(lines)} 个 IPv4 CIDR")
                    success = True
                    break
            except Exception:
                time.sleep(2)
        if not success:
            print(f"  ❌ AS{asn} → 获取失败，跳过。")

    if not raw_cidrs:
        raise ValueError("拉取到的 CIDR 数量为 0。")

    net_objs = [ipaddress.IPv4Network(c, strict=False) for c in raw_cidrs if ":" not in c]
    merged_nets = list(ipaddress.collapse_addresses(net_objs))
    
    # 拆解为 /24 精度，保障不漏查
    granular_nets = []
    for net in merged_nets:
        if net.prefixlen < 24:
            granular_nets.extend(list(net.subnets(new_prefix=24)))
        else:
            granular_nets.append(net)
            
    print(f"  去重并按 /24 拆分后共 {len(granular_nets)} 个 CIDR")

    print("\n" + "─" * 45)
    print(" 请选择 CIDR 范围模式：")
    print("  [1] 精准模式：本地离线 mmdb 秒级提取指定地区节点 (推荐)")
    print("  [2] 默认模式：保留全部 CIDR")
    print("─" * 45)
    
    choice = safe_input(" 请选择 (1/2，直接回车默认为 2): ").strip()

    if choice == "1":
        # 🌟 允许用户自由指定地区代码 🌟
        target_regions_input = safe_input(" 请输入要匹配的地区代码 (如 hk 或 jp,sg，按回车默认为 hk): ").strip().upper()
        if not target_regions_input:
            target_regions = {"HK"}
        else:
            target_regions = {r.strip() for r in target_regions_input.replace("，", ",").split(",") if r.strip()}

        mmdb_path = ensure_local_mmdb()
        if not mmdb_path:
            cidrs = [str(net) for net in merged_nets]
        else:
            print(f"\n  正在通过本地内存检索属于 {','.join(target_regions)} 的节点... (无需网络等待)")
            matched_nets = []
            
            with maxminddb.open_database(str(mmdb_path)) as reader:
                for net in granular_nets:
                    test_ip = str(net[1]) if net.num_addresses > 1 else str(net[0])
                    try:
                        res = reader.get(test_ip)
                        country = res.get("country", {}).get("iso_code", "") if res else ""
                        if country in target_regions:
                            matched_nets.append(net)
                    except Exception:
                        pass
            
            if matched_nets:
                matched_nets = list(ipaddress.collapse_addresses(matched_nets))
                cidrs = [str(net) for net in matched_nets]
                print(f"  ✅ 本地筛查完毕，提取出纯正 {','.join(target_regions)} CIDR: {len(cidrs)} 个")
            else:
                print(f"  ⚠️ 未检测到 {','.join(target_regions)} CIDR，恢复使用全部 CIDR")
                cidrs = [str(net) for net in merged_nets]
    else:
        print("\n  已跳过精筛，使用全部 CIDR")
        cidrs = [str(net) for net in merged_nets]

    cidr_file = BASE / "cidrs.txt"
    cidr_file.write_text("\n".join(cidrs))
    print(f"  ✅ 进入 masscan 的 CIDR: {len(cidrs)} 个\n")
    return cidrs

# ── 端口解析与扫描 ──
with open(BASE / "ports.txt") as f:
    _default_ports = [l.strip() for l in f if l.strip() and not l.startswith("#")]
DEFAULT_PORTS = ",".join(_default_ports)

def parse_ports(port_str):
    ports = set()
    for part in port_str.split(','):
        try:
            if '-' in part:
                a, b = part.split('-', 1)
                pa, pb = int(a), int(b)
                if pa < 1 or pb > 65535 or pa > pb: continue
                ports.update(str(p) for p in range(pa, pb + 1))
            elif part.isdigit() and 1 <= int(part) <= 65535:
                ports.add(part)
        except Exception:
            pass
    return ",".join(sorted(ports, key=int)) if ports else ""

def run_masscan(ports_str=None):
    ports = ports_str if ports_str and ports_str != "," else DEFAULT_PORTS
    result_file = BASE / "masscan_result.txt"
    ip_file = BASE / "cidrs.txt"

    if not ip_file.exists() or ip_file.stat().st_size == 0:
         raise ValueError("cidrs.txt 为空。")

    if result_file.exists():
        subprocess.run(["sudo", "rm", "-f", str(result_file)] if os.geteuid() != 0 else ["rm", "-f", str(result_file)], check=False)

    sudo = [] if os.geteuid() == 0 else ["sudo"]
    cmd = sudo + ["masscan", "-iL", str(ip_file), "-p", ports, "--rate", str(MASSCAN_RATE), "-oL", str(result_file), "--wait", "5"]
    print(f"  [运行 masscan] 速率: {MASSCAN_RATE} pps, 端口: {ports}")
    
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, bufsize=1)
    bar_width = 30
    last_pct = -1
    for line in proc.stderr:
        m = re.search(r"(\d+\.?\d*)%\s*done", line)
        if m:
            pct = min(float(m.group(1)), 100)
            if abs(pct - last_pct) >= 0.5:
                filled = int(bar_width * pct / 100)
                sys.stderr.write(f"\r  [{'█' * filled}{'░' * (bar_width - filled)}] {pct:.1f}%")
                sys.stderr.flush()
                last_pct = pct
    proc.wait()
    if proc.returncode == 0:
        sys.stderr.write(f"\r  [{'█' * bar_width}] 100.0%\n")
    else:
        raise subprocess.CalledProcessError(proc.returncode, cmd)

    if os.geteuid() != 0:
        subprocess.run(["sudo", "chown", f"{os.getuid()}:{os.getgid()}", str(result_file)], check=False)

    parsed_lines = []
    with open(result_file) as src:
        for line in src:
            if line.startswith("open"):
                parts = line.strip().split()
                parsed_lines.append(f"{parts[3]}:{parts[2]}\n")
    
    random.shuffle(parsed_lines)
    with open(result_file, "w") as dst:
        dst.writelines(parsed_lines)
        
    print(f"  开放端口: {len(parsed_lines)} (已乱序)")
    return len(parsed_lines)

def cf_scan():
    new_file, hits_file = BASE / "masscan_result.txt", BASE / "cf_hits.txt"
    if hits_file.exists(): hits_file.unlink()
    if not new_file.exists() or new_file.stat().st_size == 0: return 0
    if not os.access(CF_SCANNER, os.X_OK): os.chmod(CF_SCANNER, 0o755)

    proc = subprocess.Popen([str(CF_SCANNER), "-i", str(new_file), "-o", str(hits_file), "-c", str(CF_SCANNER_CONC)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    bar_width, last_pct = 30, -1
    for line in proc.stdout:
        m = re.search(r"Scanned\s+\d+/(\d+)\s+\((\d+\.?\d*)%\)", line)
        if m:
            pct = min(float(m.group(2)), 100)
            if abs(pct - last_pct) >= 0.5:
                filled = int(bar_width * pct / 100)
                sys.stderr.write(f"\r  [{'█' * filled}{'░' * (bar_width - filled)}] {pct:.1f}%")
                sys.stderr.flush()
                last_pct = pct
    proc.wait()
    sys.stderr.write(f"\r  [{'█' * bar_width}] 100.0%\n" if proc.returncode == 0 else "\n")
    sys.stderr.flush()
    hits = sum(1 for _ in open(hits_file)) if hits_file.exists() else 0
    print(f"  CF 节点: {hits}")
    return hits

def api_verify():
    hits_file, verified_file = BASE / "cf_hits.txt", BASE / "verified.txt"
    if verified_file.exists(): verified_file.unlink()
    if not hits_file.exists() or hits_file.stat().st_size == 0: return 0

    print(f"  正在请求 API 精筛 (并发: {API_CONCURRENT}, 块大小: {API_CHUNK})...")
    proc = subprocess.Popen([
        "python3", "-u", str(VERIFY_PY), "--input", str(hits_file), "--output", str(verified_file),
        "--api", API_URL, "--chunk", str(API_CHUNK), "--concurrent", str(API_CONCURRENT)
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    bar_width, passed_count = 30, 0
    for line in proc.stdout:
        line = line.strip()
        m_pct = re.search(r"(\d+\.?\d*)%", line)
        m_pass = re.search(r"(?:通过|passed)\s*(\d+)", line, re.IGNORECASE)
        m_count = re.search(r"\((\d+)/(\d+)\)", line)

        if m_pct:
            pct = min(float(m_pct.group(1)), 100.0)
            filled = int(bar_width * pct / 100)
            if m_pass: passed_count = int(m_pass.group(1))
            status = f" ({m_count.group(1)}/{m_count.group(2)})" if m_count else ""
            sys.stderr.write(f"\r  [{'█' * filled}{'░' * (bar_width - filled)}] {pct:.1f}%{status} | 通过: {passed_count}{'':10}")
            sys.stderr.flush()

    proc.wait()
    sys.stderr.write(f"\r  [{'█' * bar_width}] 100.0% | 精筛完成{'':20}\n")
    sys.stderr.flush()
    passed = sum(1 for _ in open(verified_file)) if verified_file.exists() else 0
    print(f"  通过节点: {passed}")
    return passed

def speed_test():
    verified_file = BASE / "verified.txt"
    if not verified_file.exists(): return
    
    lines = [l.strip() for l in open(verified_file) if l.strip() and not l.startswith(("#", "IP地址"))]
    total = len(lines)
    if total == 0: return

    SPEED_TEST_CONC = 8
    print(f"  启动多线程并发测速中 (节点数: {total}, 并发:{SPEED_TEST_CONC})")
    results, tested = [], 0
    lock = threading.Lock()

    def _test_single(entry):
        parts = entry.split(",")
        if len(parts) < 7: return None
        ip, port = parts[0], parts[1]

        latency, speed_mbps = 0, 0
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            t0 = time.time()
            s.connect((ip, int(port)))
            latency = round((time.time() - t0) * 1000)
            s.close()
            
            r = subprocess.run([
                "curl", "--connect-to", f"speed.cloudflare.com:443:{ip}:{port}",
                "-o", "/dev/null", "-s", "-w", "%{speed_download}",
                "--connect-timeout", "5", "--max-time", "20",
                "https://speed.cloudflare.com/__down?bytes=10485760"
            ], capture_output=True, text=True, timeout=25)
            speed_mbps = round(float(r.stdout.strip() or 0) * 8 / 1000000, 2)
        except Exception:
            pass

        if len(parts) == 7:
            return f"{parts[0]},{parts[1]},{parts[2]},{parts[3]},{parts[4]},{parts[5]},{latency},{speed_mbps},{parts[6]}"
        elif len(parts) >= 9:
            parts[6], parts[7] = str(latency), str(speed_mbps)
            return ",".join(parts)
        return None

    with ThreadPoolExecutor(max_workers=SPEED_TEST_CONC) as executor:
        futures = {executor.submit(_test_single, line): line for line in lines}
        for future in as_completed(futures):
            res = future.result()
            if res: results.append(res)
            with lock:
                tested += 1
                pct = tested / total * 100
                filled = int(30 * pct / 100)
                sys.stderr.write(f"\r  [{'█' * filled}{'░' * (30 - filled)}] {pct:.1f}% | 进度: {tested}/{total} {'':5}")
                sys.stderr.flush()

    sys.stderr.write(f"\r  [{'█' * 30}] 100.0% | 测速完成: {total} 个节点{'':10}\n")
    with open(verified_file, "w") as f:
        f.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n" + "\n".join(results) + "\n")

def output_csv(asns):
    verified_file = BASE / "verified.txt"
    if not verified_file.exists() or verified_file.stat().st_size == 0: return None

    output = BASE / f"output_{'_'.join(asns)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    lines = []
    for line in open(verified_file):
        line = line.strip()
        if not line or line.startswith(("#", "IP地址")): continue
        parts = line.split(",")
        if len(parts) == 7: line = f"{parts[0]},{parts[1]},{parts[2]},{parts[3]},{parts[4]},{parts[5]},0,0,{parts[6]}"
        if line.count(",") >= 8: lines.append(line)

    with open(output, "w") as f:
        f.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n" + "\n".join(lines) + "\n")
    print(f"\n  结果: {len(lines)} 条 → {output.name}")

    lan_ip, port = get_lan_ip(), 8899
    while port < 9900:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if sock.connect_ex(('127.0.0.1', port)) != 0:
            sock.close()
            break
        sock.close()
        port += 1

    if port < 9900:
        print(f"\n  📥 下载链接 (按回车关闭):")
        print(f"  http://{lan_ip}:{port}/{output.name}  (本机)")
        public_ip = get_public_ip()
        if public_ip != "127.0.0.1" and public_ip != lan_ip:
            print(f"  http://{public_ip}:{port}/{output.name}  (公网)")
        
        server = subprocess.Popen(["python3", "-m", "http.server", str(port), "--directory", str(BASE)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        safe_input("\n")
        if server.poll() is None: server.terminate()
    return output

if __name__ == "__main__":
    check_or_init_tg_config()

    if len(sys.argv) < 2:
        raw = safe_input("  输入 ASN 编号 (多个用逗号分隔): ")
        if not raw: sys.exit(1)
        asns = [a.strip().replace("AS", "").replace("as", "") for a in raw.replace("，", ",").split(",") if a.strip()]
    else:
        args, i, asn_args = sys.argv[1:], 0, []
        while i < len(args):
            if args[i] == "-p": i += 2
            else: asn_args.append(args[i]); i += 1
        asns = [a.strip().replace("AS", "").replace("as", "") for a in ",".join(asn_args).replace("，", ",").split(",") if a.strip()]
        if not asns: sys.exit(1)
    
    pps = safe_input("  设置 masscan 速率 PPS (回车默认 1000): ")
    if pps.isdigit() and int(pps) > 0: MASSCAN_RATE = int(pps)

    print(f"\n  配置: masscan={MASSCAN_RATE}pps, cf-scanner={CF_SCANNER_CONC}c, API={API_CONCURRENT}c(块{API_CHUNK})")
    print(f"  ASN: {', '.join(f'AS{a}' for a in asns)}\n")

    scan_ports = DEFAULT_PORTS
    if len(sys.argv) < 2:
        port_in = safe_input(f"  回车使用默认({DEFAULT_PORTS})，或输入自定义端口: ")
        if port_in: scan_ports = parse_ports(port_in) or DEFAULT_PORTS
    else:
        for i, arg in enumerate(sys.argv[1:], 1):
            if arg == "-p" and i < len(sys.argv) - 1:
                scan_ports = parse_ports(sys.argv[i+1])
                break

    steps = [
        ("1/6 ASN→CIDR", lambda: fetch_prefixes(asns)),
        ("2/6 masscan", lambda: run_masscan(scan_ports)),
        ("3/6 cf-scanner", cf_scan),
        ("4/6 API精筛", api_verify),
    ]

    if safe_input("\n  是否测速？(y/n，默认跳过): ").lower() == "y":
        steps.append(("6/6 测速", speed_test))

    for label, fn in steps:
        print(f"\n  [{label}]")
        try: fn()
        except Exception as e:
            print(f"  ❌ 任务提前终止: {e}")
            sys.exit(1)

    result_csv = output_csv(asns)
    if result_csv and Path(result_csv).exists() and safe_input("\n  是否发送结果至 Telegram？(y/N，默认不发送): ").lower() == "y":
        send_tg_document(result_csv, caption=f"Cloudflare 节点扫描结果: {Path(result_csv).name}")

    print("\n✓ 完成\n")
