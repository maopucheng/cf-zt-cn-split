import requests
import os
import re
import ipaddress

CF_API_TOKEN = os.getenv("CF_API_TOKEN")
ACCOUNT_ID   = os.getenv("CF_ACCOUNT_ID")
PROFILE_ID   = os.getenv("CF_PROFILE_ID", "")
MODE         = os.getenv("MODE", "exclude")  # exclude=CN直连 | include=只有CN走WARP
ALLOWED_MODES = {"exclude", "include"}

if not all([CF_API_TOKEN, ACCOUNT_ID]):
    raise ValueError("缺少环境变量！请在 GitHub Secrets 设置 CF_API_TOKEN、CF_ACCOUNT_ID")

if MODE not in ALLOWED_MODES:
    raise ValueError(f"非法 MODE: {MODE}，只允许 {'/'.join(sorted(ALLOWED_MODES))}")

HEADERS = {
    "Authorization": f"Bearer {CF_API_TOKEN}",
    "Content-Type": "application/json"
}

MAX_RULES       = 4000
TARGET_DOMAIN_N = 0  # 期望域名条数，剩余配额给 IP

# 合法域名正则：只保留标准域名格式，过滤脏数据
VALID_DOMAIN_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

# 域名：Loyalsoldier 精选直连域名
DOMAIN_URL = "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/direct.txt"

# IP：GeoIP2-CN
IP_URL = "https://raw.githubusercontent.com/soffchen/GeoIP2-CN/release/CN-ip-cidr.txt"

# 备用 IP 数据源
# IPdeny aggregated (~2200 条):
#   https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone
# metowolf/iplist (~1700 条):
#   https://raw.githubusercontent.com/metowolf/iplist/master/data/special/china.txt


def get_cn_cidrs():
    """从GeoIP2-CN 拉取聚合的 CN CIDR 列表"""
    r = requests.get(IP_URL, timeout=30)
    r.raise_for_status()
    cidrs = [line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith('#')]
    networks = [ipaddress.ip_network(cidr, strict=True) for cidr in cidrs]
    if not networks or any(network.prefixlen == 0 or not network.is_global for network in networks):
        raise ValueError("CN IP 数据源为空或包含非公网网段，停止更新")
    cidrs = list(dict.fromkeys(str(network) for network in networks))
    print(f"   IP 数据源获取到 {len(cidrs)} 条 CIDR")
    return cidrs


def get_cn_domains():
    """从 Loyalsoldier/surge-rules 拉取精选 CN 直连域名列表，过滤非法格式"""
    r = requests.get(DOMAIN_URL, timeout=30)
    r.raise_for_status()
    domains = []
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # 兼容 DOMAIN-SUFFIX,xxx 格式
        if line.startswith('DOMAIN-SUFFIX,'):
            line = line.replace('DOMAIN-SUFFIX,', '').strip()
        # 去掉前导点（如 .baidu.com → baidu.com）
        line = line.lstrip('.')
        # 只保留合法域名格式，过滤脏数据
        if line and VALID_DOMAIN_RE.match(line):
            domains.append(f"*.{line}")
    unique = list(set(domains))
    print(f"   域名数据源获取到 {len(unique)} 条域名（已过滤非法格式）")
    return unique


def update_split_tunnels(cidrs, domains):
    if PROFILE_ID:
        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{PROFILE_ID}/{MODE}"
    else:
        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{MODE}"

    current = requests.get(url, headers=HEADERS, timeout=30)
    current.raise_for_status()
    payload = current.json()
    if not payload.get("success") or not isinstance(payload.get("result"), list):
        raise ValueError("无法读取当前分流规则，停止更新")
    # 仅替换本脚本管理的规则，保留局域网及用户已有的排除条目。
    preserved = [
        {key: entry[key] for key in ("address", "host", "description") if entry.get(key) is not None}
        for entry in payload["result"]
        if entry.get("description") not in {"CN IP", "CN Domain"}
    ]
    # 动态分配配额：域名取 TARGET_DOMAIN_N 条，剩余给 IP
    max_domains = min(TARGET_DOMAIN_N, len(domains))
    max_ips     = min(MAX_RULES - max_domains, len(cidrs))

    # 域名规则在前（DNS 层优先命中），IP 规则在后（网络层兜底）
    domain_entries = [{"host":    d,    "description": "CN Domain"} for d    in domains[:max_domains]]
    ip_entries     = [{"address": cidr, "description": "CN IP"}     for cidr in cidrs[:max_ips]]
    routes = preserved + domain_entries + ip_entries
    unique = {}
    for entry in routes:
        unique.setdefault((entry.get("address"), entry.get("host")), entry)
    routes = list(unique.values())

    print(f"   域名规则：{len(domain_entries)} 条 | IP 规则：{len(ip_entries)} 条 | 合计：{len(routes)} 条")

    if len(routes) > MAX_RULES:
        raise ValueError(f"规则总数 {len(routes)} 超过 {MAX_RULES}，保留现有配置并停止更新")

    if PROFILE_ID:
        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{PROFILE_ID}/{MODE}"
    else:
        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{MODE}"

    if len(cidrs) > max_ips:
        raise ValueError("CN IP 数据超出规则配额，停止更新，避免静默丢失网段")

    print(f"   保留原有规则：{len(preserved)} 条 | 最终合计：{len(routes)} 条")
    if os.getenv("DRY_RUN") == "1":
        print("预览完成，未写入 Cloudflare")
        return

    resp = requests.put(url, json=routes, headers=HEADERS, timeout=30)
    if resp.status_code in (200, 204):
        print(f"✅ 同步成功！{len(routes)} 条路由 | Mode: {MODE}")
    else:
        print(f"❌ 失败 {resp.status_code}: Cloudflare API 请求未成功")
        resp.raise_for_status()


if __name__ == "__main__":
    print("🔄 拉取最新 CN geo 数据...")
    cidrs   = get_cn_cidrs()
    domains = get_cn_domains() if TARGET_DOMAIN_N else []
    update_split_tunnels(cidrs, domains)
