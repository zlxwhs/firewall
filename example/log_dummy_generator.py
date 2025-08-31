import asyncio
import random
import time
import uuid
import json
import datetime
from dataclasses import asdict

import requests

from src.common.id_utils import generate_log_id
from src.firewall import config
from src.firewall.logger.log_models import HttpLog, Log, PacketLog

# ---------------------------
# 랜덤 데이터 유틸
# ---------------------------
COUNTRY_CODES = ["KR", "US", "CN", "JP", "DE", "FR", "GB", "RU", "IN", "BR"]
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]
PROTOCOLS = ["TCP", "UDP", "ARP", "ICMP"]
CONTENT_TYPES = [
    "application/json",
    "application/x-www-form-urlencoded",
    "text/plain",
    "text/html",
    "application/javascript",
    "application/xml",
    "text/css",
    "text/csv",
    "application/octet-stream",
]
THREAT_BASE = [
    "XSS 공격 가능성이 높습니다.",
    "SQL Injection 공격 가능성이 발견되었습니다.",
    "CSRF 취약점이 존재합니다.",
    "민감한 정보 노출 위험이 있습니다.",
    "사용자 입력 검증이 부족합니다.",
    "외부 라이브러리 취약점이 존재합니다.",
    "권한 상승 취약점 가능성이 있습니다.",
]

# ---------------------------
# 랜덤 생성 함수
# ---------------------------


def to_nanoseconds(timestamp_str):
    # ISO 8601 형식의 문자열을 datetime 객체로 변환
    timestamp = datetime.datetime.fromisoformat(timestamp_str)

    # 나노초 단위로 변환 (1970년 1월 1일을 기준으로 초로 계산한 후, 나노초로 변환)
    nanoseconds = int(timestamp.timestamp() * 1e9)
    return nanoseconds


def random_timestamp():
    now = datetime.datetime.now(datetime.UTC)
    delta_seconds = random.randint(0, 3600)  # 0~3600초 범위
    random_time = now - datetime.timedelta(seconds=delta_seconds)
    return random_time.isoformat()


def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def random_mac():
    return ":".join(f"{random.randint(0, 255):02X}" for _ in range(6))


def random_url():
    tlds = ["com", "net", "org", "io", "kr", "jp"]
    subdomain = random.choice(["api", "app", "service", "web", "data", "user", "admin"])
    domain = f"{subdomain}{random.randint(1, 10000)}.{random.choice(tlds)}"
    path_levels = random.randint(1, 5)
    path = "/" + "/".join(
        random.choice(
            [
                "login",
                "signup",
                "api",
                "data",
                "test",
                "vuln",
                "admin",
                "config",
                "profile",
                "dashboard",
            ]
        )
        for _ in range(path_levels)
    )
    query_count = random.randint(0, 5)
    query = "&".join(
        f"{random.choice(['id', 'q', 'user', 'token', 'page', 'item'])}={uuid.uuid4().hex[:8]}"
        for _ in range(query_count)
    )
    return f"http://{domain}{path}{('?' + query) if query else ''}"


def random_user_agent():
    os_versions = [f"Windows NT 10.{i}" for i in range(0, 100)] + [
        "Macintosh; Intel Mac OS X 13_5",
        "Linux; Android 14; Pixel 8",
    ]
    webkit = f"{random.randint(500, 650)}.{random.randint(0, 50)}"
    chrome = f"{random.randint(100, 150)}.0"
    return f"Mozilla/5.0 ({random.choice(os_versions)}; Win64; x64) AppleWebKit/{webkit} Chrome/{chrome} Safari/{webkit}"


def random_headers():
    headers = {
        "User-Agent": random_user_agent(),
        "Accept": random.choice(
            [
                "*/*",
                "application/json",
                "text/html",
                "application/javascript",
                "text/css",
            ]
        ),
        "Content-Type": random.choice(CONTENT_TYPES),
    }
    if random.random() < 0.4:
        headers["Authorization"] = f"Bearer {uuid.uuid4()}"
    if random.random() < 0.3:
        headers["X-Request-ID"] = generate_log_id()
    return json.dumps(headers)


def random_body(method: str, depth=0):
    if method not in ["POST", "PUT", "PATCH"]:
        return ""
    body = {}
    for _ in range(random.randint(2, 6)):
        key = f"field_{uuid.uuid4().hex[:4]}"
        if depth < 2 and random.random() < 0.3:
            body[key] = random_body(method, depth=depth + 1)
        elif random.random() < 0.2:
            body[key] = [
                str(uuid.uuid4().hex[: random.randint(4, 12)])
                for _ in range(random.randint(2, 5))
            ]
        else:
            body[key] = str(uuid.uuid4().hex[: random.randint(4, 12)])
    if random.random() < 0.5:
        return json.dumps(body)
    else:
        # x-www-form-urlencoded
        return "&".join(
            f"{k}={v}" if not isinstance(v, list) else "&".join(f"{k}={i}" for i in v)
            for k, v in body.items()
        )


def random_threat():
    level = random.choice([round(i * 0.1, 1) for i in range(0, 11)])
    base_msg = random.choice(THREAT_BASE)
    file_name = f"script_{random.randint(1, 5000)}.js"
    func_name = f"func_{random.randint(1, 2000)}"
    line_no = random.randint(1, 1000)
    analysis_msg = f"{base_msg} (파일: {file_name}, 함수: {func_name}, 라인: {line_no})"
    return level, f"위협도: {level}\n분석결과: {analysis_msg}"


# ---------------------------
# 로그 생성
# ---------------------------
def generate_http_log() -> HttpLog:
    method = random.choice(HTTP_METHODS)
    return HttpLog(
        id=generate_log_id(),
        timestamp=random_timestamp(),
        source="mitmproxy",
        action="capture",
        protocol="http",
        method=method,
        url=random_url(),
        reason="Captured by mitmproxy (dummy)",
        headers=random_headers(),
        body=random_body(method),
        threat=None,
        threat_result=None,
    )


def generate_http_block_log() -> HttpLog:
    method = random.choice(HTTP_METHODS)
    return HttpLog(
        id=generate_log_id(),
        timestamp=random_timestamp(),
        source="mitmproxy",
        action="blocked",
        protocol="http",
        method=method,
        url=random_url(),
        reason="Blocked by mitmproxy (dummy)",
        headers=random_headers(),
        body=random_body(method),
        threat=None,
        threat_result=None,
    )


def generate_packet_log() -> PacketLog:
    return PacketLog(
        id=generate_log_id(),
        timestamp=random_timestamp(),
        source="scapy",
        action="capture",
        protocol=random.choice(PROTOCOLS),
        src_ip=random_ip(),
        src_mac=random_mac(),
        dst_ip=random_ip(),
        dst_mac=random_mac(),
        src_port=random.randint(1024, 65535),
        dst_port=random.randint(1, 65535),
        reason="Captured by scapy (dummy)",
        # src_country=random.choice(COUNTRY_CODES),
        # dst_country=random.choice(COUNTRY_CODES),
    )


def generate_packet_block_log() -> PacketLog:
    return PacketLog(
        id=generate_log_id(),
        timestamp=random_timestamp(),
        source="scapy",
        action="blocked",
        protocol=random.choice(PROTOCOLS),
        src_ip=random_ip(),
        src_mac=random_mac(),
        dst_ip=random_ip(),
        dst_mac=random_mac(),
        src_port=random.randint(1024, 65535),
        dst_port=random.randint(1, 65535),
        reason="Blocked by scapy (dummy)",
        # src_country=random.choice(COUNTRY_CODES),
        # dst_country=random.choice(COUNTRY_CODES),
    )


def generate_threat_log() -> HttpLog:
    level, analysis = random_threat()
    return HttpLog(
        id=generate_log_id(),
        timestamp=random_timestamp(),
        source="mitmproxy",
        action="capture",
        protocol="http",
        method="GET",
        url=random_url(),
        reason="Analyzed by ollama (dummy)",
        headers='{"Content-Type":"application/javascript"}',
        body="function test(){alert('xss');}",
        threat=level,
        threat_result=analysis,
    )


# ---------------------------
# 비동기 전송
# ---------------------------
async def send_bulk_logs_async(count: int = 100000):
    logger = Logger()
    tasks = []
    for i in range(count):
        log_type = random.choices(
            [
                "http",
                "packet",
                "threat",
                "info",
                "warn",
                "error",
                "block_packet",
                "block_http",
            ],
            weights=[0.2, 0.2, 0.15, 0.15, 0.05, 0.05, 0.1, 0.1],
        )[0]

        if log_type == "http":
            tasks.append(asyncio.to_thread(logger.http, generate_http_log()))
        elif log_type == "packet":
            tasks.append(asyncio.to_thread(logger.packet, generate_packet_log()))
        elif log_type == "threat":
            tasks.append(asyncio.to_thread(logger.threat, generate_threat_log()))
        elif log_type == "block_packet":
            tasks.append(asyncio.to_thread(logger.threat, generate_packet_block_log()))
        elif log_type == "block_http":
            tasks.append(asyncio.to_thread(logger.threat, generate_http_block_log()))
        elif log_type == "info":
            tasks.append(asyncio.to_thread(logger.info, f"Dummy INFO event {i}"))
        elif log_type == "warn":
            tasks.append(asyncio.to_thread(logger.warn, f"Dummy WARN event {i}"))
        elif log_type == "error":
            tasks.append(asyncio.to_thread(logger.error, f"Dummy ERROR event {i}"))

        if i % 200 == 0:
            await asyncio.sleep(0.01)

    await asyncio.gather(*tasks)


# ---------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------


import json
import time
import requests


class Loki:
    def __init__(self, loki_origin: str = config.LOKI_ORIGIN, log_callback=None):
        self.loki_url = f"{loki_origin}/loki/api/v1/push"
        self.log_callback = log_callback

    def send_log(
        self,
        labels: dict[str, str],
        message: str,
        timestamp: int,
    ):
        headers = {"Content-Type": "application/json"}

        timestamp_ns = str(timestamp)

        # Loki 페이로드 구성
        loki_payload = {
            "streams": [
                {
                    "stream": labels,
                    "values": [[timestamp_ns, message]],
                }
            ]
        }

        response = requests.post(
            self.loki_url,
            headers=headers,
            data=json.dumps(loki_payload),
            proxies={"http": None, "https": None},  # 프록시 우회
        )
        response.raise_for_status()


class Logger:
    def __init__(self):
        self.send_ui_log: callable = None
        self.loki = Loki()

    def send_log(self, labels: dict, message: str, timestamp: int):
        self.loki.send_log(labels=labels, message=message, timestamp=timestamp)
        # self.send_ui_log(message[:400])

    def get_labels(self, log: Log, log_level: str) -> dict:
        return {
            "log_type": "packet",
            "level": log_level,
            "source": log.source,
            "protocol": log.protocol,
            "action": log.action,
        }

    def http(self, http: Log):
        labels = self.get_labels(http, log_level="http")
        self.send_log(labels, json.dumps(asdict(http)), to_nanoseconds(http.timestamp))

    def packet(self, packet: Log):
        labels = self.get_labels(packet, log_level="packet")
        self.send_log(
            labels, json.dumps(asdict(packet)), to_nanoseconds(packet.timestamp)
        )

    def block(self, packet: Log):
        labels = self.get_labels(packet, log_level="block")
        self.send_log(
            labels, json.dumps(asdict(packet)), to_nanoseconds(packet.timestamp)
        )

    def threat(self, threat: Log):
        labels = self.get_labels(threat, log_level="threat")
        self.send_log(
            labels, json.dumps(asdict(threat)), to_nanoseconds(threat.timestamp)
        )

    def policy(self, message: str):
        labels = {"log_type": "config", "level": "policy"}
        self.send_log(labels, message, to_nanoseconds(random_timestamp()))

    def info(self, message: str):
        labels = {"log_type": "event", "level": "info"}
        self.send_log(labels, message, to_nanoseconds(random_timestamp()))

    def warn(self, message: str):
        labels = {"log_type": "event", "level": "warn"}
        self.send_log(labels, message, to_nanoseconds(random_timestamp()))

    def error(self, message: str):
        labels = {"log_type": "event", "level": "error"}
        self.send_log(labels, message, to_nanoseconds(random_timestamp()))


# ---------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------

# ---------------------------
# 실행
# ---------------------------
if __name__ == "__main__":
    print("Sending 100,000+ highly diverse dummy logs to Grafana Loki...")
    asyncio.run(send_bulk_logs_async(count=1000))
    print("Done.")
