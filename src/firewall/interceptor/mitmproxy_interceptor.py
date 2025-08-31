import asyncio
import json
import re

from datetime import datetime

from mitmproxy import options, http
from mitmproxy.tools import dump

from src.common.id_utils import generate_log_id
from src.firewall.logger.log_models import HttpLog
from src.firewall.logger.logger import Logger
from src.firewall.policy.policy import Policy
from src.firewall.policy.policy_models import HttpPolicy


class MitmproxyInterceptor:
    def __init__(
        self, logger: Logger, policy: Policy, listen_host="127.0.0.1", listen_port=8080
    ):
        self.logger = logger
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.policies = policy.policies
        self.is_running = False

    async def request(self, flow: http.HTTPFlow):
        if not flow.request.url.endswith([".png", ".jpeg"]):
            http_log = parse_http_request(flow)
            for policy_name, policy_info in self.policies["http"].items():
                if matches_policy(flow, policy_info):
                    http_log.action = "blocked"
                    http_log.reason = "Blocked by " + policy_info.reason
                    self.logger.http(http_log)
                    # 요청을 차단하고 HTTP 403 상태 코드 반환
                    flow.response = http.Response.make(
                        403,  # 상태 코드 403 (접근 금지)
                        b"<h1>Access Denied Blocked Domain</h1>"  # 응답 본문: 차단된 도메인 메시지
                        b"<img src='https://http.cat/403'/>",  # 403 상태를 나타내는 이미지
                        {"Content-Type": "text/html"},  # 응답 헤더 설정 (HTML 콘텐츠)
                    )
                    return
        self.logger.http(http_log)

    import requests

    # 미리 차단 이미지 다운로드 (외부 요청 최소화)
    block_image_bytes = requests.get(
        "https://http.cat/403", proxies={"http": None, "https": None}
    ).content

    async def response(self, flow: http.HTTPFlow):
        content_type = flow.response.headers.get("Content-Type", "").lower()
        for policy_name, policy_info in self.policies["http"].items():
            if matches_policy(flow, policy_info):
                if content_type.startswith("image/jpeg") or content_type.startswith(
                    "image/png"
                ):
                    flow.response.content = self.block_image_bytes
        if content_type.startswith("application/javascript") or content_type.startswith(
            "text/javascript"
        ):
            from src.assistant.ollama_analyzer import ollama_vulnerability_check

            asyncio.create_task(ollama_vulnerability_check(flow, self.logger))
        pass

    async def _run(self):
        self.is_running = True
        opts = options.Options(
            listen_host=self.listen_host, listen_port=self.listen_port
        )
        master = dump.DumpMaster(
            opts,
            with_termlog=False,
            with_dumper=False,
        )
        master.addons.add(self)
        await master.run()

    def start(self):
        asyncio.create_task(self._run())


def parse_http_request(flow: http.HTTPFlow) -> HttpLog:
    content_type = flow.request.headers.get("Content-Type", "").lower()
    body = flow.request.content

    # Content-Type에 따라 처리
    if "application/json" in content_type:
        try:
            body = json.loads(body.decode("utf-8", "ignore"))
        except json.JSONDecodeError:
            body = "Invalid JSON format"
    elif "text/" in content_type or "application/x-www-form-urlencoded" in content_type:
        body = body.decode("utf-8", "ignore")
    else:
        body = f"Unsupported content type: {content_type}"

    # HTTPLog 객체 생성
    log = HttpLog(
        id=generate_log_id(),
        timestamp=datetime.fromtimestamp(flow.request.timestamp_start).isoformat(),
        source="mitmproxy",
        action="capture",
        protocol=flow.request.scheme,
        method=flow.request.method,
        url=flow.request.url,
        reason="Captured by mitmproxy",
        headers=str(flow.request.headers),
        body=body,  # 위에서 처리한 body
        threat_result=None,
        threat=None,
    )
    return log


# 요청이 HttpPolicy와 부합하는지 확인하는 함수
def matches_policy(flow: http.HTTPFlow, policy: HttpPolicy) -> bool:
    # 모든 조건이 부합하는지 체크하기 위한 변수
    match = True

    # 메서드 비교 (정규 표현식 적용)
    if policy.method is not None and policy.method != flow.request.method:
        match = False

    # URL 비교 (정규 표현식 적용)
    if policy.url is not None and not re.search(policy.url, flow.request.url):
        match = False

    # 헤더 비교 (정규 표현식 적용)
    if policy.headers is not None:
        content_type = flow.request.headers.get("Content-Type", "")
        if not re.search(policy.headers, content_type):
            match = False

    # 본문 비교 (정규 표현식 적용)
    if policy.body is not None:
        body_content = flow.request.content.decode("utf-8", "ignore")
        if not re.search(policy.body, body_content):
            match = False

    # 모든 조건이 부합하면 True 반환
    return match
