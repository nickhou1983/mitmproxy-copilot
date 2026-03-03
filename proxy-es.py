import asyncio
import json
import logging
import re
import time
from mitmproxy import http,ctx
from elasticsearch import Elasticsearch
from datetime import datetime
import base64
import functools
import redis # 导入Redis

# 通常仅需要修改这里的配置
# 初始化Elasticsearch客户端，如果Elasticsearch需要身份验证，可以在这里设置用户名和密码
ELASTICSEARCH_URL = "https://20.2.53.237:9200/"
ELASTICSEARCH_USERNAME = "admin"
ELASTICSEARCH_PASSWORD = ""

# 添加Redis连接
REDIS_HOST="democopilotredis.redis.cache.windows.net"
REDIS_PORT=6379
REDIS_PASSWORD=""

# 可配置：需要采集并写入 ES 的 Copilot URL 匹配规则（正则）
# 如需扩展，只需在此列表追加规则。
COPILOT_URL_PATTERNS = [
    # Chat/补全主链路
    r"complet",
    r"completion",
    r"api\.business\.githubcopilot\.com/.*",
    r"proxy\.business\.githubcopilot\.com/.*",
    r"api\.enterprise\.githubcopilot\.com/.*",
    r"proxy\.enterprise\.githubcopilot\.com/.*",

    # Copilot 鉴权与通知
    # r"api\.github\.com/copilot_internal/v2/token",
    # r"api\.github\.com/copilot_internal/notification",

    # 遥测链路
    # r"telemetry",
    # r"copilot-telemetry-service\.githubusercontent\.com/.*",
    # r"copilot-telemetry\.githubusercontent\.com/.*",
]


es = Elasticsearch(
    [ELASTICSEARCH_URL],
# ElasticSearch 不需要验证服务器证书   
    verify_certs=False,
# ElasticSearch 不需要用户名和密码
    http_auth=(ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD),
)


def is_copilot_target_url(url: str) -> bool:
    for pattern in COPILOT_URL_PATTERNS:
        if re.search(pattern, url):
            return True
    return False


def parseResContent(content: str) -> str:
    """
    解析 SSE (Server-Sent Events) 格式的 Copilot 响应，
    提取 choices[0].delta.content 或 choices[0].text，拼接为完整文本。
    """
    lines = content.strip().split('\n')
    content_string = ""
    for line in lines:
        json_str = line.replace("data: ", "").rstrip(',')
        if json_str == "[DONE]" or not json_str.strip():
            continue
        try:
            data_entry = json.loads(json_str)
            if data_entry.get('choices'):
                if 'delta' in data_entry['choices'][0] and data_entry['choices'][0]['delta'].get('content') is not None:
                    content_string += data_entry['choices'][0]['delta']['content']
                elif 'text' in data_entry['choices'][0]:
                    content_string += data_entry['choices'][0]['text']
        except json.JSONDecodeError:
            continue
    return content_string


class StreamSaver:
    """
    流式数据收集器。作为 mitmproxy 的 stream callback 使用，
    每收到一块数据就追加到 self.content，同时原样返回 data 保证实时转发。
    """

    def __init__(self, flow, direction: str):
        self.flow = flow
        self.direction = direction
        self.content = ""
        self._done = False

    def __call__(self, data: bytes) -> bytes:
        if len(data) == 0:
            self.done()
            return data
        if not self.flow or not self.flow.request:
            return data
        try:
            self.content += data.decode('utf-8', 'ignore')
        except Exception:
            logging.error("StreamSaver: Failed to decode data")
        return data

    def done(self):
        if self._done:
            return
        self._done = True
        self.flow = None


class AuthProxy:
    def __init__(self):
        self.loop = asyncio.get_event_loop()
        self.proxy_authorizations = {}
        self.redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True)
        # 用于暂存每个连接的流式收集器和计时信息
        self._req_streams = {}   # flow.id -> StreamSaver
        self._rsp_streams = {}   # flow.id -> StreamSaver
        self._req_timestamps = {} # flow.id -> start_time
    
    def http_connect(self, flow: http.HTTPFlow):
        proxy_auth = flow.request.headers.get("Proxy-Authorization", "")

        if proxy_auth.strip() == "" :
            self.proxy_authorizations[(flow.client_conn.address[0])] = ""
            # flow.response = http.Response.make(401)
            return
        try:
            auth_type, auth_string = proxy_auth.split(" ", 1)
            if auth_type.lower() != "basic":
                flow.response = http.Response.make(401)
                return
            auth_string = base64.b64decode(auth_string).decode("utf-8")
            username, password = auth_string.split(":", 1)
        except Exception:
            flow.response = http.Response.make(401)
            return

        # 从Redis中校验用户名和密码
        stored_password = self.redis_client.get(username)
        if stored_password is None:
            # 如果用户名不存在
            ctx.log.info("Username: " + username + " does not exist.")
            flow.response = http.Response.make(401)
        elif stored_password != password:
            # 如果密码不正确
            ctx.log.info("User: " + username + " attempted to log in with an incorrect password.")
            flow.response = http.Response.make(401)
        else:
            # 认证成功
            ctx.log.info("Authenticated: " + flow.client_conn.address[0])
            self.proxy_authorizations[(flow.client_conn.address[0])] = username
        
    def requestheaders(self, flow: http.HTTPFlow) -> None:
        """请求头到达时，开启请求体流式捕获"""
        req_stream = StreamSaver(flow, "req")
        flow.request.stream = req_stream
        self._req_streams[flow.id] = req_stream
        self._req_timestamps[flow.id] = time.time()

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        """响应头到达时，完成请求体收集，开启响应体流式捕获"""
        # 完成请求流收集
        req_stream = self._req_streams.get(flow.id)
        if isinstance(req_stream, StreamSaver):
            req_stream.done()

        # 开启响应体流式捕获
        rsp_stream = StreamSaver(flow, "rsp")
        flow.response.stream = rsp_stream
        self._rsp_streams[flow.id] = rsp_stream

    def response(self, flow: http.HTTPFlow) -> None:
        """响应完成时，收集所有数据并异步存储到 Elasticsearch"""
        # 完成响应流收集
        rsp_stream = self._rsp_streams.pop(flow.id, None)
        if isinstance(rsp_stream, StreamSaver):
            rsp_stream.done()

        req_stream = self._req_streams.pop(flow.id, None)
        start_time = self._req_timestamps.pop(flow.id, None)

        req_content = req_stream.content if req_stream else ""
        rsp_content = rsp_stream.content if rsp_stream else ""

        ctx.log.info("response: " + flow.request.url)
        asyncio.ensure_future(
            self.save_to_elasticsearch(flow, req_content, rsp_content, start_time)
        )

    def error(self, flow: http.HTTPFlow) -> None:
        """出错时清理流式收集器"""
        req_stream = self._req_streams.pop(flow.id, None)
        if isinstance(req_stream, StreamSaver):
            req_stream.done()
        rsp_stream = self._rsp_streams.pop(flow.id, None)
        if isinstance(rsp_stream, StreamSaver):
            rsp_stream.done()
        self._req_timestamps.pop(flow.id, None)

    async def save_to_elasticsearch(self, flow: http.HTTPFlow, req_content: str, rsp_content: str, start_time: float):
        ctx.log.info("url: " + flow.request.url)
        if is_copilot_target_url(flow.request.url):

            username = self.proxy_authorizations.get(flow.client_conn.address[0])
            end_time = time.time()
            timeconsumed = round((end_time - start_time) * 1000, 2) if start_time else 0
            timeconsumed_str = f"{timeconsumed}ms"

            ctx.log.info((username or "") + ":\t consumed time: " + timeconsumed_str + str(flow.request.headers.get("x-request-id")))

            # 对补全响应进行 SSE 解析，提取可读文本
            parsed_rsp = parseResContent(rsp_content)

            # 将请求和响应存储到Elasticsearch
            doc = {
                'user': username,
                "timestamp": datetime.utcnow().isoformat(),
                "proxy-time-consumed": timeconsumed_str,
                'request': {
                    'url': flow.request.url,
                    'method': flow.request.method,
                    'headers': dict(flow.request.headers),
                    'content': req_content,
                },
                'response': {
                    'status_code': flow.response.status_code,
                    'headers': dict(flow.response.headers),
                    'content': parsed_rsp if parsed_rsp else rsp_content,
                }
            }

            # 按照日期生成索引名称
            mitmproxy_index_name = f"mitmproxy-{datetime.utcnow().strftime('%Y-%m-%d')}"
            index_func = functools.partial(es.index, index=mitmproxy_index_name, body=doc)
            await self.loop.run_in_executor(None, index_func)
  

# 添加插件
addons = [
    AuthProxy()
]


