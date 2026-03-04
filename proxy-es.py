import asyncio
import concurrent.futures
import io
import logging
import re
import time
from mitmproxy import http, ctx
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk, BulkIndexError
from datetime import datetime
import base64
import functools
import redis.asyncio as aioredis  # 异步 Redis 客户端

# 通常仅需要修改这里的配置
# 初始化Elasticsearch客户端，如果Elasticsearch需要身份验证，可以在这里设置用户名和密码
ELASTICSEARCH_URL = "https://20.2.53.237:9200/"
ELASTICSEARCH_USERNAME = "admin"
ELASTICSEARCH_PASSWORD = ""

# 添加Redis连接
REDIS_HOST="democopilotredis.redis.cache.windows.net"
REDIS_PORT=10000
REDIS_PASSWORD=""

# 可配置：需要采集并写入 ES 的 Copilot URL 匹配规则（正则）
# 如需扩展，只需在此列表追加规则。
COPILOT_URL_PATTERNS = [
    # Chat/补全主链路
    r"complet",
    r"completion",
    r"api\.business\.githubcopilot\.com/.*",
    r"api\.enterprise\.githubcopilot\.com/.*",

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
    verify_certs=False,
    http_auth=(ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD),
)


def is_copilot_target_url(url: str) -> bool:
    for pattern in COPILOT_URL_PATTERNS:
        if re.search(pattern, url):
            return True
    return False


class StreamSaver:
    """
    流式数据收集器。作为 mitmproxy 的 stream callback 使用，
    每收到一块数据就写入 BytesIO 缓冲区，同时原样返回 data 保证实时转发。
    使用 BytesIO 替代字符串拼接，避免大请求体时 O(n²) 开销。
    """

    def __init__(self, flow, direction: str):
        self.flow = flow
        self.direction = direction
        self._buffer = io.BytesIO()
        self._done = False

    def __call__(self, data: bytes) -> bytes:
        if len(data) == 0:
            self.done()
            return data
        if not self.flow or not self.flow.request:
            return data
        try:
            self._buffer.write(data)
        except Exception:
            logging.error("StreamSaver: Failed to write data to buffer")
        return data

    def get_content(self) -> str:
        """获取已收集的全部内容（UTF-8 解码，忽略错误字符）"""
        return self._buffer.getvalue().decode('utf-8', 'ignore')

    def done(self):
        if self._done:
            return
        self._done = True
        self.flow = None


class AuthProxy:
    # --- ES Bulk 写入配置 ---
    ES_FLUSH_INTERVAL = 5       # 定时刷写间隔（秒）
    ES_FLUSH_SIZE = 100         # 单批最大文档数
    ES_MAX_BUFFER_SIZE = 5000   # 背压上限，超过则丢弃最旧文档
    # --- Auth 缓存配置 ---
    AUTH_TTL = 3600             # 认证缓存过期时间（秒）
    AUTH_CLEANUP_INTERVAL = 300 # 清理间隔（秒）

    def __init__(self):
        self.loop = asyncio.get_event_loop()

        # 认证缓存：{client_ip: (username, timestamp)}
        self.proxy_authorizations: dict[str, tuple[str, float]] = {}

        # 异步 Redis 客户端
        self.redis_client = aioredis.Redis(
            host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD,
            decode_responses=True, ssl=True,
        )

        # 用于暂存每个连接的流式收集器和计时信息
        self._req_streams: dict[str, StreamSaver] = {}    # flow.id -> StreamSaver
        self._req_timestamps: dict[str, float] = {}       # flow.id -> start_time

        # ES Bulk 写入队列及锁
        self._es_buffer: list[dict] = []
        self._es_lock = asyncio.Lock()

        # 专用 ES 写入线程池
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=8, thread_name_prefix="es"
        )

        # 启动后台任务
        asyncio.ensure_future(self._periodic_flush())
        asyncio.ensure_future(self._cleanup_auth_cache())

    # ==================== 认证 ====================

    async def http_connect(self, flow: http.HTTPFlow):
        """CONNECT 阶段：解析 Basic Auth 并通过异步 Redis 校验"""
        proxy_auth = flow.request.headers.get("Proxy-Authorization", "")

        if proxy_auth.strip() == "":
            self.proxy_authorizations[flow.client_conn.address[0]] = ("", time.time())
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

        # 从 Redis 中异步校验用户名和密码
        try:
            stored_password = await self.redis_client.get(username)
        except Exception as e:
            ctx.log.error(f"Redis connection error: {e}")
            flow.response = http.Response.make(503)
            return

        if stored_password is None:
            ctx.log.info("Username: " + username + " does not exist.")
            flow.response = http.Response.make(401)
        elif stored_password != password:
            ctx.log.info("User: " + username + " attempted to log in with an incorrect password.")
            flow.response = http.Response.make(401)
        else:
            ctx.log.info("Authenticated: " + flow.client_conn.address[0])
            self.proxy_authorizations[flow.client_conn.address[0]] = (username, time.time())
        
    # ==================== 流式处理钩子 ====================

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        """请求头到达时，开启请求体流式捕获"""
        req_stream = StreamSaver(flow, "req")
        flow.request.stream = req_stream
        self._req_streams[flow.id] = req_stream
        self._req_timestamps[flow.id] = time.time()

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        """响应头到达时，完成请求体收集，并启用响应流式透传"""
        req_stream = self._req_streams.get(flow.id)
        if isinstance(req_stream, StreamSaver):
            req_stream.done()

        # 启用响应体流式透传，避免先缓存在代理内存中
        flow.response.stream = (lambda data: data)

    def response(self, flow: http.HTTPFlow) -> None:
        """响应完成时，收集请求数据并异步入队到 ES 缓冲区"""
        req_stream = self._req_streams.pop(flow.id, None)
        start_time = self._req_timestamps.pop(flow.id, None)

        req_content = req_stream.get_content() if req_stream else ""

        ctx.log.info("response: " + flow.request.url)
        asyncio.ensure_future(
            self._enqueue_to_es(flow, req_content, start_time)
        )

    def error(self, flow: http.HTTPFlow) -> None:
        """出错时清理流式收集器"""
        req_stream = self._req_streams.pop(flow.id, None)
        if isinstance(req_stream, StreamSaver):
            req_stream.done()
        self._req_timestamps.pop(flow.id, None)

    # ==================== ES 写入 ====================

    async def _enqueue_to_es(self, flow: http.HTTPFlow, req_content: str, start_time: float):
        """构造文档并入队到 ES 缓冲区，达到阈值时触发批量写入"""
        if not is_copilot_target_url(flow.request.url):
            return

        client_ip = flow.client_conn.address[0]
        auth_entry = self.proxy_authorizations.get(client_ip)
        username = auth_entry[0] if auth_entry else None
        user_value = username or client_ip

        end_time = time.time()
        timeconsumed = round((end_time - start_time) * 1000, 2) if start_time else 0
        timeconsumed_str = f"{timeconsumed}ms"

        ctx.log.info(f"{user_value}:\t consumed time: {timeconsumed_str} {flow.request.headers.get('x-request-id')}")

        now = datetime.utcnow()
        doc = {
            '_index': f"mitmproxy-{now.strftime('%Y-%m-%d')}",
            '_source': {
                'user': user_value,
                'timestamp': now.isoformat(),
                'proxy-time-consumed': timeconsumed_str,
                'request': {
                    'url': flow.request.url,
                    'method': flow.request.method,
                    'headers': dict(flow.request.headers),
                    'content': req_content,
                },
            }
        }

        async with self._es_lock:
            # 背压：若缓冲区超限，丢弃最旧文档
            if len(self._es_buffer) >= self.ES_MAX_BUFFER_SIZE:
                discarded = len(self._es_buffer) - self.ES_MAX_BUFFER_SIZE + self.ES_FLUSH_SIZE
                del self._es_buffer[:discarded]
                ctx.log.warn(f"ES buffer overflow! Discarded {discarded} oldest docs.")
            self._es_buffer.append(doc)
            buffer_len = len(self._es_buffer)

        # 达到批量阈值时立即刷写
        if buffer_len >= self.ES_FLUSH_SIZE:
            await self._flush_to_es()

    async def _flush_to_es(self):
        """从缓冲区取出一批文档，执行 ES bulk 写入"""
        async with self._es_lock:
            if not self._es_buffer:
                return
            batch = self._es_buffer[:self.ES_FLUSH_SIZE]
            del self._es_buffer[:self.ES_FLUSH_SIZE]

        try:
            bulk_func = functools.partial(bulk, es, batch, raise_on_error=False)
            success, errors = await self.loop.run_in_executor(self._executor, bulk_func)
            if errors:
                ctx.log.error(f"ES bulk write: {success} succeeded, {len(errors)} failed")
                for err in errors[:5]:  # 只打印前 5 条错误
                    ctx.log.error(f"  ES error: {err}")
            else:
                ctx.log.info(f"ES bulk write: {success} docs indexed")
        except BulkIndexError as e:
            ctx.log.error(f"ES BulkIndexError: {len(e.errors)} errors")
        except Exception as e:
            ctx.log.error(f"ES bulk write failed: {e}")
            # 写入失败的文档放回队列头部（仅重试一次）
            async with self._es_lock:
                self._es_buffer = batch + self._es_buffer

    async def _periodic_flush(self):
        """后台定时刷写任务：每 ES_FLUSH_INTERVAL 秒检查缓冲区"""
        while True:
            await asyncio.sleep(self.ES_FLUSH_INTERVAL)
            try:
                await self._flush_to_es()
            except Exception as e:
                ctx.log.error(f"Periodic flush error: {e}")

    # ==================== Auth 缓存清理 ====================

    async def _cleanup_auth_cache(self):
        """后台任务：定期清理过期的认证缓存条目"""
        while True:
            await asyncio.sleep(self.AUTH_CLEANUP_INTERVAL)
            now = time.time()
            expired_keys = [
                k for k, (_, ts) in self.proxy_authorizations.items()
                if (now - ts) > self.AUTH_TTL
            ]
            for k in expired_keys:
                del self.proxy_authorizations[k]
            if expired_keys:
                ctx.log.info(f"Auth cache cleanup: removed {len(expired_keys)} expired entries")

    # ==================== 生命周期 ====================

    def done(self):
        """mitmproxy 关闭时：刷写剩余缓冲区、关闭资源"""
        # 同步刷写剩余文档
        if self._es_buffer:
            try:
                batch = self._es_buffer[:]
                self._es_buffer.clear()
                bulk(es, batch, raise_on_error=False)
                ctx.log.info(f"Final flush: {len(batch)} docs indexed")
            except Exception as e:
                ctx.log.error(f"Final flush failed: {e}")

        # 关闭线程池
        self._executor.shutdown(wait=False)
        ctx.log.info("AuthProxy shutdown complete")


# 添加插件
addons = [
    AuthProxy()
]


