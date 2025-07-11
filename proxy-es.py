import asyncio
from mitmproxy import http,ctx,connection,proxy
from elasticsearch import Elasticsearch
from datetime import datetime
import base64
import os
import json
import functools
import re
from functools import lru_cache
# import redis # 导入Redis

# 通常仅需要修改这里的配置

# URL白名单配置
URL_WHITELIST = [
    "https://github.com/login*",
    "https://github.com/login/oauth/*",
    "https://api.github.com/copilot_internal/*",
    "https://github.com/assets-cdn/worker/*",
    "https://default.exp-tas.com",
    "https://github.com/favicon.ico",
    "https://github.com/account/*",
    "https://github.com/session*",
    "https://copilot-proxy.githubusercontent.com",
    "https://origin-tracker.githubusercontent.com",
    "https://copilot-telemetry.githubusercontent.com/telemetry",
    "https://*.business.githubcopilot.com/*",
    "https://*.enterprise.githubcopilot.com/*",
    "https://github.com/settings/*",
    "https://avatars.githubusercontent.com/*",
    "https://api.github.com/*",
    "https://github.com/notifications/*",
    "https://github.com/copilot/*",
    "https://raw.githubusercontent.com/*",
    "https://github.githubassets.com/*",
    "https://collector.github.com/*",
    "https://github.com/github-copilot/*",
    "https://collector.github.com/*",
    # "https://github.com/dashboard/*",
    # "https://github.com/dashboard?*",
    "https://westus-0.in.applicationinsights.azure.com/v2.1/track",
    "https://api.githubcopilot.com/_ping",
    "*visualstudio.com*",
    "*vscode-cdn*",
    "*vsassets.io*",
    "*gallerycdn.azure*",
    "*microsoft.com*",
    "*raw.githubusercontent.com*",
    "*digicert.com*",
    "*vscode.dev*",
    "*jetbrains.com*",
    "*jbstatic.com*",
    "https://mitm.it/*",
]

# 初始化Elasticsearch客户端，如果Elasticsearch需要身份验证，可以在这里设置用户名和密码

ELASTICSEARCH_URL = "https://20.2.53.237:9200/"
ELASTICSEARCH_USERNAME = "admin"
ELASTICSEARCH_PASSWORD = "P@ssw0rddt01!"

# 添加Redis连接，由于代码中未使用Redis相关功能，暂时注释掉
# REDIS_HOST="localhost"
# REDIS_PORT=10000
# REDIS_PASSWORD= ""


es = Elasticsearch(
    [ELASTICSEARCH_URL],
# ElasticSearch 不需要验证服务器证书   
    verify_certs=False,
# ElasticSearch 不需要用户名和密码
    http_auth=(ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD),
)


class AuthProxy:
    def __init__(self):
        self.loop = asyncio.get_event_loop()
        self.proxy_authorizations = {}
        self.whitelist = URL_WHITELIST
        self.whitelist_patterns = self._compile_whitelist_patterns()
        # ElasticSearch 批量操作配置
        self.es_queue = []  # 文档队列
        self.es_queue_max_size = 50  # 队列达到此大小时批量提交
        self.es_queue_lock = asyncio.Lock()  # 保护队列的锁
        # 创建定期刷新队列的任务
        asyncio.ensure_future(self.periodic_bulk_index())
        # self.redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True) 
    
    def _compile_whitelist_patterns(self):
        """将URL白名单转换为正则表达式模式"""
        patterns = []
        for pattern in self.whitelist:
            # 将通配符 * 转换为正则表达式，并转义其他特殊字符
            regex_pattern = pattern.replace(".", "\\.").replace("*", ".*")
            patterns.append(re.compile(regex_pattern))
        return patterns
    
    @lru_cache(maxsize=1000)
    def is_url_whitelisted(self, url):
        """使用正则表达式检查URL是否在白名单中，使用LRU缓存提高性能"""
        return any(pattern.search(url) for pattern in self.whitelist_patterns)
        
    def http_connect(self, flow: http.HTTPFlow):
        proxy_auth = flow.request.headers.get("Proxy-Authorization", "")
        
        # 如果验证头为空，记录为匿名用户
        if proxy_auth.strip() == "":
            ctx.log.info("Anonymous connection from: " + flow.client_conn.address[0])
            self.proxy_authorizations[(flow.client_conn.address[0])] = flow.client_conn.address[0]  # 记录IP地址作为用户名
            return
            
        # 如果验证头不为空，提取用户名但不验证密码
        try:
            auth_type, auth_string = proxy_auth.split(" ", 1)
            auth_string = base64.b64decode(auth_string).decode("utf-8")
            username = auth_string.split(":", 1)[0]  # 只获取用户名部分
            ctx.log.info("User: " + username + " connected from " + flow.client_conn.address[0])
            # 记录用户名，但不进行验证
            self.proxy_authorizations[(flow.client_conn.address[0])] = username
        except Exception as e:
            # 如果解析失败，记录为匿名用户
            ctx.log.info(f"Error parsing authorization: {e}")
            self.proxy_authorizations[(flow.client_conn.address[0])] = flow.client_conn.address[0]  # 记录IP地址作为用户名
        
    def request(self, flow: http.HTTPFlow):
        # 检查请求URL是否在白名单中
        if not self.is_url_whitelisted(flow.request.url):
            ctx.log.warn(f"Blocked non-whitelisted URL: {flow.request.url}")
            flow.response = http.Response.make(
                403,  # 状态码
                f"访问被拒绝: URL不在白名单中".encode(),  # 响应内容
                {"Content-Type": "text/plain; charset=utf-8"}  # 响应头
            )
            return
 

    async def periodic_bulk_index(self):
        """定期将队列中的数据批量提交到 ElasticSearch，避免数据在队列中停留过长时间"""
        while True:
            await asyncio.sleep(10)  # 每10秒检查一次
            await self.flush_es_queue()

    async def flush_es_queue(self):
        """将队列中的文档批量提交到 ElasticSearch"""
        async with self.es_queue_lock:
            if not self.es_queue:
                return
            
            bulk_data = []
            for index, doc in self.es_queue:
                # 添加索引操作
                bulk_data.append({"index": {"_index": index}})
                # 添加文档
                bulk_data.append(doc)
            
            self.es_queue = []  # 清空队列
        
        if bulk_data:
            # 使用 run_in_executor 执行批量索引操作
            try:
                await self.loop.run_in_executor(None, lambda: es.bulk(body=bulk_data))
                ctx.log.info(f"批量索引了 {len(bulk_data)//2} 个文档")
            except Exception as e:
                ctx.log.error(f"批量索引失败: {e}")

    async def queue_document(self, index, doc):
        """将文档添加到队列，当队列达到最大大小时执行批量操作"""
        async with self.es_queue_lock:
            self.es_queue.append((index, doc))
            should_flush = len(self.es_queue) >= self.es_queue_max_size
        
        if should_flush:
            await self.flush_es_queue()

    def response(self, flow: http.HTTPFlow):
        # 异步将请求和响应存储到Elasticsearch
        ctx.log.info("response: " + flow.request.url)
        asyncio.ensure_future(self.save_to_elasticsearch(flow))

    async def split_jsons(self, json_string):
        json_objects = []
        depth = 0
        start_index = 0
        for i, char in enumerate(json_string):
            if char == '{':
                if depth == 0:
                    start_index = i
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    end_index = i + 1
                    try:
                        json_obj = json.loads(json_string[start_index:end_index])
                        json_objects.append(json_obj)
                    except json.JSONDecodeError as e:
                        print(f"Error decoding JSON: {e}")
        return json_objects
  
    async def save_to_elasticsearch(self, flow: http.HTTPFlow):
        ctx.log.info("url: " + flow.request.url)
        if "complet" in flow.request.url or "telemetry" in flow.request.url:
            
            username = self.proxy_authorizations.get(flow.client_conn.address[0])
            timeconsumed = round((flow.response.timestamp_end - flow.request.timestamp_start) * 1000, 2)
            timeconsumed_str = f"{timeconsumed}ms"  # Add "ms" to the end of the timeconsumed string
            
            # ctx.log.info(username + ":\t consumed time: " + timeconsumed_str + str(flow.request.headers.get("x-request-id")))
            # 将请求和响应存储到Elasticsearch
            doc = {
                'user': username,
                "timestamp": datetime.utcnow().isoformat(),
                "proxy-time-consumed": timeconsumed_str,  # Use the modified timeconsumed string
                'request': {
                    'url': flow.request.url,
                    'method': flow.request.method,
                    'headers': dict(flow.request.headers),
                    # 'content': flow.request.content.decode('utf-8', 'ignore'),
                },
                'response': {
                    'status_code': flow.response.status_code,
                    'headers': dict(flow.response.headers),
                    # 'content': flow.response.content.decode('utf-8', 'ignore'),
                }
            }

            # 按照日期生成索引名称
            # current_date = datetime.utcnow().strftime("%Y-%m-%d")
            # mitmproxy_index_name = f"mitmproxy-logs-{current_date}"
            # telemetry_index_name = f"telemetry-logs-{current_date}"
            mitmproxy_index_name = "mitmproxy-logs"
            telemetry_index_name = "telemetry-logs"
            
            if "complet" in flow.request.url:
                # 使用批量操作替代单个索引
                await self.queue_document(mitmproxy_index_name, doc)
            else:
                request_content = flow.request.content.decode('utf-8', 'ignore')
                json_objects = await self.split_jsons(request_content)

                for obj in json_objects:
                    # ctx.log.info("obj: ===" + str(obj))
                    try:
                        baseDataName = obj.get("data").get("baseData").get("name")
                        accepted_numLines = 0
                        # accepted_charLens = 0
                        shown_numLines = 0
                        # shown_charLens = 0
                        if "hown" in baseDataName or "accepted" in baseDataName or "message" in baseDataName:
                            if "hown" in baseDataName:
                                shown_numLines = obj.get("data").get("baseData").get("measurements").get("numLines", 0)
                                # shown_charLens = obj.get("data").get("baseData").get("measurements").get("compCharLen")
                            else: 
                                accepted_numLines = obj.get("data").get("baseData").get("measurements").get("numLines", 0)
                                # accepted_charLens = obj.get("data").get("baseData").get("measurements").get("compCharLen")
                            
                            # 安全地获取属性，避免 None 值错误
                            properties = obj.get("data", {}).get("baseData", {}).get("properties", {})
                            editor_version = properties.get("editor_version", "unknown/unknown")
                            editor_parts = editor_version.split("/") if "/" in editor_version else ["unknown", "unknown"]
                            
                            doc = {
                                'user': username,
                                "timestamp": datetime.utcnow().isoformat(),
                                "proxy-time-consumed": timeconsumed_str,  # Use the modified timeconsumed string
                                'request': {
                                    'url': flow.request.url,
                                    'baseData': baseDataName,
                                    'accepted_numLines': accepted_numLines,
                                    'shown_numLines': shown_numLines,
                                    # 'accepted_charLens': accepted_charLens,
                                    # 'shown_charLens': shown_charLens,
                                    'language': properties.get("languageId", "unknown"),
                                    'editor': editor_parts[0],
                                    'editor_version': editor_parts[1],
                                    'copilot-ext-version': properties.get("common_extversion", "unknown"),
                                },
                                'response': {
                                    'status_code': flow.response.status_code,
                                    # 'content': flow.response.content.decode('utf-8', 'ignore'),
                                }
                            }
                            # 使用批量操作替代单个索引
                            await self.queue_document(telemetry_index_name, doc)
                    except Exception as e:
                        ctx.log.error(f"处理遥测数据时出错: {e}")
                        continue
  

# 添加插件
addons = [
    AuthProxy()
]


