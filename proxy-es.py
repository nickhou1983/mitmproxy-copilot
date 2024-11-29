import asyncio
from mitmproxy import http,ctx,connection,proxy
from elasticsearch import Elasticsearch
from datetime import datetime
import base64
import re
import os
import json
import functools
import redis # 导入Redis

# 通常仅需要修改这里的配置
# 初始化Elasticsearch客户端，如果Elasticsearch需要身份验证，可以在这里设置用户名和密码
ELASTICSEARCH_URL = "https://20.2.53.237:9200/"
ELASTICSEARCH_USERNAME = "admin"
ELASTICSEARCH_PASSWORD = "Qifeng@123.com"

# 添加Redis连接
REDIS_HOST="democopilotredis.redis.cache.windows.net"
REDIS_PORT=6379
REDIS_PASSWORD="k1wS4jxlRoOGgeK4QXpbHtjve2tB9B4MpAzCaEPKg1A="


es = Elasticsearch(
    [ELASTICSEARCH_URL],
# ElasticSearch 不需要验证服务器证书   
    verify_certs=False,
# ElasticSearch 不需要用户名和密码
    http_auth=(ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD),
)


allowed_patterns = [
     "https://github.com/",
     "https://api.githubcopilot.com/.*",
     "https://raw.githubusercontent.com/.*",
     "https://github.com/login.*",
     "https://github.com/settings/two_factor_checkup.*",
     "https://github.com/favicon.ico",
     "https://github.com/session",
     "https://github.com/sessions.*",
     "https://github.githubassets.com/assets.*",
     "https://education.github.com/api/user",
     "https://default.exp-tas.com",
     "https://default.exp-tas.com/vscode/ab",
     "https://copilot-telemetry.githubusercontent.com/telemetry",
     "https://copilot-proxy.githubusercontent.com",
     "https://origin-tracker.githubusercontent.com",
     "https:\/\/[\w.-]*\.githubcopilot\.com(\/.*)?",
     "https://api.github.com/.*",
     "https:\/\/[\w.-]*\.business\.githubcopilot\.com",
     "https:\/\/[\w.-]*\.enterprise\.githubcopilot\.com",
     "https://az764295.vo.msecnd.net/.*",
     "https://code.visualstudio.com/.*",
     "https://dc.services.visualstudio.com/.*",
     "https://github.com/microsoft/.*",
     "https://marketplace.visualstudio.com/.*",
     "https://mobile.events.data.microsoft.com/.*",
     "https://update.code.visualstudio.com/.*",
     "https://vscode.download.prss.microsoft.com/.*",
     "https://vscodeexperiments.azureedge.net/.*",
     "https://avatars.githubusercontent.com/.*",
     "https:\/\/[\w.-]*\.vscode-cdn\.net(\/.*)?",
     "https:\/\/[\w.-]*\.gallerycdn\.vsassets\.io(\/.*)?",
     "https:\/\/[\w.-]*\.gallery\.vsassets\.io(\/.*)?",
     "https://.*.gallery.vsassets.io/.*",
     "https://.*.gallerycdn.vsassets.io/.*",
     "https://.*.githubcopilot.com/.*",
     "https://vscode.dev/.*",
     "https://vscode-sync.trafficmanager.net/.*",
     "https://vscode-sync-insiders.trafficmanager.net/.*",
     "https://[\w.-]*\.vscode-unpkg\.net(\/.*)?"
]


def is_url_allowed(url: str, allowed_patterns) -> bool:
    """
    Checks if a given URL matches any of the allowed patterns.

    Args:
        url (str): The URL to be checked.
        allowed_patterns (list): A list of regex patterns to match the URL against.

    Returns:
        bool: True if the URL matches any of the allowed patterns, False otherwise.
    """
    for pattern in allowed_patterns:
        if re.match(pattern, url):
            return True
    return False

auth_whitelist_url = [
    "api.github.com.*",
    "api.enterprise.githubcopilot.com.*",
    "api.busniess.githubcopilot.com.*",
    "update.code.visualstudio.com.*",
    "dc.services.visualstudio.com.*",
    "default.exp-tas.com.*",
    "marketplace.visualstudio.com.*",
    "mobile.events.data.microsoft.com.*",
    "embeddings.vscode-cdn.net.*",
    "avatars.githubusercontent.com.*",
    "api.githubcopilot.com.*",

]

class AuthProxy:
    def __init__(self):
        self.loop = asyncio.get_event_loop()
        self.proxy_authorizations = {}
        self.redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True) 
    
    def http_connect(self, flow: http.HTTPFlow):
        proxy_auth = flow.request.headers.get("Proxy-Authorization", "")
        # 如果没有代理授权，或者URL不在白名单中，返回401
        url = flow.request.pretty_url
        if not proxy_auth and not is_url_allowed(url, auth_whitelist_url):
            ctx.log.info("Proxy-Authorization: 401 failed " + url)
            flow.response = http.Response.make(401)

        ctx.log.info("Proxy-Authorization: " + proxy_auth.strip())

        if proxy_auth.strip() == "" :
            self.proxy_authorizations[(flow.client_conn.id)] = ""
            # flow.response = http.Response.make(401)
            return
        auth_type, auth_string = proxy_auth.split(" ", 1)
        auth_string = base64.b64decode(auth_string).decode("utf-8")
        username, password = auth_string.split(":")
        ctx.log.info("User: " + username + " Password: " + password)

        # 从Redis中校验用户名和密码
        stored_password = self.redis_client.get(username)
        print(stored_password)
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
        
    def request(self, flow: http.HTTPFlow):
        if not is_url_allowed(flow.request.url, allowed_patterns):
            flow.response = http.Response.make(403, b"Forbidden", {"Content-Type": "text/html"})
 

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
            
            ctx.log.info(username + ":\t consumed time: " + timeconsumed_str + str(flow.request.headers.get("x-request-id")))
            # 将请求和响应存储到Elasticsearch
            doc = {
                'user': username,
                "timestamp": datetime.utcnow().isoformat(),
                "proxy-time-consumed": timeconsumed_str,  # Use the modified timeconsumed string
                'request': {
                    'url': flow.request.url,
                    'method': flow.request.method,
                    'headers': dict(flow.request.headers),
                    'content': flow.request.content.decode('utf-8', 'ignore'),
                },
                'response': {
                    'status_code': flow.response.status_code,
                    'headers': dict(flow.response.headers),
                    'content': flow.response.content.decode('utf-8', 'ignore'),
                }
            }

            # 按照日期生成索引名称
            
            mitmproxy_index_name = f"mitmproxy-{datetime.utcnow().strftime('%Y-%m-%d')}"
            telemetry_index_name = f"telemetry-{datetime.utcnow().strftime('%Y-%m-%d')}"

            if "complet" in flow.request.url:
                index_func = functools.partial(es.index, index=mitmproxy_index_name, body=doc)
                await self.loop.run_in_executor(None, index_func)
            else:
                request_content = flow.request.content.decode('utf-8', 'ignore')
                json_objects = await self.split_jsons(request_content)

                for obj in json_objects:
                    ctx.log.info("obj: ===" + str(obj))
                    baseDataName = obj.get("data").get("baseData").get("name")
                    accepted_numLines = 0
                    accepted_charLens = 0
                    shown_numLines = 0
                    shown_charLens = 0
                    if "hown" in baseDataName or "accepted" in baseDataName:
                        if "hown" in baseDataName:
                            shown_numLines = obj.get("data").get("baseData").get("measurements").get("numLines")
                            shown_charLens = obj.get("data").get("baseData").get("measurements").get("compCharLen")
                        else: 
                            accepted_numLines = obj.get("data").get("baseData").get("measurements").get("numLines")
                            accepted_charLens = obj.get("data").get("baseData").get("measurements").get("compCharLen")
                        doc = {
                            'user': username,
                            "timestamp": datetime.utcnow().isoformat(),
                            "proxy-time-consumed": timeconsumed_str,  # Use the modified timeconsumed string
                            'request': {
                                'url': flow.request.url,
                                'baseData': baseDataName,
                                'accepted_numLines': accepted_numLines,
                                'shown_numLines': shown_numLines,
                                'accepted_charLens': accepted_charLens,
                                'shown_charLens': shown_charLens,
                                'language': obj.get("data").get("baseData").get("properties").get("languageId"),
                                'editor': obj.get("data").get("baseData").get("properties").get("editor_version").split("/")[0],
                                'editor_version': obj.get("data").get("baseData").get("properties").get("editor_version").split("/")[1],
                                'copilot-ext-version': obj.get("data").get("baseData").get("properties").get("common_extversion"),
                            },
                            'response': {
                                'status_code': flow.response.status_code,
                                'content': flow.response.content.decode('utf-8', 'ignore'),
                            }
                        }
                        index_func = functools.partial(es.index, index=telemetry_index_name, body=doc)
                        await self.loop.run_in_executor(None, index_func)
  

# 添加插件
addons = [
    AuthProxy()
]


