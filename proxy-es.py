import asyncio
from mitmproxy import http,ctx,connection,proxy
from elasticsearch import Elasticsearch
from datetime import datetime
import base64
import re
import os
import json
import functools
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from msal import ConfidentialClientApplication

# 通常仅需要修改这里的配置
# 初始化Elasticsearch客户端，如果Elasticsearch需要身份验证，可以在这里设置用户名和密码

ELASTICSEARCH_URL = "https://143.64.161.23:9200/"
ELASTICSEARCH_USERNAME = "admin"
ELASTICSEARCH_PASSWORD = "admin"

es = Elasticsearch(
    [ELASTICSEARCH_URL],
# ElasticSearch 不需要验证服务器证书   
    verify_certs=False,
# ElasticSearch 不需要用户名和密码
    http_auth=(ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD),
)

allowed_patterns = [
     # "https://.*",
     "https://github.com/.*",
     "https://api.githubcopilot.com/.*",
     "https://github.com/login.*",
     "https://vscode.dev/redirect.*",
     "https://github.com/settings/two_factor_checkup.*",
     "https://github.com/favicon.ico",
     "https://github.com/session",
     "https://github.com/sessions.*",
     "https://github.githubassets.com/assets.*",
     "https://api.github.com/user",
     "https://education.github.com/api/user",
     "https://api.github.com/copilot_internal/v2/token",
     "https://api.github.com/copilot_internal/notification",
     "https://default.exp-tas.com",
     "https://default.exp-tas.com/vscode/ab",
     "https://copilot-telemetry.githubusercontent.com/telemetry",
     "https://copilot-proxy.githubusercontent.com.*",
     "https://*.githubcopilot.com/.*",
     "https://api.github.com/applications/[0-9a-fA-F]+/token",
     "https://api.githubcopilot.com/chat/completions.*",
     "https://api.github.com/.*"
]

def is_url_allowed(url: str) -> bool:
    for pattern in allowed_patterns:
        if re.match(pattern, url):
            return True
    return False

class AuthProxy:
    def __init__(self):
        self.loop = asyncio.get_event_loop()
        self.proxy_authorizations = {} 
        self.azure_credential = DefaultAzureCredential()
        self.key_vault_url = "https://<your-key-vault-name>.vault.azure.net/"
        self.secret_client = SecretClient(vault_url=self.key_vault_url, credential=self.azure_credential)
        self.oidc_client = ConfidentialClientApplication(
            client_id="your-client-id",
            client_credential="your-client-secret",
            authority="https://login.microsoftonline.com/your-tenant-id"
        )

    def get_azure_secret(self, secret_name):
        secret = self.secret_client.get_secret(secret_name)
        return secret.value

    def authenticate_oidc(self, username, password):
        result = self.oidc_client.acquire_token_by_username_password(
            scopes=["User.Read"],
            username=username,
            password=password
        )
        return result

    def http_connect(self, flow: http.HTTPFlow):
        proxy_auth = flow.request.headers.get("Proxy-Authorization", "")
        # 如果没有代理授权头，返回401
        if not proxy_auth:
            flow.response = http.Response.make(401)
        ctx.log.info("Proxy-Authorization: " + proxy_auth.strip())
        if proxy_auth.strip() == "" :
            flow.response = http.Response.make(401)
        auth_type, auth_string = proxy_auth.split(" ", 1)
        auth_string = base64.b64decode(auth_string).decode("utf-8")
        username, password = auth_string.split(":")
        ctx.log.info("User: " + username + " Password: " + password)
        # Check Azure AD for the username
        try:
            azure_password = self.get_azure_secret(username)
            if azure_password != password:
                ctx.log.info("User: " + username + " attempted to log in with an incorrect password.")
                flow.response = http.Response.make(401)
                return
        except Exception as e:
            ctx.log.info("Azure AD authentication failed for user: " + username)
            flow.response = http.Response.make(401)
            return
        # Check OIDC for the username
        try:
            oidc_result = self.authenticate_oidc(username, password)
            if "access_token" not in oidc_result:
                ctx.log.info("User: " + username + " failed OIDC authentication.")
                flow.response = http.Response.make(401)
                return
        except Exception as e:
            ctx.log.info("OIDC authentication failed for user: " + username)
            flow.response = http.Response.make(401)
            return
        ctx.log.info("Authenticated: " + flow.client_conn.address[0])
        self.proxy_authorizations[(flow.client_conn.address[0])] = username
    
    def request(self, flow: http.HTTPFlow):
        if not is_url_allowed(flow.request.url):
            flow.response = http.Response.make(403, b"Forbidden", {"Content-Type": "text/html"})

    def response(self, flow: http.HTTPFlow):
        # 异步将请求和响应存储到Elasticsearch
        ctx.log.info("response: " + flow.request.url)
        asyncio.ensure_future(self.save_to_elasticsearch(flow))

    # Generated by Copilot
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
        if "complet"  in flow.request.url or "telemetry"  in flow.request.url:
            
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
            if "complet"  in flow.request.url:
                index_func = functools.partial(es.index, index='mitmproxy', body=doc)
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
                        index_func = functools.partial(es.index, index='telemetry', body=doc)
                        await self.loop.run_in_executor(None, index_func)

# 添加插件
addons = [
    AuthProxy()
]

