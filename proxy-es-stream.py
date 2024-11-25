
# 导入依赖的库

import asyncio
import base64
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Optional
import chardet
from mitmproxy import ctx,http
import json
import functools
import urllib.parse
from elasticsearch import Elasticsearch
import redis
import time
import os
 

# 定义Elasticsearch配置
# 通常仅需要修改这里的配置
# 初始化Elasticsearch客户端，如果Elasticsearch需要身份验证，可以在这里设置用户名和密码
ELASTICSEARCH_URL = "https://20.2.53.237:9200/"
ELASTICSEARCH_USERNAME = "admin"
ELASTICSEARCH_PASSWORD = "Qifeng@123.com"

es = Elasticsearch(
    [ELASTICSEARCH_URL],
# ElasticSearch 不需要验证服务器证书   
    verify_certs=False,
# ElasticSearch 不需要用户名和密码
    http_auth=(ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD),
)


# 添加Redis连接

REDIS_HOST="democopilotredis.redis.cache.windows.net"
REDIS_PORT=6379
REDIS_PASSWORD="k1wS4jxlRoOGgeK4QXpbHtjve2tB9B4MpAzCaEPKg1A="

# 定义允许域名列表

allowed_patterns = [

     "https://github.com/login.*",

     "https://vscode.dev/redirect.*",

     "https://github.com/settings/two_factor_checkup.*",

     "https://github.com/favicon.ico",

     "https://github.com/session.*",

     "https://github.com/sessions.*",

     "https://github.githubassets.com/assets.*",

     "https://api.github.com/user.*",

     "https://education.github.com/api/user",

     "https://api.github.com/copilot_internal/v2/token.*",

     "https://api.github.com/copilot_internal/notification.*",

     "https://default.exp-tas.com/.*",

     "https://copilot-proxy.githubusercontent.com.*",

     "https://api.github.com/applications/[0-9a-fA-F]+/token",

     "https://api.githubcopilot.com/.*",

     "https://copilot-telemetry-service.githubusercontent.com/.*",

     "https://copilot-telemetry.githubusercontent.com/.*",

     "https://api.github.com/teams/.*",

     "https://github.com/enterprise.*",

     "https://login.microsoftonline.com/.*",

     "https://collector.github.com.*",

     "https://aadcdn.msauth.net.*",

     "https://github.com/auth/.*",

     "https://github.com/sso_login",

     "https://github.com/$",

     "https://marketplace.visualstudio.com/.*",

     "https://github.gallery.vsassets.io/.*",

     "https://github.gallerycdn.azure.cn/.*",

     "https://api.github.com/copilot_internal/.*",

     "https://avatars.githubusercontent.com/.*",

     "https://api.github.com/_private/.*",

     "https://az764295.vo.msecnd,net/.*",

     "https://ms-python.gallery.vsassets.io/.*",

     "https://ms-python.gallerycdn.azure.cn/.*",

     "https:\/\/[\w.-]*\.gallerycdn\.azure\.cn(\/.*)?",

     "https:\/\/[\w.-]*\.gallery\.vsassets\.io(\/.*)?",

     "https://raw.githubusercontent.com/.*",

     "https://displaycatalog.mp.microsoft.com/.*",

     "https://www.jetbrains.com/config/.*",

     "https://account.jetbrains.com/lservice/.*",

     "https://plugins.jetbrains.com/api/.*",

     "https://plugins.jetbrains.com/files/.*",

     "https://download.jetbrains.com/jdk/.*",

     "https://downloads.marketplace.jetbrains.com/.*",

     "https://plugins.jetbrains.com/pluginManager*",

     "https://downloads.marketplace.jetbrains.com/files/.*",

     "https://download-cdn.jetbrains.com/jdk/.*",

     "https://github.com/logout",

     "https://dl.google.com/android/.*",

     "https://github.com/assets-cdn/.*",

     "https://github.githubassets.com/favicons/.*",

     "https:\/\/.*\.githubcopilot\.com",

     "https:\/\/.*\.business\.githubcopilot\.com",

     "https:\/\/.*\.enterprise\.githubcopilot\.com",

     #vscode更新所需url

     "https://az764295.vo.msecnd.net/.*",

     "https://vscode.download.prss.microsoft.com",

     "https://vscode-update.azurewebsites.net/.*",

     "https://update.code.visualstudio.com/.*",

     "https://code.visualstudio.com/.*",

     "https://marketplace.visualstudio.com/.*",

     "https://go.microsoft.com/.*",

     "https://vscode.blob.core.windows.net/.*",

     "https:\/\/.*\.gallerycdn\.visualstudio\.com",

     "https://rink.hockeyapp.net/.*",

     "https://bingsettingssearch.trafficmanager.net/.*",

     "https://vscode.search.windows.net/.*",

     "https://vsmarketplacebadges.dev/.*",

     "https://download.visualstudio.microsoft.com/.*",

     "https://vscode-sync.trafficmanager.net/.*",

     "https://vscode-sync-insiders.trafficmanager.net/.*",

     "https://embeddings.vscode-cdn.net/.*",

     "https://[\w.-]*\.vscode-unpkg\.net(\/.*)?",

     "https://vscode.dev/.*",

     "https://dc.services.visualstudio.com/.*",

     "https://github.com/microsoft/.*",

     "https://mobile.events.data.microsoft.com/.*",

     "https://vscodeexperiments.azureedge.net/.*",

     "https://westus-0.in.applicationinsights.azure.com/.*",

     "https:\/\/[\w.-]*\.vscode-cdn\.net(\/.*)?",

     "https:\/\/[\w.-]*\.gallerycdn\.vsassets.io(\/.*)?",

     "https://github.com/switch_account",

     #vscode更新所需url

      #"https://api.github.com/.*",

]

# 定义一个函数，用于检查URL是否在允许的域名列表中

def is_url_allowed(url: str) -> bool:

    for pattern in allowed_patterns:

        if re.match(pattern, url):

            return True

    return False

# 定义白名单URL列表

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



class StreamSaver:
    """
    A class to save and process streamed data, and optionally save it to Elasticsearch.
    Attributes:
        TAG (str): A tag for logging purposes.
        loop (asyncio.AbstractEventLoop): The event loop for asynchronous operations.
        flow (mitmproxy.http.HTTPFlow): The HTTP flow object.
        url (str): The URL of the request.
        method (str): The HTTP method of the request.
        headers (dict): The headers of the request.
        direction (str): The direction of the data flow (request/response).
        content (str): The content of the data stream.
        ip (str): The IP address of the user.
        fh (bool): A flag indicating if the file handle is open.
        path (str): The file path for saving data.
        connectionid (str): The connection ID.
    Methods:
        split_jsons(json_string):
            Splits a JSON string into individual JSON objects.
        parseResContent(content):
            Parses the response content and concatenates 'content' values from JSON data.
        save_to_elasticsearch(ip, url, method, headers, content, direction, connectionid):
            Saves the processed data to Elasticsearch.
        done():
            Finalizes the data processing and optionally kills the flow if certain conditions are met.
        __call__(data):
            Processes incoming data and appends it to the content.
    """

    TAG = "save_streamed_data: "

    def __init__(self, flow, url, method, headers, direction,ip,connectionid):
        """
        Initializes the StreamSaver object.
        Args:
            flow: The mitmproxy flow object.
            url (str): The URL of the request.
            method (str): The HTTP method of the request (e.g., 'GET', 'POST').
            headers (dict): The headers of the request.
            direction (str): The direction of the stream ('inbound' or 'outbound').
            ip (str): The IP address of the client.
            connectionid (str): The unique identifier for the connection.
        """

        # ctx.log.info("StreamSaver")

        self.loop = asyncio.get_event_loop()

        self.flow = flow

        self.url = url

        self.method = method

        self.headers = headers

        self.direction = direction

        self.content = ""

        self.ip = ip

        self.fh = False

        self.path = None

        self.connectionid = connectionid


    async def split_jsons(self, json_string):
        """
        Splits a string containing multiple JSON objects into a list of individual JSON objects.
        Args:
            json_string (str): A string containing multiple JSON objects.
        Returns:
            list: A list of JSON objects parsed from the input string.
        Raises:
            json.JSONDecodeError: If a JSON object cannot be decoded.
        """

        json_objects = []

        #encoding = chardet.detect(json_string)['encoding']

       # ctx.log.inf("encoding:\t"+ encoding)

       # ctx.log.info("split_jsons" + json_string)

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

    async def parseResContent(self, content):
        """
        Parses the response content and extracts the 'content' values from JSON data.
        Args:
            content (str): The response content as a string.
        Returns:
            str: The concatenated 'content' values extracted from the JSON data.
        Raises:
            json.JSONDecodeError: If there is an error in decoding JSON data.
        """

        lines = content.strip().split('\n')

        # Initialize an empty string to collect all 'content' values

        content_string = ""

 

        for line in lines:

            # Remove the "data: " prefix and any trailing commas

            json_str = line.replace("data: ", "").rstrip(',')

            # Skip lines that do not contain JSON data

            if json_str == "[DONE]":

                continue

            # Parse the JSON data

            try:

                data_entry = json.loads(json_str)

                # ctx.log.info("data_entry: " + str(data_entry))

                # Check if 'choices' is not empty

                if data_entry['choices']:

                    # Check if 'delta' and 'content' keys exist and 'content' is not None

                    if 'delta' in data_entry['choices'][0] and data_entry['choices'][0]['delta'].get('content') is not None:

                        # Concatenate the 'content' value to the content_string

                        content_string += data_entry['choices'][0]['delta']['content']

                    elif 'text' in data_entry['choices'][0]:

                        content_string += data_entry['choices'][0]['text']

            except json.JSONDecodeError as e:

                # print(f"JSON parsing error: {e}")

                continue  # Continue with the next line

 

        # Output the final concatenated string

        ctx.log.info("content_string: " + content_string)

        return content_string

 

    async def save_to_elasticsearch(self, ip, url, method, headers, content, direction, connectionid):


     

        if len(content.strip()) == 0:

            return

        ctx.log.info("url to es: " + url)

        if "complet"  in url or "telemetry"  in url:

            if direction == "rsp" and "complet" in url:

                content = await self.parseResContent(content)

                if len(content.strip()) == 0:

                    return

            doc = {

                # 'user': username,

                'user_ip': ip,

                "timestamp": datetime.utcnow().isoformat(),

                'payload': {

                    'url': url,

                    'method': method,

                    'headers': dict(headers),

                    'content': content,

                    'direction': direction,

                    'connection-id': connectionid,

                },

            }

            copilot_complete = f"mitmproxy-{datetime.utcnow().strftime('%Y-%m-%d')}"

            copilot_telemetry = f"telemetry-{datetime.utcnow().strftime('%Y-%m-%d')}"

            if "complet"  in url:

                index_func = functools.partial(es.index, index=copilot_complete, body=doc)

                await self.loop.run_in_executor(None, index_func)

            else:

                if direction == "rsp":

                    return

                request_content = content

                json_objects = await self.split_jsons(request_content)

                # print(json_objects)

                for obj in json_objects:

                    # ctx.log.info("obj: ===" + str(obj))

                    # baseDataName = obj.get("data").get("baseData").get("name")

                    baseDataName = obj.get("data", {}).get("baseData", {}).get("name")

                    if baseDataName is None:

                        # ctx.log.info("baseDataName is None")

                        continue  # 如果需要跳过当前循环迭代，可以使用continue


                    accepted_numLines = 0

                    accepted_charLens = 0

                    shown_numLines = 0

                    shown_charLens = 0

                    # ctx.log.info("baseDataName: === " + baseDataName)

                    # ctx.log.info("obj: ===" + str(obj))

                    if "shown" in baseDataName or "ccepted" in baseDataName:

                        if "hown" in baseDataName:

                            shown_numLines = obj.get("data").get("baseData").get("measurements").get("numLines")

                            shown_charLens = obj.get("data").get("baseData").get("measurements").get("documentLength")

                        else:

                            accepted_numLines = obj.get("data").get("baseData").get("measurements").get("numLines")

                            accepted_charLens = obj.get("data").get("baseData").get("measurements").get("documentLength")

                        doc = {

                            # 'user': username,

                            'user_ip': ip,

                            "timestamp": datetime.utcnow().isoformat(),

                            # "proxy-time-consumed": timeconsumed_str,  # Use the modified timeconsumed string

                            'request': {

                                'url': url,

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

                        }

                        index_func = functools.partial(es.index, index=copilot_telemetry, body=doc)

                        await self.loop.run_in_executor(None, index_func)

 

 

    def done(self):

        # ctx.log.info("done: \t" + self.direction)

        # ctx.log.info("done: \t" + self.content)

 

        if self.url == "https://github.com/session":          

           ctx.log.info("done: \t" + self.content)          

           request_body = self.content          

           ctx.log.info("Request body: " + str(request_body))          

           parsed_body = urllib.parse.parse_qs(request_body)          

           login_value = parsed_body.get('login', [''])[0]          

           ctx.log.info("login value1: " + login_value)          

           if not login_value.endswith('_hdkj'):              

               self.flow.response = http.Response.make(403, b"Forbidden", {"Content-Type": "text/html"})              

               self.flow.kill()             

               return

 

        asyncio.ensure_future(self.save_to_elasticsearch(self.ip, self.url, self.method, self.headers, self.content, self.direction,self.connectionid))

        if self.fh:

            self.fh = False

        # Make sure we have no circular references

        # print(self.flow)

        self.flow = None

        self.content = ""

        # self.direction = ""

 

    def __call__(self, data):

        # ctx.log.info("call:\t" + self.direction)

        # End of stream?

        if len(data) == 0:

            self.done()

            return data

 

        # This is a safeguard but should not be needed

        if not self.flow or not self.flow.request:

          

            return data

 

        if not self.fh:

            self.fh = True

 

        if self.fh:

            try:

                # self.fh.write(data)

                self.content = self.content + data.decode('utf-8', 'ignore')

                # ctx.log.info(f"url {self.flow.request.url}, user {self.user}, client-id {self.flow.client_conn.id}, data {data}")

            except OSError:

                logging.error(f"{self.TAG}Failed to write to: {self.path}")

 

        return data

 

 

def load(loader):

    ctx.log.info("loader")

 

 

class MITM_ADDON:

    def __init__(self):
        self.loop = asyncio.get_event_loop()
        self.proxy_authorizations = {}
        self.redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True)
        # ctx.log.info("MITM_ADDON")

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

        if not is_url_allowed(flow.request.pretty_url):

            ctx.log.info("Forbidden URL:\t"+flow.request.pretty_url)

            error_str = "Forbidden URL:\t"+flow.request.pretty_url

            flow.response = http.Response.make(403, error_str, {"Content-Type": "text/html"})

            flow.kill()

 

    def requestheaders(self, flow: http.HTTPFlow) -> None:

        # if flow.request.stream:

        flow.request.stream = StreamSaver(flow, flow.request.url, flow.request.method, flow.request.headers, "req", flow.client_conn.address[0], flow.client_conn.id)

 

    def responseheaders(self, flow: http.HTTPFlow) -> None:

        # ctx.log.info("response create--")

        if isinstance(flow.request.stream, StreamSaver):

            # ctx.log.info("request done--")

            flow.request.stream.done()

        # if flow.response.stream:

            flow.response.stream = StreamSaver(flow, flow.request.url, flow.request.method, flow.response.headers, "rsp", flow.client_conn.address[0], flow.client_conn.id)

 

 

    def response(self, flow: http.HTTPFlow) -> None:

        # ctx.log.info("response method invocation---")

        if isinstance(flow.response.stream, StreamSaver):

            # ctx.log.info("response done---")

            flow.response.stream.done()

 

 

    def error(self, flow: http.HTTPFlow) -> None:

        ctx.log.info("error")

        if flow.request and isinstance(flow.request.stream, StreamSaver):

            # ctx.log.info("request error done---")

            flow.request.stream.done()

        if flow.response and isinstance(flow.response.stream, StreamSaver):

            # ctx.log.info("response error done---")

            flow.response.stream.done()

 

addons = [

    MITM_ADDON()

]