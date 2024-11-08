
import asyncio
import logging
import base64
import os
from datetime import datetime
from pathlib import Path
from typing import Optional
import re
from mitmproxy import ctx,http
import json
import functools
from elasticsearch import Elasticsearch

ELASTICSEARCH_URL = "http://xxxx:9200/"
#ELASTICSEARCH_URL = "http://es-test-es-http-ext:9200/"
ELASTICSEARCH_USERNAME = "xxxx"
ELASTICSEARCH_PASSWORD = "xxxx"

es = Elasticsearch(
    [ELASTICSEARCH_URL],
    # use_ssl=False,
    verify_certs=False,
    http_auth=(ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD),
)

allowed_patterns = [
     "https://github.com/login.*",
     "https://vscode.dev/redirect.*",
     "https://github.com/settings/two_factor_checkup.*",
     "https://github.com/favicon.ico",
     "https://github.com/session",
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
     r"^https://([a-zA-Z0-9-]+\.)*githubcopilot\.com/.*",
     r"^https://([a-zA-Z0-9-]+\.)*business\.githubcopilot\.com/.*",
     r"^https://([a-zA-Z0-9-]+\.)*enterprise\.githubcopilot\.com/.*"
    #  "https://api.github.com/.*"
]

def is_url_allowed(url: str) -> bool:
    for pattern in allowed_patterns:
        if re.match(pattern, url):
            return True
    return False


class StreamSaver:
    TAG = "save_streamed_data: "
    def __init__(self, flow, url, method, headers, direction,ip,connectionid, username):
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
        self.username = username

    async def split_jsons(self, json_string):
        json_objects = []
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

    async def save_to_elasticsearch(self, ip, url, method, headers, content, direction, connectionid, username):
       
        if len(content.strip()) == 0:
            return
        ctx.log.info("url to es: " + url)
        if "complet"  in url or "telemetry"  in url:
            if direction == "rsp" and "complet" in url:
                content = await self.parseResContent(content)
                if len(content.strip()) == 0:
                    return
            doc = {
                'user': username,
                'user_ip': ip,
                'connectionid': connectionid,
                "timestamp": datetime.utcnow().isoformat(),
                'payload': {
                    'url': url,
                    'method': method,
                    'headers': dict(headers),
                    'content': content,
                    'direction': direction,
                },
            }
            if "complet"  in url:
                index_func = functools.partial(es.index, index='mitmproxy-stream', body=doc)
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
                    if "hown" in baseDataName or "accepted" in baseDataName:
                        if "hown" in baseDataName:
                            shown_numLines = obj.get("data").get("baseData").get("measurements").get("numLines")
                            shown_charLens = obj.get("data").get("baseData").get("measurements").get("compCharLen")
                        else: 
                            accepted_numLines = obj.get("data").get("baseData").get("measurements").get("numLines")
                            accepted_charLens = obj.get("data").get("baseData").get("measurements").get("compCharLen")
                        doc = {
                            'user': username,
                            'user_ip': ip,
                            'connectionid': connectionid,
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
                        index_func = functools.partial(es.index, index='telemetry-streaming', body=doc)
                        await self.loop.run_in_executor(None, index_func)


    def done(self):
        # ctx.log.info("done: \t" + self.direction)
        # ctx.log.info("done: \t" + self.content)
        asyncio.ensure_future(self.save_to_elasticsearch(self.ip, self.url, self.method, self.headers, self.content, self.direction,self.connectionid, self.username))
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
    ctx.log.info("loading streaming server addon")

class MITM_ADDON:
    def __init__(self):
        self.proxy_authorizations = {} 
        self.credentials = self.load_credentials("creds.txt")
    
    def load_credentials(self, file_path):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Credentials file '{file_path}' not found")
        creds = {}
        with open(file_path, "r") as f:
            for line in f:
                username, password = line.strip().split(",")
                creds[username] = password
        return creds
    
    def http_connect(self, flow: http.HTTPFlow):
        proxy_auth = flow.request.headers.get("Proxy-Authorization", "")
        # 如果没有代理授权头，返回401
        if not proxy_auth:
            flow.response = http.Response.make(401)

        ctx.log.info("Proxy-Authorization: " + proxy_auth.strip())
        if proxy_auth.strip() == "" :
            self.proxy_authorizations[(flow.client_conn.id)] = ""
            return
        auth_type, auth_string = proxy_auth.split(" ", 1)
        auth_string = base64.b64decode(auth_string).decode("utf-8")
        username, password = auth_string.split(":")
        if username == "admin":
            flow.response = http.Response.make(401)
        ctx.log.info("User: " + username + " Password: " + password)

        if username in self.credentials:
            # If the username exists, check if the password is correct
            if self.credentials[username] != password:
                ctx.log.info("User: " + username + " attempted to log in with an incorrect password.")
                flow.response = http.Response.make(401)
                return
        else:
            # If the username does not exist, log the event and return a 401 response
            ctx.log.info("Username: " + username + " does not exist.")
            flow.response = http.Response.make(401)
            return
    
        # ctx.log.info("Authenticated: " + flow.client_conn.id + ". url "  + flow.request.url)
        self.proxy_authorizations[(flow.client_conn.id)] = username

    def request(self, flow: http.HTTPFlow):
        # ctx.log.info("request method invocation---")
        if not is_url_allowed(flow.request.pretty_url):
            ctx.log.info("Forbidden URL:\t"+flow.request.pretty_url)
            error_str = "Forbidden URL:\t"+flow.request.pretty_url
            flow.response = http.Response.make(403, error_str, {"Content-Type": "text/html"})
            flow.kill()

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        # if flow.request.stream:
        flow.request.stream = StreamSaver(flow, flow.request.url, flow.request.method, flow.request.headers, "req", flow.client_conn.address[0], flow.client_conn.id, self.proxy_authorizations.get(flow.client_conn.id))

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        # ctx.log.info("response create--")
        if isinstance(flow.request.stream, StreamSaver):
            # ctx.log.info("request done--")
            flow.request.stream.done()
        # if flow.response.stream:
            flow.response.stream = StreamSaver(flow, flow.request.url, flow.request.method, flow.response.headers, "rsp", flow.client_conn.address[0], flow.client_conn.id, self.proxy_authorizations.get(flow.client_conn.id))


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
