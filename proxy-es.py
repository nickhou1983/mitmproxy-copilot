import asyncio
from mitmproxy import http,ctx,connection,proxy
from elasticsearch import Elasticsearch
from datetime import datetime
import base64
import os
import json
import functools
# import redis # 导入Redis

# 通常仅需要修改这里的配置

# 初始化Elasticsearch客户端，如果Elasticsearch需要身份验证，可以在这里设置用户名和密码

ELASTICSEARCH_URL = "https://20.2.53.237:9200/"
ELASTICSEARCH_USERNAME = "admin"
ELASTICSEARCH_PASSWORD = "P@ssw0rddt01!"

# 添加Redis连接
# REDIS_HOST="democopilotredis.eastasia.redis.azure.net"
# REDIS_PORT=10000
# REDIS_PASSWORD= "JbKWL2gaCnk7Xi3NoiTmeBXWU3L5VtxJBAzCaMwBiuw="


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
        # self.redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True) 
    
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
        pass
 

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
        
    async def extract_user_messages(self, content):
        """Extract messages with role 'user' from the content, keeping only the last one"""
        user_messages = []
        try:
            # Try to parse the entire content as JSON
            json_content = json.loads(content)
            
            # Check if the content is an object with messages
            if isinstance(json_content, dict):
                # Check if there's a messages list
                messages = json_content.get('messages', [])
                if isinstance(messages, list):
                    for msg in messages:
                        if isinstance(msg, dict) and msg.get('role') == 'user':
                            user_messages.append(msg)
                            ctx.log.info(f"Found user message in messages array: {msg.get('content', '')[:50]}...")
                
                # If there's a direct role field at the top level
                if json_content.get('role') == 'user':
                    user_messages.append(json_content)
                    ctx.log.info(f"Found top-level user message: {json_content.get('content', '')[:50]}...")
            
            # Check if the content is a list of messages
            elif isinstance(json_content, list):
                for item in json_content:
                    if isinstance(item, dict) and item.get('role') == 'user':
                        user_messages.append(item)
                        ctx.log.info(f"Found user message in list: {item.get('content', '')[:50]}...")
                        
        except json.JSONDecodeError:
            ctx.log.info("Content is not valid JSON, trying to extract JSON objects")
            # If it's not valid JSON, try to extract individual JSON objects
            json_objects = await self.split_jsons(content)
            for obj in json_objects:
                if isinstance(obj, dict):
                    # Check if this object is a user message
                    if obj.get('role') == 'user':
                        user_messages.append(obj)
                        ctx.log.info(f"Found user message in split JSON: {obj.get('content', '')[:50]}...")
                    
                    # Check if it contains a messages array
                    messages = obj.get('messages', [])
                    if isinstance(messages, list):
                        for msg in messages:
                            if isinstance(msg, dict) and msg.get('role') == 'user':
                                user_messages.append(msg)
                                ctx.log.info(f"Found user message in split JSON messages: {msg.get('content', '')[:50]}...")
        
        # Get only the last user message
        if user_messages:
            last_user_message = user_messages[-1]
            ctx.log.info(f"Only keeping the last user message: {last_user_message.get('content', '')[:50]}...")
            return [last_user_message]  # Return as a list with only the last message
        else:
            ctx.log.info("No user messages found")
            return []
        
    async def save_to_file(self, messages):
        """Save the last user message to a JSONL file with the current date"""
        if not messages:
            ctx.log.info("No user message to save")
            return
            
        # Create the filename with current date
        filename = f"chat-{datetime.utcnow().strftime('%Y-%m-%d')}.jsonl"

        # Append the last message to the file (should be only one in the list)
        with open(filename, 'a', encoding='utf-8') as f:
            for msg in messages:
                f.write(json.dumps(msg, ensure_ascii=False) + '\n')
                
        ctx.log.info(f"Saved last user message to {filename}")
    
    async def check_for_model(self, content, model_name="gpt-4o-mini"):
        """Check if the content contains the specified model name using proper JSON parsing"""
        try:
            # Try to parse the content as a single JSON object
            json_content = json.loads(content)
            if isinstance(json_content, dict) and json_content.get('model') == model_name:
                return True
                
            # Check in messages or other nested structures
            if isinstance(json_content, dict):
                # Some common paths where model might be specified
                if json_content.get('messages') and isinstance(json_content.get('messages'), list):
                    for msg in json_content.get('messages'):
                        if isinstance(msg, dict) and msg.get('model') == model_name:
                            return True
                
                # Check for nested model field
                if 'data' in json_content and isinstance(json_content['data'], dict):
                    if json_content['data'].get('model') == model_name:
                        return True
                        
            # If content is a list, check each item
            elif isinstance(json_content, list):
                for item in json_content:
                    if isinstance(item, dict) and item.get('model') == model_name:
                        return True
                        
        except json.JSONDecodeError:
            # If parsing as a single object failed, try to find individual JSON objects
            json_objects = await self.split_jsons(content)
            for obj in json_objects:
                if isinstance(obj, dict) and obj.get('model') == model_name:
                    return True
                    
        # Simple string search as fallback (less reliable but catches some cases)
        if f'"model":"{model_name}"' in content or f"'model':'{model_name}'" in content:
            return True
            
        return False
    
    async def save_to_elasticsearch(self, flow: http.HTTPFlow):
        ctx.log.info("url: " + flow.request.url)
        
        # Check for x-initiator header value
        x_initiator = flow.request.headers.get("x-initiator", "")
        ctx.log.info(f"x-initiator header: {x_initiator}")
        
        # Check for openai-intent header value
        openai_intent = flow.request.headers.get("openai-intent", "")
        ctx.log.info(f"openai-intent header: {openai_intent}")
        
        # New conditions: 
        # 1. openai_intent != "copilot-ghost" AND x_initiator == "agent"
        # 2. request.content contains "model":"gpt-4o-mini"
        
        # First check the header conditions
        if openai_intent != "copilot-ghost" and x_initiator.lower() == "agent":
            # Decode request content
            request_content = flow.request.content.decode('utf-8', 'ignore')
            
            # Check if request contains "model":"gpt-4o-mini"
            has_target_model = await self.check_for_model(request_content)
            
            if has_target_model:
                ctx.log.info("Conditions met: non-ghost intent, agent initiator, and gpt-4o-mini model")
                # Extract and save the last user message to JSONL file
                last_user_message = await self.extract_user_messages(request_content)
                await self.save_to_file(last_user_message)
                
                # Save to ElasticSearch chat-YYYY-MM-DD index
                if last_user_message:
                    username = self.proxy_authorizations.get(flow.client_conn.address[0], "unknown")
                    chat_index_name = f"chat-{datetime.utcnow().strftime('%Y-%m-%d')}"
                    
                    chat_doc = {
                        'user': username,
                        'timestamp': datetime.utcnow().isoformat(),
                        'message': last_user_message[0],  # Only one message in the list
                        'url': flow.request.url,
                        'headers': {
                            'x-initiator': x_initiator,
                            'openai-intent': openai_intent
                        }
                    }
                    
                    try:
                        index_func = functools.partial(es.index, index=chat_index_name, body=chat_doc)
                        await self.loop.run_in_executor(None, index_func)
                        ctx.log.info(f"Saved user message to ElasticSearch index: {chat_index_name}")
                    except Exception as e:
                        ctx.log.error(f"Error saving to ElasticSearch chat index: {e}")
            else:
                ctx.log.info("Request doesn't contain gpt-4o-mini model, skipping extraction")
        else:
            if openai_intent == "copilot-ghost":
                ctx.log.info("Request has openai-intent: copilot-ghost, skipping extraction")
            if x_initiator.lower() != "agent":
                ctx.log.info(f"Request has x-initiator: {x_initiator}, not agent, skipping extraction")
        
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


