#!/usr/bin/env python3
"""
将 chat-YYYY-MM-DD.jsonl 文件转换为 OpenAI Batch API 输入格式，并向Azure OpenAI提交批处理任务，
完成后自动将结果保存到本地文件和 Elasticsearch 索引 chat-output-YYYY-MM-DD。
支持仅将 message 对象存储到ES，减少存储空间。

使用方法: 
1. 仅转换文件:
   python generate_batch_input.py [输入文件] [输出文件] [模型名称]

2. 完整批处理流程 (转换、上传、创建任务、监控、下载结果并保存到ES):
   python generate_batch_input.py [输入文件] [输出文件] [模型名称] [API密钥] [API端点] [部署ID]
   注意: 如果不提供[API密钥][API端点][部署ID]，将自动尝试使用环境变量中的配置

3. 根据output_file_id直接下载结果文件并保存到ES:
   python generate_batch_input.py --download-output [output_file_id] [API密钥] [API端点] [部署ID]
   注意: 如果不提供[API密钥][API端点][部署ID]，将自动尝试使用环境变量中的配置
   
4. 直接处理批处理结果文件并保存到ES (仅存储message对象):
   python generate_batch_input.py --process-file [结果文件路径]

默认参数:
- 输入文件: chat-当前日期.jsonl
- 输出文件: chat-input-当前日期.jsonl
- 模型名称: gpt-4o-mini

环境变量配置:
- Azure OpenAI (可以通过命令行参数覆盖):
  - AZURE_OPENAI_API_KEY: Azure OpenAI API密钥
  - AZURE_OPENAI_ENDPOINT: Azure OpenAI端点URL (以http://或https://开头)
  - AZURE_OPENAI_DEPLOYMENT_ID: Azure OpenAI部署ID

- Elasticsearch配置:
  - ES_HOST: Elasticsearch主机地址 (默认: localhost)
  - ES_PORT: Elasticsearch端口 (默认: 9200)
  - ES_USER: Elasticsearch用户名 (可选)
  - ES_PASSWORD: Elasticsearch密码 (可选)

功能:
1. 判断是否存在今天的Chat-input文件，如果不存在，则生成对应文件
2. 如果存在今天的Chat-input文件，自动执行完整批处理流程（无需额外参数）
3. 如果提供API信息，会上传文件到Azure OpenAI服务，创建Batch任务
4. 每隔120秒，自动获取Batch任务状态
5. Batch任务完成后，下载输出文件到本地
6. 自动将批处理结果保存到Elasticsearch索引 chat-output-YYYY-MM-DD
7. 支持通过output_file_id直接下载批处理结果文件

依赖安装:
pip install requests elasticsearch
"""

import json
import sys
import os
import time
import requests
import logging
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

# Azure OpenAI配置
AZURE_OPENAI_API_KEY = os.environ.get("AZURE_OPENAI_API_KEY", "")
AZURE_OPENAI_ENDPOINT = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
AZURE_OPENAI_DEPLOYMENT_ID = os.environ.get("AZURE_OPENAI_DEPLOYMENT_ID", "gpt-4o-mini")

# Elasticsearch配置
ES_HOST = os.environ.get("ES_HOST", "20.2.53.237")
ES_PORT = int(os.environ.get("ES_PORT", "9200"))
ES_USER = os.environ.get("ES_USER", "")
ES_PASSWORD = os.environ.get("ES_PASSWORD", "")

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AzureOpenAIBatchClient:
    """Azure OpenAI Batch API客户端"""
    
    def __init__(self, api_key=None, endpoint=None, deployment_id=None, output_file=None):
        # 优先使用传入的参数，其次使用环境变量
        self.api_key = api_key or AZURE_OPENAI_API_KEY
        self.endpoint = endpoint or AZURE_OPENAI_ENDPOINT
        self.deployment_id = deployment_id or AZURE_OPENAI_DEPLOYMENT_ID
        self.output_file = output_file
        
        # 检查必要的配置
        missing_configs = []
        if not self.api_key:
            missing_configs.append("API密钥(AZURE_OPENAI_API_KEY)")
        if not self.endpoint:
            missing_configs.append("端点(AZURE_OPENAI_ENDPOINT)")
        if not self.deployment_id:
            missing_configs.append("部署ID(AZURE_OPENAI_DEPLOYMENT_ID)")
            
        if missing_configs:
            raise ValueError(f"缺少必要的Azure OpenAI配置: {', '.join(missing_configs)}。请设置相应环境变量或通过参数提供")
        
        # 确保端点没有尾部斜杠
        if self.endpoint.endswith("/"):
            self.endpoint = self.endpoint[:-1]
            
        self.headers = {
            "api-key": self.api_key,
            "Content-Type": "application/json"
        }
        
        logger.debug(f"初始化Azure OpenAI客户端，使用端点: {self.endpoint}, 部署ID: {self.deployment_id}")
        
    def upload_file(self, file_path):
        """上传文件到Azure OpenAI"""
        logger.info(f"上传文件: {file_path}")
        
        # 构建上传URL
        upload_url = f"{self.endpoint}/openai/files?api-version=2025-03-01-preview"
        
        with open(file_path, "rb") as file:
            files = {
                "file": (os.path.basename(file_path), file, "application/jsonl"),
                "purpose": (None, "batch")
            }
            response = requests.post(upload_url, headers={"api-key": self.api_key}, files=files)

        if response.status_code != 201:
            logger.error(f"文件上传失败: {response.text}")
            raise Exception(f"文件上传失败: {response.status_code} - {response.text}")
            
        result = response.json()
        logger.info(f"文件上传成功，ID: {result['id']}")
        return result["id"]
        
    def create_batch_job(self, input_file_id):
        """创建批处理任务"""
        logger.info(f"创建批处理任务，使用文件ID: {input_file_id}")
        
        # 构建创建批处理任务的URL
        create_url = f"{self.endpoint}/openai/batches?api-version=2025-03-01-preview"
        
        # 修复错误：使用input_file_id而不是input_file_ids，并添加output_folder参数
        payload = {
            # "model": self.deployment_id,
            "input_file_id": input_file_id,  # 使用正确的参数名称
            "endpoint": "/chat/completions",
            # "output_folder": "batch-outputs"  # 添加必要的输出文件夹参数
        }
        
        response = requests.post(create_url, headers=self.headers, json=payload)
        
        if response.status_code != 200:
            logger.error(f"创建批处理任务失败: {response.text}")
            raise Exception(f"创建批处理任务失败: {response.status_code} - {response.text}")
            
        result = response.json()
        logger.info(f"批处理任务创建成功，ID: {result['id']}")
        return result["id"]
        
    def get_batch_job_status(self, batch_job_id):
        """获取批处理任务状态"""
        logger.info(f"获取批处理任务状态，ID: {batch_job_id}")
        
        # 构建获取批处理任务状态的URL
        status_url = f"{self.endpoint}/openai/batches/{batch_job_id}?api-version=2025-03-01-preview"
        
        response = requests.get(status_url, headers=self.headers)
        
        if response.status_code != 200:
            logger.error(f"获取批处理任务状态失败: {response.text}")
            raise Exception(f"获取批处理任务状态失败: {response.status_code} - {response.text}")
            
        result = response.json()
        logger.info(f"批处理任务状态: {result['status']}")
        return result
    
    def download_output_file(self, output_file_id):
        """根据output_file_id下载输出文件"""
        logger.info(f"下载输出文件，ID: {output_file_id}")
        
        # 构建下载URL
        download_url = f"{self.endpoint}/openai/files/{output_file_id}/content?api-version=2025-03-01-preview"
        
        response = requests.get(download_url, headers=self.headers)
        
        if response.status_code != 200:
            logger.error(f"下载输出文件失败: {response.text}")
            raise Exception(f"下载输出文件失败: {response.status_code} - {response.text}")
        
        # 创建输出文件名（使用当前时间戳避免文件名冲突）
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file_name = f"chat-output-{timestamp}.jsonl"
        
        # 将内容写入文件
        with open(output_file_name, "wb") as f:
            f.write(response.content)
        
        logger.info(f"输出文件已保存至: {output_file_name}")
        return output_file_name
    
    def download_batch_results(self, batch_status):
        """下载批处理任务的结果文件并保存到Elasticsearch"""
        # 从批处理状态中获取输出文件ID
        output_file_id = batch_status.get("output_file_id")
        batch_id = batch_status.get("id", "unknown")
        
        if not output_file_id:
            logger.error(f"批处理任务 {batch_id} 没有输出文件ID")
            raise Exception(f"批处理任务 {batch_id} 没有输出文件ID")
        
        logger.info(f"准备下载批处理任务 {batch_id} 的输出文件 {output_file_id}")
        
        # 下载输出文件
        output_file_name = self.download_output_file(output_file_id)
        
        # 将结果保存到Elasticsearch
        try:
            logger.info(f"尝试将批处理结果从 {output_file_name} 保存到Elasticsearch...")
            start_time = time.time()
            es_result = save_to_elasticsearch(output_file_name)
            elapsed_time = time.time() - start_time
            
            if es_result:
                logger.info(f"成功将批处理结果保存到Elasticsearch (耗时: {elapsed_time:.2f}秒)")
            else:
                logger.warning(f"向Elasticsearch保存结果完成，但可能有部分失败 (耗时: {elapsed_time:.2f}秒)")
        except Exception as e:
            logger.error(f"保存到Elasticsearch失败: {str(e)}", exc_info=True)
            logger.info("尽管Elasticsearch保存失败，输出文件仍然可用")
        
        return output_file_name
    
    def process_batch_job(self):
        """处理批处理任务，包括创建、监控和获取结果"""
        # 检查是否配置了Azure OpenAI API
        if not all([self.endpoint, self.api_key]):
            logger.warning("未配置Azure OpenAI API，跳过批处理任务")
            return
        
        try:
            # 上传文件
            file_id = self.upload_file(self.output_file)
            logger.info(f"文件已上传，ID: {file_id}")
            
            # 创建批处理任务
            batch_job_id = self.create_batch_job(file_id)
            logger.info(f"批处理任务已创建，ID: {batch_job_id}")
            
            # 每120秒检查一次任务状态，直到完成或失败
            while True:
                batch_status = self.get_batch_job_status(batch_job_id)
                status = batch_status.get("status")
                
                if status == "completed":
                    logger.info("批处理任务已成功完成")
                    # 下载结果
                    output_file = self.download_batch_results(batch_status)
                    logger.info(f"批处理任务结果已下载至: {output_file}")
                    break
                elif status in ["failed", "canceled"]:
                    logger.error(f"批处理任务{status}，原因: {batch_status.get('error', '未知')}")
                    break
                else:
                    logger.info(f"批处理任务进行中，状态: {status}")
                    time.sleep(120)  # 等待120秒再次检查
            
            return batch_status
        except Exception as e:
            logger.error(f"处理批处理任务时出错: {str(e)}")
            raise
        

def convert_chat_to_batch(input_file=None, output_file=None, model_name="gpt-4o-mini"):
    """将聊天记录文件转换为 OpenAI Batch API 输入格式"""
    
    # 如果没有指定输入文件，使用当前日期创建默认文件名
    if not input_file:
        input_file = f"chat-{datetime.now().strftime('%Y-%m-%d')}.jsonl"
    
    # 如果没有指定输出文件，使用默认名称
    if not output_file:
        output_file = f"chat-input-{datetime.now().strftime('%Y-%m-%d')}.jsonl"
    
    # 检查输入文件是否存在
    if not os.path.exists(input_file):
        logger.error(f"输入文件不存在: {input_file}")
        return False
        
    # 检查输出文件目录是否存在，如果不存在则创建
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            logger.info(f"已创建输出目录: {output_dir}")
        except Exception as e:
            logger.error(f"创建输出目录失败: {e}")
            return False
    
    try:
        # 读取输入文件中的消息
        messages = []
        with open(input_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:  # 跳过空行
                    try:
                        message = json.loads(line)
                        if message.get('role') == 'user':
                            messages.append(message)
                    except json.JSONDecodeError:
                        print(f"警告: 跳过无效的JSON行: {line}")
        
        # 创建批处理输入
        batch_input = []
        for i, message in enumerate(messages, 1):
            batch_item = {
                "custom_id": f"task-{i}",
                "method": "POST",
                "url": "/chat/completions",
                "body": {
                    "model": model_name,
                    "messages": [
                        {
                            "role": "system",
                            "content": "你是一个AI助手,你的工作是判断用户输入的意图,并给出相关的回答.\n下列意图中选择一个最合适的意图:\n单元测试\n代码审查\n性能优化\n代码重构\n生成文档\n通用问答\n代码解释\n代码示例\n错误排查\n如果无法判断意图,请回答“系统自动生成”,不要回答任何其他内容."
                        },
                        {
                            "role": "user",
                            "content": message.get('content', '')
                        }
                    ]
                }
            }
            batch_input.append(batch_item)
        
        # 写入输出文件
        with open(output_file, 'w', encoding='utf-8') as f:
            for item in batch_input:
                f.write(json.dumps(item, ensure_ascii=False) + '\n')
        
        logger.info(f"成功转换 {len(batch_input)} 条消息从 {input_file} 到 {output_file}")
        return True
    
    except Exception as e:
        logger.error(f"转换过程中出错: {e}", exc_info=True)
        return False

def process_azure_batch(input_file, api_key=None, endpoint=None, deployment_id=None, wait_interval=120):
    """处理Azure OpenAI批处理任务的完整流程，包括将结果保存到Elasticsearch"""
    try:
        start_time = time.time()
        logger.info("开始Azure OpenAI批处理流程")
        
        # 记录配置来源
        api_source = "命令行参数" if api_key and api_key != AZURE_OPENAI_API_KEY else "环境变量"
        endpoint_source = "命令行参数" if endpoint and endpoint != AZURE_OPENAI_ENDPOINT else "环境变量"
        deployment_source = "命令行参数" if deployment_id and deployment_id != AZURE_OPENAI_DEPLOYMENT_ID else "环境变量"
        
        logger.info(f"使用配置: API密钥(来源:{api_source}), 端点(来源:{endpoint_source}), 部署ID(来源:{deployment_source})")
        
        # 确定输出文件名
        today_date = datetime.now().strftime('%Y-%m-%d')
        output_file = f"chat-input-{today_date}.jsonl"
        
        # 检查今天的输入文件是否存在
        if not os.path.exists(output_file):
            logger.info(f"今天的批处理输入文件不存在，需要生成: {output_file}")
            
            # 如果没有指定输入文件，使用默认的 chat-YYYY-MM-DD.jsonl
            if not input_file:
                input_file = f"chat-{today_date}.jsonl"
                logger.info(f"未指定输入文件，使用默认文件: {input_file}")
                
                # 检查默认输入文件是否存在
                if not os.path.exists(input_file):
                    logger.error(f"默认输入文件不存在: {input_file}")
                    return False
            
            logger.info(f"开始将 {input_file} 转换为批处理格式: {output_file}")
            success = convert_chat_to_batch(input_file, output_file)
            if not success:
                logger.error("生成批处理输入文件失败")
                return False
            logger.info(f"成功生成批处理输入文件: {output_file}")
        else:
            logger.info(f"今天的批处理输入文件已存在: {output_file}")
        
        # 检查Elasticsearch连接
        es_available = False
        try:
            if all([ES_HOST, ES_PORT]):
                logger.info(f"检查Elasticsearch连接 ({ES_HOST}:{ES_PORT})...")
                
                # 创建Elasticsearch客户端
                es_config = {"hosts": [f"https://{ES_HOST}:{ES_PORT}"]}
                es_config["verify_certs"] = False  # 如果使用自签名证书，可以设置为False

                if ES_USER and ES_PASSWORD:
                    es_config["http_auth"] = (ES_USER, ES_PASSWORD)
                
                es = Elasticsearch(**es_config)
                es_available = es.ping()
                
                if es_available:
                    logger.info("Elasticsearch连接正常，批处理结果将自动保存到ES")
                    # 检查索引是否存在
                    index_name = f"chat-output-{datetime.now().strftime('%Y-%m-%d')}"
                    if not es.indices.exists(index=index_name):
                        logger.info(f"Elasticsearch索引 {index_name} 不存在，将在保存结果时自动创建")
                else:
                    logger.warning("Elasticsearch连接失败，批处理结果将不会保存到ES")
            else:
                logger.warning("未配置Elasticsearch，批处理结果将不会保存到ES")
        except Exception as e:
            logger.warning(f"检查Elasticsearch时出错: {e}")
        
        # 初始化Azure OpenAI客户端
        client = AzureOpenAIBatchClient(api_key, endpoint, deployment_id)
        client.output_file = output_file
        
        # 执行批处理流程（上传文件、创建任务、监控状态、下载结果）
        logger.info("开始执行Azure OpenAI批处理任务")
        batch_status = client.process_batch_job()
        
        if batch_status and batch_status.get("status", "").lower() == "completed":
            elapsed_time = time.time() - start_time
            logger.info(f"批处理流程已成功完成 (总耗时: {elapsed_time:.2f}秒)")
            
            # 如果Elasticsearch不可用，记录输出文件位置
            if not es_available:
                output_file_id = batch_status.get("output_file_id")
                if output_file_id:
                    logger.info(f"批处理结果输出文件ID: {output_file_id}")
                    logger.info("要手动保存结果到Elasticsearch，请使用命令:")
                    logger.info(f"python {sys.argv[0]} --download-output {output_file_id} [API密钥] [API端点] [部署ID]")
            
            return True
        else:
            logger.error("批处理流程未成功完成")
            if batch_status:
                logger.error(f"状态: {batch_status.get('status', '未知')}")
                if "error" in batch_status:
                    logger.error(f"错误信息: {batch_status['error']}")
            return False
    
    except Exception as e:
        logger.error(f"处理批处理任务过程中出错: {str(e)}", exc_info=True)
        return False

def validate_azure_config(api_key, endpoint, deployment_id):
    """验证Azure OpenAI配置是否有效"""
    missing_configs = []
    
    if not api_key:
        missing_configs.append("API密钥(AZURE_OPENAI_API_KEY)")
        
    if not endpoint:
        missing_configs.append("端点(AZURE_OPENAI_ENDPOINT)")
        
    if not deployment_id:
        missing_configs.append("部署ID(AZURE_OPENAI_DEPLOYMENT_ID)")
    
    if missing_configs:
        logger.error(f"Azure OpenAI配置不完整: 缺少 {', '.join(missing_configs)}。请设置相应环境变量或通过命令行参数提供")
        return False
        
    # 检查endpoint格式
    if not endpoint.startswith("http"):
        logger.error("Azure OpenAI端点必须以http://或https://开头")
        return False
        
    logger.info("Azure OpenAI配置验证通过")
    return True

def save_to_elasticsearch(output_file_path):
    """将Azure OpenAI批处理输出文件内容保存到Elasticsearch"""
    try:
        # 检查是否配置了Elasticsearch
        if not all([ES_HOST, ES_PORT]):
            logger.warning("未配置Elasticsearch，跳过保存到ES的步骤")
            return False
        
        # 创建Elasticsearch客户端
        es_config = {
            "hosts": [f"https://{ES_HOST}:{ES_PORT}"]
        }
        
        # 添加认证信息（如果提供）
        if ES_USER and ES_PASSWORD:
            es_config["http_auth"] = (ES_USER, ES_PASSWORD)
            
        # 可选：添加超时和重试配置
        es_config["retry_on_timeout"] = True
        es_config["max_retries"] = 3
        # es_config["timeout"] = 30
        es_config["verify_certs"] = False  # 如果使用自签名证书，可以设置为False
        
        es = Elasticsearch(**es_config)
        
        # 检查Elasticsearch连接
        try:
            if not es.ping():
                logger.error("无法连接到Elasticsearch")
                return False
            logger.info("成功连接到Elasticsearch")
        except Exception as e:
            logger.error(f"Elasticsearch连接错误: {e}")
            return False
        
        # 创建索引名称，使用当前日期
        index_name = f"chat-output-{datetime.now().strftime('%Y-%m-%d')}"
        logger.info(f"将结果保存到Elasticsearch索引: {index_name}")
        
        # 定义索引映射，优化搜索功能
        mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "custom_id": {"type": "keyword"},
                    "input": {"type": "text", "analyzer": "standard"},
                    "output": {"type": "text", "analyzer": "standard"},
                    "input_tokens": {"type": "integer"},
                    "output_tokens": {"type": "integer"},
                    "model": {"type": "keyword"},
                    "message": {  # 存储message对象，取代完整response
                        "type": "object", 
                        "properties": {
                            "content": {"type": "text", "analyzer": "standard"},
                            "role": {"type": "keyword"},
                            "annotations": {"type": "object", "enabled": True},
                            "refusal": {"type": "keyword"},
                        }
                    },
                    "intent": {"type": "keyword"},  # 存储意图分类结果
                    "batch_id": {"type": "keyword"}  # 用于关联同一批处理作业
                }
            },
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1,
                "index.mapping.total_fields.limit": 2000  # 增加字段限制，以防字段太多
            }
        }
        
        # 确保索引存在，并应用映射
        if not es.indices.exists(index=index_name):
            try:
                es.indices.create(index=index_name, body=mapping)
                logger.info(f"创建索引并应用映射: {index_name}")
            except Exception as e:
                logger.warning(f"创建索引失败: {e}, 尝试使用默认设置")
                try:
                    es.indices.create(index=index_name)
                    logger.info(f"使用默认设置创建索引: {index_name}")
                except Exception as e2:
                    logger.error(f"无法创建索引: {e2}, 将尝试直接写入")
                    # 不返回False，继续尝试写入数据
        
        # 生成批处理ID - 用于关联同一批次的所有文档
        batch_id = f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # 读取输出文件
        docs = []
        with open(output_file_path, 'r', encoding='utf-8') as f:
            line_number = 0
            for line in f:
                line = line.strip()
                if line:  # 跳过空行
                    try:
                        data = json.loads(line)
                        line_number += 1
                        
                        # 提取批处理结果中的内容
                        doc = {
                            "_index": index_name,
                            "_id": f"{batch_id}_{line_number}",
                            "_source": {
                                "timestamp": datetime.now().isoformat(),
                                "custom_id": data.get("custom_id", ""),
                                "batch_id": batch_id,
                                "input": "",  # 将在后续处理中添加输入内容
                                "output": "",  # 将在后续处理中添加输出内容
                                "input_tokens": 0,
                                "output_tokens": 0,
                                "model": "",
                                "response": data,  # 存储完整响应
                                "intent": ""  # AI识别的意图
                            }
                        }
                        
                        # 分析Azure OpenAI批处理响应结构
                        # 批处理输出结构可能有所不同，同时处理多种情况
                        # 只存储message对象到ES
                        message_object = None
                        model = ""
                        input_tokens = 0
                        output_tokens = 0
                        
                        # 场景1: 特定结构 - 批处理响应中的message位于response.body.choices[0].message
                        if "response" in data and "body" in data["response"]:
                            body_data = data["response"]["body"]
                            
                            # 提取令牌使用信息
                            if "usage" in body_data:
                                usage = body_data["usage"]
                                input_tokens = usage.get("prompt_tokens", 0)
                                output_tokens = usage.get("completion_tokens", 0)
                                model = body_data.get("model", "")
                                
                            # 提取message对象
                            if "choices" in body_data and len(body_data["choices"]) > 0:
                                choice = body_data["choices"][0]
                                if "message" in choice:
                                    message_object = choice["message"]
                                    doc["_source"]["output"] = message_object.get("content", "")
                                    doc["_source"]["intent"] = message_object.get("content", "").strip()
                        
                        # 场景2: 顶层直接包含choices
                        elif "choices" in data and len(data["choices"]) > 0:
                            choice = data["choices"][0]
                            if "message" in choice:
                                message_object = choice["message"]
                                doc["_source"]["output"] = message_object.get("content", "")
                                doc["_source"]["intent"] = message_object.get("content", "").strip()
                            
                            # 提取令牌使用信息
                            if "usage" in data:
                                usage = data["usage"]
                                input_tokens = usage.get("prompt_tokens", 0) 
                                output_tokens = usage.get("completion_tokens", 0)
                                model = data.get("model", "")
                        
                        # 设置提取的值
                        doc["_source"]["input_tokens"] = input_tokens
                        doc["_source"]["output_tokens"] = output_tokens
                        doc["_source"]["model"] = model
                        
                        # 仅存储message对象，而不是整个response
                        if message_object:
                            doc["_source"]["message"] = message_object
                            # 移除完整响应，只保留message对象
                            doc["_source"].pop("response", None)
                        else:
                            # 如果找不到message对象，保留一个空的message字段
                            doc["_source"]["message"] = {}
                        
                        # 提取输入内容 - 从body.messages中提取用户消息
                        if "body" in data and "messages" in data["body"]:
                            user_messages = [m for m in data["body"]["messages"] if m.get("role") == "user"]
                            if user_messages:
                                doc["_source"]["input"] = user_messages[0].get("content", "")
                        elif "messages" in data:
                            user_messages = [m for m in data["messages"] if m.get("role") == "user"]
                            if user_messages:
                                doc["_source"]["input"] = user_messages[0].get("content", "")
                        
                        # 尝试提取模型名称
                        if not doc["_source"]["model"]:
                            doc["_source"]["model"] = data.get("model", "") or data.get("body", {}).get("model", "")
                        
                        docs.append(doc)
                        logger.debug(f"已解析行 {line_number}: custom_id={doc['_source']['custom_id']}, intent={doc['_source']['intent']}")
                    except json.JSONDecodeError:
                        logger.warning(f"跳过无效的JSON行: {line}")
                    except Exception as e:
                        logger.warning(f"处理行 {line_number} 时出错: {e}")
        
        if docs:
            # 批量插入文档
            try:
                success, errors = bulk(es, docs, stats_only=False)
                
                if errors:
                    logger.warning(f"部分文档插入失败: {errors}")
                
                logger.info(f"成功保存到Elasticsearch: {success}条文档，失败: {len(errors) if errors else 0}条")
                return True
            except Exception as e:
                logger.error(f"批量插入文档失败: {e}", exc_info=True)
                
                # 尝试单独插入文档（降级策略）
                logger.info("尝试单独插入文档...")
                success_count = 0
                for doc in docs:
                    try:
                        es.index(index=doc["_index"], id=doc["_id"], body=doc["_source"])
                        success_count += 1
                    except Exception as e2:
                        logger.warning(f"插入文档 {doc['_id']} 失败: {e2}")
                
                logger.info(f"单独插入成功: {success_count}/{len(docs)}条文档")
                return success_count > 0
        else:
            logger.warning("没有有效的文档可保存到Elasticsearch")
            return False
    
    except Exception as e:
        logger.error(f"保存到Elasticsearch时出错: {e}", exc_info=True)
        return False

def process_specific_output_file(file_path):
    """处理特定的批处理输出文件并将其保存到ES
    
    Args:
        file_path: 批处理输出文件路径
        
    Returns:
        bool: 成功返回True，失败返回False
    """
    try:
        if not os.path.exists(file_path):
            logger.error(f"指定的文件不存在: {file_path}")
            return False
            
        logger.info(f"开始处理并保存文件 {file_path} 到Elasticsearch")
        
        # 调用保存到ES函数
        success = save_to_elasticsearch(file_path)
        
        if success:
            logger.info(f"成功将文件 {file_path} 的内容保存到Elasticsearch")
        else:
            logger.error(f"保存文件 {file_path} 到Elasticsearch失败")
            
        return success
    except Exception as e:
        logger.error(f"处理文件时出错: {e}", exc_info=True)
        return False

if __name__ == "__main__":
    # 解析命令行参数
    input_file = sys.argv[1] if len(sys.argv) > 1 else None
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    model_name = sys.argv[3] if len(sys.argv) > 3 else "gpt-4o-mini"
    api_key = sys.argv[4] if len(sys.argv) > 4 else AZURE_OPENAI_API_KEY
    endpoint = sys.argv[5] if len(sys.argv) > 5 else AZURE_OPENAI_ENDPOINT
    deployment_id = sys.argv[6] if len(sys.argv) > 6 else AZURE_OPENAI_DEPLOYMENT_ID
    
    # 如果第一个参数是"--process-file"，则直接处理指定的批处理结果文件
    if input_file == "--process-file" and len(sys.argv) >= 3:
        file_path = sys.argv[2]
        logger.info(f"直接处理批处理结果文件: {file_path}")
        
        success = process_specific_output_file(file_path)
        if success:
            logger.info(f"成功处理文件 {file_path} 并保存到Elasticsearch")
        else:
            logger.error(f"处理文件 {file_path} 失败")
            sys.exit(1)
    
    # 如果第一个参数是"--download-output"，则下载指定的输出文件
    elif input_file == "--download-output" and len(sys.argv) >= 3:
        output_file_id = sys.argv[2]
        logger.info(f"直接下载输出文件，ID: {output_file_id}")
        
        # 验证Azure配置
        config_valid = validate_azure_config(api_key, endpoint, deployment_id)
        if not config_valid:
            logger.error("Azure OpenAI配置无效，请检查环境变量或参数设置")
            sys.exit(1)
            
        try:
            # 初始化客户端并下载文件
            client = AzureOpenAIBatchClient(api_key, endpoint, deployment_id)
            result_file = client.download_output_file(output_file_id)
            logger.info(f"输出文件已下载至: {result_file}")
        except Exception as e:
            logger.error(f"下载输出文件时出错: {e}")
            sys.exit(1)
    else:
        # 确定今天的批处理输入文件名
        today_date = datetime.now().strftime('%Y-%m-%d')
        today_input_file = f"chat-input-{today_date}.jsonl"
        
        # 检查是否存在今天的批处理输入文件
        if os.path.exists(today_input_file):
            logger.info(f"检测到今天的批处理输入文件: {today_input_file}，直接执行批处理流程")
            
            # 使用有效的配置：优先使用命令行参数，如果不存在则使用环境变量
            effective_api_key = api_key or AZURE_OPENAI_API_KEY
            effective_endpoint = endpoint or AZURE_OPENAI_ENDPOINT
            effective_deployment_id = deployment_id or AZURE_OPENAI_DEPLOYMENT_ID
            
            # 验证Azure配置
            config_valid = validate_azure_config(effective_api_key, effective_endpoint, effective_deployment_id)
            if not config_valid:
                logger.error("Azure OpenAI配置无效，请检查环境变量或参数设置")
                sys.exit(1)
                
            logger.info("开始执行Azure OpenAI批处理流程")
            # 执行批处理流程（使用默认的input_file，即当天日期）
            success = process_azure_batch(None, effective_api_key, effective_endpoint, effective_deployment_id)
            if not success:
                logger.error("Azure OpenAI批处理流程失败")
                sys.exit(1)
            else:
                logger.info("Azure OpenAI批处理流程成功完成")
        else:
            # 使用有效的配置：优先使用命令行参数，如果不存在则使用环境变量
            effective_api_key = api_key or AZURE_OPENAI_API_KEY
            effective_endpoint = endpoint or AZURE_OPENAI_ENDPOINT
            effective_deployment_id = deployment_id or AZURE_OPENAI_DEPLOYMENT_ID
            
            # 检查是否有足够的配置（命令行参数或环境变量）执行批处理
            has_valid_config = effective_api_key and effective_endpoint and effective_deployment_id
            
            if has_valid_config:
                logger.info("使用可用的Azure OpenAI配置，开始执行批处理流程")
                
                # 先生成批处理输入文件
                logger.info(f"开始将 {input_file} 转换为批处理格式...")
                convert_success = convert_chat_to_batch(input_file, output_file, model_name)
                
                if not convert_success:
                    logger.error("生成批处理输入文件失败")
                    sys.exit(1)
                
                # 验证配置
                config_valid = validate_azure_config(effective_api_key, effective_endpoint, effective_deployment_id)
                if not config_valid:
                    logger.error("Azure OpenAI配置无效，请检查环境变量或参数设置")
                    sys.exit(1)
                
                # 执行批处理流程
                success = process_azure_batch(input_file, effective_api_key, effective_endpoint, effective_deployment_id)
                if not success:
                    logger.error("Azure OpenAI批处理流程失败")
                    sys.exit(1)
                else:
                    logger.info("Azure OpenAI批处理流程成功完成")
            else:
                logger.info("配置不完整，仅执行文件转换（未提供完整的Azure OpenAI配置）")
                convert_chat_to_batch(input_file, output_file, model_name)
