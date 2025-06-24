## Azure OpenAI批处理与Elasticsearch集成

`generate_batch_input.py` 脚本提供了一个完整的工作流，用于将聊天日志文件转换为Azure OpenAI批处理API的输入格式，提交批处理任务，并将结果保存到Elasticsearch。

### 功能特点

1. 自动将 `chat-YYYY-MM-DD.jsonl` 文件转换为批处理API输入格式
2. 上传文件到Azure OpenAI，创建批处理任务，监控任务状态
3. 下载批处理结果并自动保存到Elasticsearch索引 `chat-output-YYYY-MM-DD`
4. 支持通过环境变量或命令行参数配置Azure OpenAI和Elasticsearch

### 环境变量配置

- Azure OpenAI配置:
  - `AZURE_OPENAI_API_KEY`: Azure OpenAI API密钥
  - `AZURE_OPENAI_ENDPOINT`: Azure OpenAI端点 (如 https://your-resource.openai.azure.com)
  - `AZURE_OPENAI_DEPLOYMENT_ID`: Azure OpenAI部署ID

- Elasticsearch配置:
  - `ES_HOST`: Elasticsearch主机地址 (默认: localhost)
  - `ES_PORT`: Elasticsearch端口 (默认: 9200)
  - `ES_USER`: Elasticsearch用户名 (可选)
  - `ES_PASSWORD`: Elasticsearch密码 (可选)

### 使用方法

#### 1. 仅转换文件

```bash
python generate_batch_input.py [输入文件] [输出文件] [模型名称]
```

#### 2. 完整批处理流程 (转换、上传、创建任务、监控、下载结果并保存到ES)

```bash
python generate_batch_input.py [输入文件] [输出文件] [模型名称] [API密钥] [API端点] [部署ID]
```

#### 3. 根据output_file_id直接下载结果文件并保存到ES

```bash
python generate_batch_input.py --download-output [output_file_id] [API密钥] [API端点] [部署ID]
```

### Elasticsearch索引结构

批处理结果保存到Elasticsearch时使用的索引名为 `chat-output-YYYY-MM-DD`，文档结构如下:

```json
{
  "timestamp": "2023-07-12T15:30:45.123456",
  "custom_id": "task-1",
  "batch_id": "batch_20230712_153045",
  "input": "用户原始输入消息",
  "output": "AI生成的意图分类结果",
  "input_tokens": 50,
  "output_tokens": 10,
  "model": "gpt-4o-mini",
  "intent": "代码审查",
  "response": {
    // 完整的API响应内容
  }
}
```

### 查询示例

以下是一些常用的Elasticsearch查询示例:

#### 按意图分组统计数量

```json
GET chat-output-2023-07-12/_search
{
  "size": 0,
  "aggs": {
    "intents": {
      "terms": {
        "field": "intent.keyword",
        "size": 10
      }
    }
  }
}
```

#### 查找特定关键词的输入

```json
GET chat-output-2023-07-12/_search
{
  "query": {
    "match": {
      "input": "docker container"
    }
  }
}
```

#### 按批次ID查询

```json
GET chat-output-2023-07-12/_search
{
  "query": {
    "term": {
      "batch_id": "batch_20230712_153045"
    }
  }
}
```

### 依赖安装

确保安装所需的Python包:

```bash
pip install requests elasticsearch python-dateutil
```
