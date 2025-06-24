# mitmproxy-copilot

此代理服务器通过开源的 mitmproxy 实现，可以参考 [mitmproxy 官方文档](https://docs.mitmproxy.org/stable/) 进行使用。请务必确认不要修改HTTP请求中的任何字段信息，否则可能会被Github检测到并封禁账号；

此代理服务器的主要用于提供如下功能：
1. 记录开发者通过代理服务器上传到Github Copilot的代码片段上下文和生成的代码片段；
2. 用于记录通过开发者的活动信息；
3. 用于记录开发者的代码生成和接受数据；
4. 提取用户消息并保存到日志文件和Elasticsearch；
5. 使用Azure OpenAI批处理API对用户消息进行批量处理，并将结果保存到Elasticsearch索引 `chat-output-YYYY-MM-DD`。


为了简化 mitmproxy 的使用，建议通过容器化部署 mitmproxy-copilot，这样可以避免因为 mitmproxy 的版本不同导致的问题。

1. Dockerfile 用于生成 mitmproxy-copilot 镜像；
2. proxy-es.py 用于在mitmproxy中使用elasticsearch存储数据，可以通过此脚本对mitmproxy进行扩展；
3. Redis 用于存储用户名和密码，用于mitmproxy的认证，和记录访问的用户名；
4. 可以通过对proxy-es.py进行修改，实现更多的功能；

## 已知问题

1. 密码为数字，或数字和字母组合，请不要包含特殊字符，否则可能会导致mitmproxy无法启动；
2. 代理服务器会首先缓存Copilot Chat响应内容，等全部接收后，再转发给IDE，导致增加返回的延时；
3. 代理服务器仅支持基本身份验证，需在Redis中配置用户名和密码；

## 代理服务器支持捕获的域名说明
| 捕获的域名 | 用途 | 内容 | 延时影响 | 说明 |
| --- | --- | --- | --- | --- |
| api.business.githubcopilot.com,api.enterprise.githubcopilot.com| Github Copilot Chat | Chat 请求和响应内容 | 启用：首字符返回延时平均在5-10s；关闭：首字符返回延时平均在1-2s | 启用此URL流量捕获后，代理服务器会首先缓存Copilot Chat响应内容，等全部接收后，再转发给IDE，导致增加返回的延时；关闭此URL流量捕获后，代理服务器不会混存相应内容，透明转发给IDE，无法捕获请求和影响内容；|
| proxy.business.githubcopilot.com,proxy.enterprise.githubcopilot.com | IDE Completion（代码补全等） | IDE Editor中请求和响应内容 | 基本无影响 | 启用此URL流量捕获后，代理服务器会首先缓存Copilot IDE Completion响应内容，等全部接收后，再转发给IDE，导致增加返回的延时；关闭此URL流量捕获后，代理服务器不会混存相应内容，透明转发给IDE，无法捕获请求和影响内容；|
| Copilot-Telemetry.githubusercontent.com,Copilot-Telemetry-Service.githubusercontent.com,telemetry.business.githubcopilot.com,telemetry.enterprise.githubcopilot.com | Github Copilot 遥测数据 | IDE Completion ：代码建议行数/代码接受行数 | 不适用 | 当前不支持Copilot Chat 的遥测数据 |

## 部署架构

![Architecture](https://github.com/nickhou1983/mitmproxy-copilot/blob/main/image.png)

## 资源配置

| 服务器 | 规格 | 数量 | 用途 |
| --- | --- | --- | --- |
| mitmproxy | 4C16G 200GDisk | 1 | 部署mitmproxy
| elasticsearch | 2C8G 500GDisk | 3 | 存储mitmproxy数据
| kibana | 2C8G 200GDisk | 1 | 可视化mitmproxy数据



## 使用方法

### Azure OpenAI批处理与Elasticsearch集成

为了处理用户聊天历史，提供了Azure OpenAI批处理与Elasticsearch集成功能，详见 [README_batch.md](README_batch.md)。

此功能可以：
- 将聊天日志文件转换为批处理输入格式
- 上传到Azure OpenAI并创建批处理任务
- 自动监控任务状态并下载结果
- 将结果保存到Elasticsearch索引 `chat-output-YYYY-MM-DD`
- 支持通过意图分类分析用户查询

### 通过容器化部署 mitmproxy-copilot

1. 在部署mitmproxy的服务器上安装 Docker，参考 [Docker 安装文档](https://docs.docker.com/get-docker/)
```
yum install -y yum-utils
yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
yum install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```
2. 通过 Dockerfile 构建镜像，注意一定要在当前目录下执行
```
docker build . -t mitmproxy-copilot:v1
```

3. 运行容器
```
docker run -d --net="host" mitmproxy-copilot:v1 -v ./creds.txt:/app/creds.txt -v ./proxy-es.py:/app/proxy-es.py
```


### 代理高可用部署



### 客户端配置

1. 安装mitmproxy 服务器信任证书，Mitmproxy 证书位于容器的如下目录：
![alt text](1716267494806.png)
在Windows 操作系统安装mitmproxy 证书，可以参考 [mitmproxy 官方文档](https://docs.mitmproxy.org/stable/concepts-certificates/#installing-the-mitmproxy-ca-certificate-on-windows)
```
certutil -addstore root mitmproxy-ca-cert.cer
```

2. 安装证书后，在IDE中启用代理配置：

![alt text](image-1.png)

配置项如下：

* Http:Proxy 采用如下格式：*http://用户名:密码@代理服务器地址:代理服务器端口*
* Http: Proxy Strict SSL 启用后，IDE会检查Mitmproxy代理服务器的证书。禁用后，IDE 不会检查Mitmproxy代理服务器的证书；

3. 启用代理后，IDE会通过代理服务器访问Github Copilot Chat，代理服务器会记录请求和响应内容；

## 批处理功能说明

### 提取用户消息
`proxy-es.py` 脚本会从HTTP请求中提取最后一条用户消息，并将其保存到：
- 按日期命名的JSONL文件 (`chat-YYYY-MM-DD.jsonl`)
- Elasticsearch索引 (`chat-YYYY-MM-DD`)

### 生成批处理输入
`generate_batch_input.py` 脚本用于生成Azure OpenAI批处理API的输入文件，并可选择执行完整的批处理工作流：

```bash
# 使用方法:
# 1. 自动检测并执行:
python generate_batch_input.py
# (如果存在当天的chat-input-YYYY-MM-DD.jsonl文件，自动执行批处理流程；否则只进行文件转换)

# 2. 仅转换文件:
python generate_batch_input.py [输入文件] [输出文件] [模型名称]

# 3. 完整批处理流程 (转换、上传、创建任务、监控、下载结果):
python generate_batch_input.py [输入文件] [输出文件] [模型名称] [API密钥] [API端点] [部署ID]

# 4. 根据output_file_id直接下载结果文件:
python generate_batch_input.py --download-output [output_file_id] [API密钥] [API端点] [部署ID]
```

#### 默认参数:
- 输入文件: chat-当前日期.jsonl
- 输出文件: chat-input-当前日期.jsonl
- 模型名称: gpt-4o-mini
- API密钥: 从环境变量AZURE_OPENAI_API_KEY获取
- API端点: 从环境变量AZURE_OPENAI_ENDPOINT获取
- 部署ID: 从环境变量AZURE_OPENAI_DEPLOYMENT_ID获取

#### 环境变量配置:
```bash
export AZURE_OPENAI_API_KEY="your-api-key"
export AZURE_OPENAI_ENDPOINT="https://your-endpoint.openai.azure.com"
export AZURE_OPENAI_DEPLOYMENT_ID="your-deployment-id"
```

#### 批处理功能:
1. 判断是否存在今天的Chat-input文件，如果不存在，则生成对应文件
2. 如果存在今天的Chat-input文件，自动执行完整批处理流程（无需额外参数）
3. 使用Azure OpenAI批处理API处理用户消息
4. 每隔120秒自动检查批处理任务状态
5. 任务完成后自动下载结果文件
6. 支持通过output_file_id直接下载批处理结果文件

#### 依赖安装:
```bash
pip install -r requirements.txt
```
