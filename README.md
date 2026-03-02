# mitmproxy-copilot

此代理服务器通过开源的 mitmproxy 实现，可以参考 [mitmproxy 官方文档](https://docs.mitmproxy.org/stable/) 进行使用。请务必确认不要修改HTTP请求中的任何字段信息，否则可能会被Github检测到并封禁账号；

此代理服务器的主要用于提供如下功能：
1. 记录开发者通过代理服务器上传到Github Copilot的代码片段上下文和生成的代码片段；
2. 用于记录通过开发者的活动信息；
3. 用于记录开发者的代码生成和接受数据；


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

通过 `-v` 参数将宿主机上的 `proxy-es.py` 脚本和 `certs` 证书目录挂载到容器中，方便修改配置而无需重新构建镜像：
```
docker run -d --net="host" \
  -v $(pwd)/proxy-es.py:/app/proxy-es.py \
  -v $(pwd)/certs:/opt/mitmproxy \
  -v $(pwd)/creds.txt:/app/creds.txt \
  mitmproxy-copilot:v1
```

> **说明：**
> - `$(pwd)/proxy-es.py:/app/proxy-es.py` — 挂载宿主机当前目录下的 `proxy-es.py` 脚本到容器中，修改后重启容器即可生效；
> - `$(pwd)/certs:/opt/mitmproxy` — 挂载宿主机当前目录下的 `certs` 证书目录到容器中，该目录包含 mitmproxy 的 CA 证书文件；
> - `$(pwd)/creds.txt:/app/creds.txt` — 挂载宿主机当前目录下的用户名密码文件到容器中；

如果首次运行没有现成的证书，可以先不挂载 `certs` 目录，让 mitmproxy 自动生成证书，然后从容器中拷贝出来：
```
# 先启动容器（不挂载证书目录）
docker run -d --name mitmproxy-tmp --net="host" \
  -v $(pwd)/proxy-es.py:/app/proxy-es.py \
  mitmproxy-copilot:v1

# 从容器中拷贝生成的证书到宿主机
docker cp mitmproxy-tmp:/opt/mitmproxy ./certs

# 停止并删除临时容器
docker rm -f mitmproxy-tmp

# 再使用挂载证书目录的方式启动容器
docker run -d --net="host" \
  -v $(pwd)/proxy-es.py:/app/proxy-es.py \
  -v $(pwd)/certs:/opt/mitmproxy \
  -v $(pwd)/creds.txt:/app/creds.txt \
  mitmproxy-copilot:v1
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
