# 使用官方的mitmproxy镜像作为基础镜像
FROM mitmproxy/mitmproxy:10.0.0

# 安装任何额外的依赖项（如果需要）
RUN pip install mitmproxy elasticsearch asyncio redis chardet pathlib typing datetime 

# 在生产环境中，建议将配置通过Volume 挂载方式挂载到容器中，这样可以方便的修改配置；
# 将您的脚本添加到容器中, 建议可以采用docker -v 将脚本挂载到容器中
# COPY proxy-es.py /app/proxy-es.py
# 将您的proxy 用户名密码本加到容器中，建议可以采用docker -v 将密码本文件挂载到容器中
# COPY creds.txt /app/creds.txt
# 将您的 mitmproxy 的证书加到容器中，建议可以采用docker -v 将证书挂载到容器中
# COPY ./certs /opt/mitmproxy

# 设置工作目录
WORKDIR /app


# Mitmproxy 捕获所有流量，适用于Mitmproxy 作为域名过滤的场景
# CMD ["mitmdump", "--set", "confdir=/opt/mitmproxy", "-s", "proxy-es-stream.py", "-p", "8080", "--listen-host", "0.0.0.0", "--set", "block_global=false"]

# Mitmproxy 捕获所有流量，除了--ignore-hosts 中指定的域名，适用于Mitmproxy 作为域名过滤的场景
# CMD ["mitmdump", "--set", "confdir=/opt/mitmproxy", "-s", "proxy-es.py", "-p", "8080", "--listen-host", "0.0.0.0", "--set", "block_global=false", "--ignore-hosts", "(.*vo\\.msecnd\\.net.*|.*default\\.exp-tas\\.com.*|.*visualstudio\\.com.*|.*vscode-cdn.*|.*vsassets\\.io.*|.*gallerycdn\\.azure.*|.*microsoft\\.com.*|.*raw\\.githubusercontent\\.com.*|.*digicert\\.com.*|.*vscode\\.dev.*|.*jetbrains\\.com.*|.*jbstatic\\.com.*|.*mitm\\.it.*|.*applicationinsights\\.azure\\.com.*)"]

# Mitmproxy 只捕获Github域名流量，其他域名均直接转发
CMD ["mitmdump", "--set", "confdir=/opt/mitmproxy", "-s", "proxy-es.py", "-p", "8080", "--listen-host", "0.0.0.0", "--set", "block_global=false", "--allow-hosts", "(.*github\\.com.*|.*githubusercontent\\.com.*|.*githubcopilot\\.com.*)"]

