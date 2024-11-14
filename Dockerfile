# 使用官方的mitmproxy镜像作为基础镜像
FROM mitmproxy/mitmproxy:10.0.0

# 安装任何额外的依赖项（如果需要）
RUN pip install mitmproxy elasticsearch asyncio azure-identity azure-keyvault-secrets

# 在生产环境中，建议将配置通过Volume 挂载方式挂载到容器中，这样可以方便的修改配置；
# 将您的脚本添加到容器中, 建议可以采用docker -v 将脚本挂载到容器中
# COPY proxy-es.py /app/proxy-es.py
# 将您的proxy 用户名密码本加到容器中，建议可以采用docker -v 将密码本文件挂载到容器中
# COPY creds.txt /app/creds.txt
# 将您的 mitmproxy 的证书加到容器中，建议可以采用docker -v 将证书挂载到容器中
# COPY ./certs /opt/mitmproxy

# 设置工作目录
WORKDIR /app

# 设置环境变量
ENV AZURE_KEY_VAULT_URL=""
ENV AZURE_CLIENT_ID=""
ENV AZURE_CLIENT_SECRET=""
ENV AZURE_TENANT_ID=""

# 设置mitmproxy的启动命令，使用您的脚本作为参数
CMD ["mitmdump","--set", "confdir=/opt/mitmproxy","-s", "proxy-es.py", "-p", "8080", "--listen-host", "0.0.0.0", "--set",  "block_global=false", "--set", "azure_key_vault_url=${AZURE_KEY_VAULT_URL}", "--set", "azure_client_id=${AZURE_CLIENT_ID}", "--set", "azure_client_secret=${AZURE_CLIENT_SECRET}", "--set", "azure_tenant_id=${AZURE_TENANT_ID}"]
