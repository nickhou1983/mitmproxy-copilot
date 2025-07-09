Github Copilot URL List

your_allowed_domains = [
    # your enterprices related
    f"https://github.com/{enterprise_slug}/*",
    f"https://github.com/{enterprise_slug}?*",
    f"https://github.com/enterprises/{enterprise_slug}/*",
    f"https://github.com/login?return_to=https%3A%2F%2Fgithub.com%2Fenterprises%2F{enterprise_slug}",

    # anything you like
    # "https://www.google.com/*",
    # "https://www.baidu.com/*",
]

# GitHub Copilot 服务域名列表
# https://docs.github.com/en/copilot/managing-copilot/managing-github-copilot-in-your-organization/configuring-your-proxy-server-or-firewall-for-copilot
github_copilot_official_domains = [
    # Github 登录域名
    "https://github.com/login/*",
    "https://github.com/login/oauth/*",
    "https://api.github.com/user/*",
    "https://api.github.com/copilot_internal/*",
    "https://default.exp-tas.com/*",

    # Github Copilot 旧版本域名
    "https://copilot-proxy.githubusercontent.com/*",
    "https://origin-tracker.githubusercontent.com/*",
    "https://copilot-telemetry.githubusercontent.com/telemetry/*",

    # Github Copilot 服务所有域名，
    # "https://*.githubcopilot.com/*",
    # Github Copilot 个人版域名
    # "https://*.individual.githubcopilot.com/*",
    # Github Copilot 商业版域名，通常需要这个域名即可
    "https://*.business.githubcopilot.com/*",
    # Github Copilot 企业版域名
    # "https://*.enterprise.githubcopilot.com/*",
]

github_public_domains = [
    # Github 登录相关域名
    "https://github.com/favicon.ico",
    "https://github.com/account/*",
    "https://github.com/settings/*",
    "https://avatars.githubusercontent.com/*",

    # Github 帮助文档
    "https://docs.github.com/*",
    
    # others
    "https://github.com/copilot/*",
    "https://raw.githubusercontent.com/*",
    "https://github.githubassets.com/*",
    "https://collector.github.com/*",
    "https://github.com/github-copilot/*",
    "https://collector.github.com/*",
    "https://api.github.com/*",
    "https://github.com/notifications/*",
    "https://github.com/session/*",
    "https://github.com/dashboard/*",
    "https://github.com/dashboard?*",

    # Github 登出相关域名列表
    "https://github.com/logout/*",
    "https://github.com/logout?*",
    "https://github.com/",
    "https://github.com/switch_account?*",
    "https://github.com/switch_account/*",
]

# Microsoft Extra ID Domains and IPs
msft_extra_id_domains = [
    "https://login.microsoftonline.com/*",
    "https://aadcdn.msauth.net/*",
    "https://login.live.com/*",
    "https://*.activedirectory.windowsazure.com/*",
]

# IDE 和 插件安装域名列表
ide_extension_domains = [
    # VSCode
    "*visualstudio.com*",
    "*vscode-cdn*",
    "*vsassets.io*",
    "*gallerycdn.azure*",
    "*microsoft.com*",
    "*raw.githubusercontent.com*",
    "*digicert.com*",
    "https://vscode.dev/*",

    # JetBrains
    "*jetbrains.com*",
    "*jbstatic.com*",
]
