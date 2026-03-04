# GitHub Copilot 放行域名清单（汇总）

来源页面：
- https://docs.github.com/en/enterprise-cloud@latest/copilot/reference/copilot-allowlist-reference

更新时间：2026-03-04

> 说明
> - 以下为官方页面汇总结果，按分类整理。
> - 页面以 HTTPS URL 为主，网络策略通常对应 TCP 443。
> - 带 `*` 的为通配匹配。

---

## 1) GitHub Copilot 核心必需（GitHub public URLs）

- `https://github.com/login/*`
- `https://github.com/enterprises/YOUR-ENTERPRISE/*`（仅 Enterprise Managed Users 场景）
- `https://api.github.com/user`
- `https://api.github.com/copilot_internal/*`
- `https://copilot-telemetry.githubusercontent.com/telemetry`
- `https://collector.github.com/*`
- `https://default.exp-tas.com`
- `https://copilot-proxy.githubusercontent.com`
- `https://origin-tracker.githubusercontent.com`
- `https://*.githubcopilot.com/*`
- `https://*.individual.githubcopilot.com`
- `https://*.business.githubcopilot.com`
- `https://*.enterprise.githubcopilot.com`
- `https://*.SUBDOMAIN.ghe.com`（GHE.com 用户）
- `https://SUBDOMAIN.ghe.com`（GHE.com 用户）
- `https://copilot-reports-*.b01.azurefd.net`（Copilot 使用报表下载）

### 订阅路由相关注意（官方脚注）

- 若使用 subscription-based network routing，不应无差别放行：
  - `*.githubcopilot.com/*`
  - `*.individual.githubcopilot.com`
  - `*.business.githubcopilot.com`
  - `*.enterprise.githubcopilot.com`

---

## 2) Copilot Coding Agent 推荐放行（Recommended allowlist）

> 此部分是 Coding Agent 的推荐清单，是否全量放行取决于你是否启用对应语言、包管理器、镜像源与工具链。

### 2.1 Azure 基础设施

- `168.63.129.16`（Azure Metadata Service）

### 2.2 证书颁发机构（CA/OCSP/CRL）

#### DigiCert
- `crl3.digicert.com`
- `crl4.digicert.com`
- `ocsp.digicert.com`

#### Symantec
- `ts-crl.ws.symantec.com`
- `ts-ocsp.ws.symantec.com`
- `s.symcb.com`
- `s.symcd.com`

#### GeoTrust
- `crl.geotrust.com`
- `ocsp.geotrust.com`

#### Thawte
- `crl.thawte.com`
- `ocsp.thawte.com`

#### VeriSign
- `crl.verisign.com`
- `ocsp.verisign.com`

#### GlobalSign
- `crl.globalsign.com`
- `ocsp.globalsign.com`

#### SSL.com
- `crls.ssl.com`
- `ocsp.ssl.com`

#### IdenTrust
- `crl.identrust.com`
- `ocsp.identrust.com`

#### Sectigo
- `crl.sectigo.com`
- `ocsp.sectigo.com`

#### UserTrust
- `crl.usertrust.com`
- `ocsp.usertrust.com`

### 2.3 容器镜像仓库

- `172.18.0.1`
- `ghcr.io`
- `registry.hub.docker.com`
- `*.docker.io`
- `*.docker.com`
- `production.cloudflare.docker.com`
- `auth.docker.io`
- `quay.io`
- `mcr.microsoft.com`
- `gcr.io`
- `public.ecr.aws`

### 2.4 GitHub 内容与 API

- `*.githubusercontent.com`
- `raw.githubusercontent.com`
- `objects.githubusercontent.com`
- `lfs.github.com`
- `github-cloud.githubusercontent.com`
- `github-cloud.s3.amazonaws.com`
- `codeload.github.com`
- `scanning-api.github.com`
- `api.mcp.github.com`
- `uploads.github.com/copilot/chat/attachments/`

### 2.5 GitHub Actions Artifact Storage

- `productionresultssa0.blob.core.windows.net`
- `productionresultssa1.blob.core.windows.net`
- `productionresultssa2.blob.core.windows.net`
- `productionresultssa3.blob.core.windows.net`
- `productionresultssa4.blob.core.windows.net`
- `productionresultssa5.blob.core.windows.net`
- `productionresultssa6.blob.core.windows.net`
- `productionresultssa7.blob.core.windows.net`
- `productionresultssa8.blob.core.windows.net`
- `productionresultssa9.blob.core.windows.net`
- `productionresultssa10.blob.core.windows.net`
- `productionresultssa11.blob.core.windows.net`
- `productionresultssa12.blob.core.windows.net`
- `productionresultssa13.blob.core.windows.net`
- `productionresultssa14.blob.core.windows.net`
- `productionresultssa15.blob.core.windows.net`
- `productionresultssa16.blob.core.windows.net`
- `productionresultssa17.blob.core.windows.net`
- `productionresultssa18.blob.core.windows.net`
- `productionresultssa19.blob.core.windows.net`

### 2.6 语言与包管理器

#### C# / .NET
- `nuget.org`
- `dist.nuget.org`
- `api.nuget.org`
- `nuget.pkg.github.com`
- `dotnet.microsoft.com`
- `pkgs.dev.azure.com`
- `builds.dotnet.microsoft.com`
- `dotnetcli.blob.core.windows.net`
- `nugetregistryv2prod.blob.core.windows.net`
- `azuresearch-usnc.nuget.org`
- `azuresearch-ussc.nuget.org`
- `dc.services.visualstudio.com`
- `dot.net`
- `download.visualstudio.microsoft.com`
- `dotnetcli.azureedge.net`
- `ci.dot.net`
- `www.microsoft.com`
- `oneocsp.microsoft.com`
- `www.microsoft.com/pkiops/crl/`

#### Dart
- `pub.dev`
- `pub.dartlang.org`
- `storage.googleapis.com/pub-packages/`
- `storage.googleapis.com/dart-archive/`

#### Go
- `go.dev`
- `golang.org`
- `proxy.golang.org`
- `sum.golang.org`
- `pkg.go.dev`
- `goproxy.io`
- `storage.googleapis.com/proxy-golang-org-prod/`

#### Haskell
- `haskell.org`
- `*.hackage.haskell.org`
- `get-ghcup.haskell.org`
- `downloads.haskell.org`

#### Java
- `www.java.com`
- `jdk.java.net`
- `api.adoptium.net`
- `adoptium.net`
- `search.maven.org`
- `maven.apache.org`
- `repo.maven.apache.org`
- `repo1.maven.org`
- `maven.pkg.github.com`
- `maven-central.storage-download.googleapis.com`
- `maven.google.com`
- `maven.oracle.com`
- `jcenter.bintray.com`
- `oss.sonatype.org`
- `repo.spring.io`
- `gradle.org`
- `services.gradle.org`
- `plugins.gradle.org`
- `plugins-artifacts.gradle.org`
- `repo.grails.org`
- `download.eclipse.org`
- `download.oracle.com`

#### Node.js / JavaScript
- `npmjs.org`
- `npmjs.com`
- `registry.npmjs.com`
- `registry.npmjs.org`
- `skimdb.npmjs.com`
- `npm.pkg.github.com`
- `api.npms.io`
- `nodejs.org`
- `yarnpkg.com`
- `registry.yarnpkg.com`
- `repo.yarnpkg.com`
- `deb.nodesource.com`
- `get.pnpm.io`
- `bun.sh`
- `deno.land`
- `registry.bower.io`
- `binaries.prisma.sh`

#### Perl
- `cpan.org`
- `www.cpan.org`
- `metacpan.org`
- `cpan.metacpan.org`

#### PHP
- `repo.packagist.org`
- `packagist.org`
- `getcomposer.org`

#### Python
- `pypi.python.org`
- `pypi.org`
- `pip.pypa.io`
- `*.pythonhosted.org`
- `files.pythonhosted.org`
- `bootstrap.pypa.io`
- `conda.binstar.org`
- `conda.anaconda.org`
- `binstar.org`
- `anaconda.org`
- `download.pytorch.org`
- `repo.continuum.io`
- `repo.anaconda.com`

#### Ruby
- `rubygems.org`
- `api.rubygems.org`
- `rubygems.pkg.github.com`
- `bundler.rubygems.org`
- `gems.rubyforge.org`
- `gems.rubyonrails.org`
- `index.rubygems.org`
- `cache.ruby-lang.org`
- `*.rvm.io`

#### Rust
- `crates.io`
- `index.crates.io`
- `static.crates.io`
- `sh.rustup.rs`
- `static.rust-lang.org`

#### Swift
- `download.swift.org`
- `swift.org`
- `cocoapods.org`
- `cdn.cocoapods.org`

### 2.7 基础设施与工具

#### HashiCorp
- `releases.hashicorp.com`
- `apt.releases.hashicorp.com`
- `yum.releases.hashicorp.com`
- `registry.terraform.io`

#### JSON Schema
- `json-schema.org`
- `json.schemastore.org`

#### Playwright
- `playwright.download.prss.microsoft.com`
- `cdn.playwright.dev`
- `playwright.azureedge.net`
- `playwright-akamai.azureedge.net`
- `playwright-verizon.azureedge.net`
- `storage.googleapis.com/chrome-for-testing-public`

### 2.8 Linux 包管理源

#### Ubuntu
- `archive.ubuntu.com`
- `security.ubuntu.com`
- `ppa.launchpad.net`
- `keyserver.ubuntu.com`
- `azure.archive.ubuntu.com`
- `api.snapcraft.io`

#### Debian
- `deb.debian.org`
- `security.debian.org`
- `keyring.debian.org`
- `packages.debian.org`
- `debian.map.fastlydns.net`
- `apt.llvm.org`

#### Fedora
- `dl.fedoraproject.org`
- `mirrors.fedoraproject.org`
- `download.fedoraproject.org`

#### CentOS
- `mirror.centos.org`
- `vault.centos.org`

#### Alpine
- `dl-cdn.alpinelinux.org`
- `pkg.alpinelinux.org`

#### Arch
- `mirror.archlinux.org`
- `archlinux.org`

#### SUSE
- `download.opensuse.org`

#### Red Hat
- `cdn.redhat.com`

#### Common Sources
- `packagecloud.io`
- `packages.cloud.google.com`
- `packages.microsoft.com`

#### Other
- `dl.k8s.io`
- `pkgs.k8s.io`

---

## 3) 建议执行策略（落地）

1. **先最小放行核心域名**：先放行“第 1 节 GitHub public URLs”。
2. **按需放行 Coding Agent 域名**：只启用你实际使用语言/工具对应分类。
3. **变更可审计**：将放行规则按分类分组并保留变更记录。
4. **定期回看官方文档**：GitHub 会更新域名列表，建议按季度复核。
