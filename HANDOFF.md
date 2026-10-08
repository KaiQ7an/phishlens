# PhishLens 交接说明

更新日期：2026-10-09。先阅读 [AGENTS.md](AGENTS.md)、[README.md](README.md) 和 [CHANGELOG.md](CHANGELOG.md)。

## 项目与当前阶段

PhishLens 是离线 `.eml` 钓鱼迹象分析 CLI，输出可解释的风险分数、文本或 JSON 报告。当前版本为 **0.1.0，尚未正式发布**；源码已公开于 [KaiQ7an/phishlens](https://github.com/KaiQ7an/phishlens)。本轮继续完善解析、评分与验证流程，最终验收前不创建版本标签、GitHub Release 或 PyPI 上传。

工作范围只包含 PhishLens；课程通知整理器 `course-digest` 暂停，不修改它或其他项目。支持 Python 3.11+，运行时仅使用标准库。现有六封示例邮件全部为合成数据，示例表现不代表真实邮件识别准确率。

本机目录：`~/Desktop/Projects/phishlens`；当前分支 `main`，远端 `origin` 为 `git@github.com:KaiQ7an/phishlens.git`。开发虚拟环境使用 Python 3.14.8，已安装普通 wheel；无需重建环境。

## 已确定的工作约定

- 完成一批修改后运行相关检查，按逻辑拆成小提交，再自动 push；用户已授权常规 commit/push。修复与回归测试放在同一提交，CI、打包与文档可另行提交。
- 提交作者使用 `KaiQian Xue <kaiqianxue593@gmail.com>`，不增加 AI attribution 或 `Co-Authored-By`。不重写历史、不 force-push；连接失败时保留本地提交并准确说明状态。
- 安装、CLI、评分或安全边界变化时同步 README；本文件与 CHANGELOG 也应随交接状态更新。检查 `git status`，保留其他人的未提交工作。
- 真实 `.eml` 和生成报告仅在仓库外本地保存；不复制到 fixtures、文档、提交、CI 日志或公开输出。回归测试使用重新编写的合成场景，不包含真实邮件的地址、正文、链接或令牌。

## 安全边界与已知限制

分析不连接收件箱、不请求 DNS 或信誉服务、不访问邮件链接；HTML 不渲染，附件不保存、不执行、不解压。普通附件只在内存中解码和计算 SHA-256。转发邮件及附加 MIME 容器为不透明附件，内部内容不参与外层评分；其 `hash_basis=serialized-mime` 明确表示序列化表示的哈希，可能不同于原始字节。

仅解析最上方 `Authentication-Results`，不独立验证其来源、签名或 DNS。报告保留 `verified: false`；冲突或损坏子句可显示 unknown，并带警告。通过认证或低分都不能证明安全。文本输出转义控制和隐藏格式字符；JSON 转义后保留原始值。

默认输入上限 25 MiB，最多 1,000 个 MIME 部件、深度 30。文件读取有界，但 MIME 限制在标准库完成解析后检查，尚无硬性 CPU、内存或运行时间隔离。当前用于本地检查，不能直接作为公开上传服务。域名后缀、品牌与语言规则有限，误报和漏报仍可能发生。

### Constant Contact 的狭窄校准

`mailings.py` 只识别 `ccsend.com` 发件域及严格匹配的 HTTPS `*.rs6.net/tn.jsp?f=…` 跟踪路由；官方资料链接记录在该模块的 docstring 中。应用校准还要求 SPF/DKIM/DMARC 的记录全为 pass、没有认证或解析警告，且没有其他中高风险正文、附件、头部或链接发现。

在这组有限条件下，普通跨域 Reply-To 和普通站点经此路由的 anchor mismatch 降为低等级提示；最终目标仍明确为 **unverified**。这是路由上下文，不验证发送者、跟踪令牌或最终目标。受保护品牌、仿冒域名、混合文字、登录提示、损坏地址/路由和表单保留正常风险规则；认证失败与其他发现不会被移除。修改前阅读相关边界测试，勿扩展为服务商白名单。

可见链接只接受普通 ASCII 站点名或标准端口 HTTP(S) URL；格式异常、百分号编码和非标准端口均不降权。From/Reply-To 解析缺陷或重复头部会产生警告并禁用校准。表单及其他中高风险 URL 会取消整封邮件的路由降权，与链接顺序无关。

### 标注场景评估

`tests/scenarios.py` 含 36 个先写标签、后跑规则的合成场景：dev 24 个用于发现和修正规则缺口，holdout 12 个**不得用于调参**。`python scripts/evaluate.py`（可加 `--markdown`/`--json`）按集合报告结果；钓鱼场景评为 suspicious 或 high 即算检出。

| 集合 | 精确率 | 召回率 | 修正前召回率 |
| --- | ---: | ---: | ---: |
| dev | 92% | 100% | 33% |
| holdout | 100% | 33% | 17% |

dev 修正包括：显示名参与话术判断、海关/“不要报警”、银行账户变更与包裹/清关费、远程交易（人在海外、钥匙寄送）、扫码请求、SharePoint/OneDrive/Australia Post 品牌别名、正文给出密码的压缩包、HTML/SVG 附件升为 high。holdout 的提升只来自这些通用修正。剩余漏报（tax-refund、crypto-investment、macro-invoice、social-copyright-appeal）和 dev 误报 newsletter-tracked-url-text 记录在 `KNOWN_GAPS`，以 strict xfail 运行；修好后须同时删除对应条目。不要为让 holdout 通过而针对其文本加规则；需要新的未见数据时另写一批 holdout。

## 模块地图

| 模块 / 目录 | 责任 |
| --- | --- |
| `message.py` | 有界文件读取、MIME/地址解析、警告与附件元数据 |
| `auth.py` | 认证子句、注释/引号边界、重复结果与来源声明 |
| `domains.py` / `urls.py` | 域名与仿冒规则、离线链接和可见文字提取 |
| `mailings.py` | 狭窄的邮件服务商路由形状识别 |
| `content.py` / `attachments.py` | 中英文话术与附件文件名规则 |
| `analyzer.py` / `scoring.py` | 组合发现、校准条件、评分与风险等级 |
| `display.py` / `report.py` | 安全转义、文本与 JSON 报告 |
| `cli.py` / `__main__.py` | 安装命令、参数及退出码 |
| `intel.py` | 离线接口占位；尚无外部信誉查询 |
| `tests/` | 合成 fixtures 与回归测试 |
| `tests/scenarios.py` / `scripts/evaluate.py` | 36 个已标注合成场景（dev/holdout）、`KNOWN_GAPS` 与精确率/召回率评估 |
| `scripts/verify_distribution.py` | 检出目录外新环境中的 wheel/sdist 安装与 CLI 检查 |
| `.github/workflows/ci.yml` | 跨版本/平台测试、构建和普通 CI 构件；不发布版本 |

## 接手后的安装与验证

以下命令从项目根目录执行，适用于 macOS/Linux。Windows 使用 `.venv\Scripts\python.exe` 和 `.venv\Scripts\phishlens.exe`；README 有对应安装示例。
已有 `.venv` 时直接激活，跳过创建步骤。

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install '.[dev]' build twine

# 源码修改后重新安装，再验证安装的 CLI。
python -m pip install --force-reinstall --no-deps .
python -m pytest -q
phishlens --version
phishlens analyze tests/fixtures/clean_newsletter.eml
phishlens analyze tests/fixtures/zh_fake_police.eml --json
git diff --check
```

使用普通安装，避免 `pip install -e`：此开发机器会给 editable 安装的 `.pth` 文件重新加 macOS hidden 标记，导致 Python 跳过它并出现 `No module named 'phishlens'`。普通安装不依赖该机制，但每次改源码后必须重装；仅源码测试通过不代表安装入口已更新。

构建使用新的临时目录，避免旧版本构件混入验证。依赖下载需要网络；后续验证安装使用 `--no-index`，不会上传包：

```bash
phishlens_dist_dir="$(mktemp -d /tmp/phishlens-dist.XXXXXX)"
python -m build --outdir "$phishlens_dist_dir"
python -m twine check "$phishlens_dist_dir"/*
python -m pip download --only-binary=:all: --dest /tmp/phishlens-build-deps 'setuptools>=68' wheel
python scripts/verify_distribution.py --dist-dir "$phishlens_dist_dir" --build-deps /tmp/phishlens-build-deps
```

包检查读取 sdist 内的六封合成邮件，在仓库外两个新虚拟环境中分别安装 wheel 和 sdist，核对版本、导入来源、文本/JSON 输出及风险阈值退出码。CI 配置覆盖 Linux Python 3.11–3.14，以及 macOS/Windows Python 3.14；这些配置不等同于最新运行已成功。

## 本轮最终验证记录

- 规则修正位于提交 `5472b8a` 及之前，本文件所在文档提交之后推送到 `origin/main`。
- Python 3.14.8 重装 wheel 后：**431 passed, 5 xfailed**（xfail 为已记录的已知缺口）。
- wheel/sdist 构建、`twine check` 及仓库外两个新环境中的离线包检查全部通过；sdist 包含场景与评估脚本。
- 六封公开 fixture：正常邮件 0；五封钓鱼均为 high（suspicious_attachment 因 HTML 附件升级为 85）。README 示例输出已按显示名参与判断后的证据更新。
- 上一个已验证 CI 运行见 [CI 运行](https://github.com/KaiQ7an/phishlens/actions/runs/37727234391)；本轮推送后的 CI 结果需在 GitHub Actions 中核对。

## 下一步优先级

1. 已完成第一批 dev/holdout 标注场景。下一步：将剩余 holdout 漏报类型作为新的 dev 问题研究（避免直接照抄 holdout 文本），再另写一批全新的 holdout 场景检验泛化；补充误报场景（尤其是正常的付款、扫码登录和含密码说明的工作邮件）。
2. 明确许可证，完成陌生用户安装和报告理解的最终检查，再单独执行正式发布步骤。正式发布仍保持延后。
3. 后续可研究更完整的离线域名数据、可配置品牌/语言规则和批量报告。公开 Web 服务或外部信誉查询属于新范围，不能悄悄加入当前离线 CLI。
