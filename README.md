# singbox-rules

独立的 sing-box 分流规则仓库。完整复用 [passwall2-rules](https://github.com/poohyeban/passwall2-rules) 的上游来源、七类规则、包含关系、人工审核输入、排除项、CIDR 合并和安全检查，生成官方 JSON 源规则及 `.srs` 二进制规则集。构建和自动更新只写入本仓库。

参考逻辑固定于 [`fdb978f07ef6205866f85128468fa5505e2c68eb`](https://github.com/poohyeban/passwall2-rules/tree/fdb978f07ef6205866f85128468fa5505e2c68eb)，以逐字节未修改的副本保存在 `vendor/passwall2/`，文件哈希记录于 [reference.lock.json](reference.lock.json)。原仓库的 39 项单元测试和原生 Xray 回归检查也被复用。上游数据每日重新抓取；参考仓库构建逻辑或审核输入发生变化时，自动报告并停止发布，待人工审查后更新快照。

## 规则与文件

| 分类 | 保留的选择范围 | 合并规则集 |
| --- | --- | --- |
| China | v2fly `cn` release；GeoLite2 Country 的 `country.iso_code == CN`，IPv4 与 IPv6 | `pooban-china` |
| Google | v2fly `google` 的完整递归 include 树，保留原仓库包含的 CN/ads 数据 | `pooban-google` |
| OpenAI | v2fly OpenAI＋已审核官方域名及排除项；GeoLite ASN 401518/401864＋官方 Voice 前缀 | `pooban-openai` |
| AdGuard | 原仓库相同的保守主机名投影、例外、badfilter 与省略策略 | `pooban-adguard` |
| WhatsApp | v2fly WhatsApp＋审核后的 Sukka 服务补充 | `pooban-whatsapp` |
| Instagram | v2fly Instagram＋审核后的 Sukka 服务补充 | `pooban-instagram` |
| Facebook | v2fly Facebook＋审核后的 Sukka 服务补充，保留与其他 Meta 服务的边界 | `pooban-facebook` |

每类均提供 `rule-set/<名称>.json` / `.srs`，以及 `<名称>-domain.json` / `.srs`。China、OpenAI 另提供 `<名称>-ip.json` / `.srs`。共 16 对规则集，每个文件附带 SHA-256 校验文件。合并规则集中的域名与目的 IP 是 OR 关系；DNS 域名策略应使用 `-domain` 版本。

`rules/` 保留原构建器生成的可读规则和逐来源明细。`Sources/` 文件是审计输入，不是可直接订阅的 sing-box JSON。原 Xray DAT 仅在忽略的构建目录中用于交叉验证，不作为本仓库的发布格式。

## 匹配语义

| 原仓库的解析类型 | sing-box 字段 | 范围 |
| --- | --- | --- |
| `full` | `domain` | 精确域名 |
| `domain` | `domain_suffix` | 顶级域名本身及其子域名，保留标签边界 |
| `keyword`，包括解析后的裸字符串 | `domain_keyword` | 原始子串匹配 |
| `regexp` | `domain_regex` | 原表达式逐字节复制，不改大小写、锚点或转义 |
| IPv4/IPv6 CIDR | `ip_cidr` | 原前缀、地址族和目的 IP 范围 |

审核域名中的 `*.example.com` 保留为只匹配子域名的原始正则，不能变成会额外匹配 `example.com` 的后缀规则。规则集不携带代理节点、出站策略、DNS 解析策略或 `rule_set_ip_cidr_match_source` 设置；使用者应保持目的 IP 匹配。路由策略示例将 Google 放在 China 之前，以保留重叠域名的优先级。

以 **2026-10-11 的最新稳定版 sing-box 1.14.3** 官方文档为依据，使用文档仍支持的 source/SRS **版本 2**，因为本仓库仅使用上述基础字段，并受益于该版本的后缀存储优化。官方 1.14.3 编译所有 `.srs`，官方 1.13.0 和 1.14.3 同时加载 JSON/发布的 SRS 并执行原生路由测试。每日更新还验证当日最新稳定版；更早版本未在本项目中承诺运行兼容。

官方依据：[Rule Set](https://sing-box.sagernet.org/configuration/rule-set/)、[Source Format](https://sing-box.sagernet.org/configuration/rule-set/source-format/)、[Headless Rule](https://sing-box.sagernet.org/configuration/rule-set/headless-rule/)。具体转换与验证边界见 [docs/semantics.md](docs/semantics.md)。

## 使用

本仓库保持私有即可使用。通过已认证的 GitHub 客户端克隆或下载规则文件，使用本地规则集配置；私有仓库的 raw URL 不支持匿名订阅，也不应在订阅 URL 中放入访问令牌。

```sh
git clone https://github.com/poohyeban/singbox-rules.git
cd singbox-rules
sing-box check -c examples/local.json
```

[examples/local.json](examples/local.json) 是可检查的本地路由示例，示例中的出站为 `direct`，需要按实际使用场景替换。AdGuard 使用显式拒绝动作，其他分类仅示范路由顺序。仓库是否公开由数据分享需求决定，不影响生成和自动更新。

## 自动更新与验证

[GitHub Actions](.github/workflows/update.yml) 每天台北时间 **01:17、05:43** 更新，也支持手动运行、相关代码推送及 PR 验证。流程依次检查参考快照、运行两套单元测试、下载校验后的官方工具、抓取原来的全部来源、构建并交叉验证、执行离线确定性重建。所有步骤成功后，才将规则和报告一起提交到本仓库的 `main`。GitHub 调度可能延迟。

发布门槛包括：

- 所有可读规则和来源文件与未修改参考构建结果的完整哈希清单一致。
- 每个 JSON 的域名类型、表达式、CIDR 清单与参考结果完全一致，阻止遗漏和范围扩大。
- 每个发布的 `.srs` 与官方 1.14.3 从对应 JSON 重新编译的完整字节完全一致。
- 真实 Xray 与各 sing-box 版本在独立回环环境中检查七类规则、CIDR 边界、通配符、优先级及每一条源正则；测试流量不会发往外部目标。
- 相同原始输入的离线重建必须产生完全相同的全部规则、二进制及报告。
- 保留原构建器的最低规则量和超过 35% 的异常缩减检查。

## 无法等价表达的内容与报告

本项目承诺与 **PassWall2 仓库已经解析的规则集合** 等价。原仓库的 AdGuard 主机名投影本来就不是整个 AdGuard 过滤语言：条件规则、重定向、无法安全处理的例外交集等可能被省略或保守降级。这些已有处理保持原样，并完整保留在 [AdGuard 诊断](rules/AdGuard/Sources/omissions.json) 和 [参考来源清单](reports/reference-manifest.json)；它们不会被伪装成 sing-box 的完整 AdGuard 转换。

[转换报告](reports/conversion.json) 单独列出新增转换省略数量、分类计数、字段映射和完整正则。初始构建的新增转换省略为 **0**；继承的 AdGuard 诊断为 **762** 条。当前 GeoLite ASN 数据没有 AS401864 记录，OpenAI 选出的 IP 中也没有 IPv6；这些事实保留在来源报告中，不猜测或补造前缀。China 和独立回归夹具均验证 IPv6。

遇到未知规则、无法加载的正则、新正则缺少审核过的独立回归样例、参考逻辑漂移或任何验证失败，会停止发布，保留上一版已通过验证的数据。失败原因和源文件位置写入 `build/failure.json`；参考漂移写入 `build/reference-drift.json`，由 Actions 保存为失败诊断附件。新增合法正则时，需要为它增加 [独立正则回归样例](tests/regex_witnesses.json)，防止其他宽泛规则掩盖测试失败。

## 本地构建

CI 每次检查并使用最新稳定版 Python 3（`3.x` + `check-latest`，不含预发布版），同时更新 pip；回归测试通过后才会发布规则。官方二进制下载脚本目前针对 Linux/amd64 构建环境。

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
make PYTHON="$PWD/.venv/bin/python" test
.venv/bin/python -m scripts.reference --remote
make PYTHON="$PWD/.venv/bin/python" tools
make PYTHON="$PWD/.venv/bin/python" build
make PYTHON="$PWD/.venv/bin/python" reproducible
```

`--offline` 只能在完整抓取过全部来源之后使用，缺少缓存会报错。下载地址、原始数据 SHA-256、审核输入 SHA-256、编译版本、验证版本和所有产物 SHA-256 记录于 [reports/manifest.json](reports/manifest.json)。构建器及回归测试采用 MIT；数据许可及修改说明见 [NOTICE.md](NOTICE.md) 和 `licenses/`。
