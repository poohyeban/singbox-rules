# passwall2-rules

[English](README.md) | **简体中文**

为 **PassWall2 + Xray** 独立分流规则组生成 China、Google、OpenAI、AdGuard、WhatsApp、Instagram、Facebook 七类规则。
每天自动获取公开数据源，保留可用的域名正则，生成可阅读的明文规则与原生
`geosite.dat`、`geoip.dat`。规则只定义匹配范围，出口由 PassWall2 中的选择决定。

## 使用地址

在 PassWall2 的规则管理页面填写：

**Geosite 更新地址**

```text
https://raw.githubusercontent.com/poohyeban/passwall2-rules/main/dist/geosite.dat
```

**GeoIP 更新地址**

```text
https://raw.githubusercontent.com/poohyeban/passwall2-rules/main/dist/geoip.dat
```

同路径提供 `.sha256sum` 校验文件。下载地址是两个全局数据文件；各分类通过下列
标签使用，不是在域名框里填写 HTTP 链接。

| 新分流规则 | 域名框 | IP 框 | 出口 |
|---|---|---|---|
| AdGuard | `geosite:pooban-adguard` | 留空 | 屏蔽 |
| OpenAI | `geosite:pooban-openai` | `geoip:pooban-openai` | 指定代理 |
| Google | `geosite:pooban-google` | 留空 | 指定代理 |
| WhatsApp | `geosite:pooban-whatsapp` | 留空 | 自行选择 |
| Instagram | `geosite:pooban-instagram` | 留空 | 自行选择 |
| Facebook | `geosite:pooban-facebook` | 留空 | 自行选择 |
| China | `geosite:pooban-china` | `geoip:pooban-china` | 直连 |

新建独立规则组，并让正在使用的 Xray 分流节点选择该组。网络选择 TCP + UDP；
通常按表中顺序排列，最后设置未匹配流量的默认出口。应用特定的放行需求应显式
处理，不要把 AdGuard 的上游例外一律设置为直连。

**首次切换需要同时准备新规则组、分流节点选择和两个数据文件。** 本库不包含
内置 `cn`、`google`、游戏等分类，不用于兼容旧规则组。旧配置仍引用那些分类时，
不要只替换数据文件并重启。本仓库不自动连接或部署到任何路由器。

### 与远程 rule-set 的区别

PassWall2 26.9.16 的 `rule-set:remote:` / `rule-set:local:` 用于 Sing-box；Xray
生成器会跳过这些条目，且也不支持通过该界面传入 `ext:`。只填不支持的条目可能
使域名/IP 条件为空。因此本仓库不发布伪装为 Xray 远程规则集的 `.list` 或 `.srs`。

Geo 数据不携带 Shadowrocket 的 `no-resolve` 属性。是否为 IP 规则解析域名由 Xray
的 `domainStrategy`、DNS 和入站设置决定，不能靠换一个文件名模拟。


### WhatsApp / Instagram / Facebook

三类规则分别使用 `geosite:pooban-whatsapp`、`geosite:pooban-instagram`、
`geosite:pooban-facebook`，均已写入同一个 `dist/geosite.dat`。IP 框留空。
可阅读规则位于 `rules/WhatsApp/domains.txt`、`rules/Instagram/domains.txt`、
`rules/Facebook/domains.txt`，只含匹配条件。

主源为 v2fly 对应的三个独立分类，复用 Google 下载的同一仓库快照并递归展开
include；辅助源为 SukkaW/Surge 的原始 `Source/non_ip/global.conf`。
使用与 loon-rules 相同的审核映射 `data/Meta/sukka-review.json`，按服务归类，
补充 `instagr.am`、`accountkit.com`、`f8.com`。不额外合入 Messenger、Threads、
Oculus、Meta 综合站点或宽泛品牌关键词。未分类的辅助根域名记录待审；
审核映射不会重新注入上游已删除的条目。数据直接来自原始上游，不转换 Loon 成品。

保留 Xray 的精确、后缀、关键词和原生正则语义；只在同类中做去重与安全后缀覆盖
压缩，不添加整个 Meta ASN 或 IP 大段。域名分类不保证覆盖纯 IP 的音视频连接。
manifest 记录源哈希、展开分类和全部辅助筛选结果。现有定时 Action 自动更新，
发布前由真实 Xray 验证三个标签及跨服务不命中、伪装后缀不命中等边界。

## 数据源

| 分类 | 来源 |
|---|---|
| Google 域名 | 单个仓库快照中完整展开的 [v2fly Google](https://github.com/v2fly/domain-list-community/blob/master/data/google)，包含 YouTube、Google Play 等子分类 |
| China 域名 | [v2fly release/cn.txt](https://raw.githubusercontent.com/v2fly/domain-list-community/release/cn.txt) |
| China IPv4/IPv6 | [P3TERX GeoLite2 Country](https://github.com/P3TERX/GeoLite.mmdb)，仅 `country.iso_code == CN` |
| OpenAI 域名 | [v2fly openai](https://github.com/v2fly/domain-list-community/blob/master/data/openai) + `data/OpenAI` 中审核过的官方域名快照减去显式排除条目 |
| OpenAI ASN | 同一 P3TERX GeoLite2 ASN 数据库中的 AS401518、AS401864；不扩大到整个 Azure/Cloudflare 等共享网络 |
| OpenAI Voice | [官方 chatgpt-voice.json](https://openai.com/chatgpt-voice.json) |
| AdGuard | [官方 AdGuard DNS Filter](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt) |

China 表示上游数据分类，不等同于“仅中国公司所有的域名”。OpenAI 官方域名
快照需要人工复核；每天构建不代表每天重新审核 Help Center 页面。共享第三方
依赖的排除只作用于该快照，不删除其他独立来源中的规则。
ASN 数据库可能暂时没有某个目标 ASN 的记录；manifest 会分别记录数量（包括 0），
不猜测缺失网段。两个目标 ASN 合计为空时构建失败。

### Google 覆盖范围与上游选择

`pooban-google` 使用 v2fly 的完整 `google` 分类，从**同一个仓库压缩包快照**递归
展开全部 include。审核时包含 YouTube（视频/CDN/Music）、Google Play、Android、
Firebase、DeepMind、FCM、Blogger、Scholar 及开发者服务。父级规则还覆盖 Gmail、
Drive、Maps、Photos、Gemini、Google APIs 和 Cloud 服务域名。
manifest 记录压缩包校验值及所有展开分类。每天重新获取；遇到缺失、循环引用或
新增的带过滤条件 include 时停止发布，避免静默改变范围。

使用完整分类，保留 `@cn` 和 `@ads` 条目，包括 `google.cn`、`googleapis.cn`、
`gstatic.com`、`xn--ngstr-lra8j.com`。**Google 必须放在 China 前面**，这样同时属于
China 的 Google 域名才能优先走 Google 出口。若上方启用 AdGuard，命中广告规则的
Google 广告和追踪域名仍会被拦截；Google 不会覆盖这一策略。

上游比较：

| 候选 | 结论 |
|---|---|
| [v2fly Google](https://github.com/v2fly/domain-list-community/blob/master/data/google) | 采用：明确包含 YouTube、Google Play，保留原生匹配语义，与现有域名来源一致。 |
| [blackmatrix7 Google](https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Clash/Google) | README 明确说明不包含 YouTube，需要额外组合分类。 |
| [MetaCubeX meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) | 可用的聚合分发项目；本库直接取 v2fly，来源和 include 展开过程更简单。 |

**不提供 `geoip:pooban-google`，IP 框留空。** 大范围 Google 网段可能包含第三方
Cloud 租户，不能准确代表 Google 服务。域名列表仍按上游保留 `appspot.com`、
`run.app` 等共享托管后缀，因此这些后缀下的租户也会匹配；第三方自定义域名不会
自动被视为 Google。覆盖范围依赖上游维护，不能保证识别所有未来新增端点或
只有 IP、没有可识别域名的连接。不加入泛化的 `google` 关键词或猜测网段。

原有下载地址及分类名保持不变。在 PassWall2 更新 Geosite 后，在独立集合中新建
Google 规则，选择 TCP + UDP、指定代理出口，并放在 China 上方。只更新数据文件
不会自动启用新分流。

## 架构

```text
data/OpenAI/             人工审核域名及排除清单
scripts/                下载、独立转换器、DAT 编码、验证、隐私检查
tests/                  语义回归测试
rules/
  China/
    Sources/            v2fly 域名、GeoLite Country IP
    domains.txt
    ip.txt
  Google/
    Sources/            完整展开的 v2fly Google 分类
    domains.txt
  OpenAI/
    Sources/            v2fly、官方域名、ASN、Voice
    domains.txt
    ip.txt
  AdGuard/
    Sources/            上游原文、转换结果、遗漏原因
    domains.txt
dist/
  geosite.dat           POOBAN-CHINA、POOBAN-GOOGLE、POOBAN-OPENAI、POOBAN-ADGUARD
  geoip.dat             POOBAN-CHINA、POOBAN-OPENAI
  *.sha256sum
  manifest.json         来源校验值、规则数量、产物校验值
```

## 转换边界

- v2fly 的 `domain`、`full`、`keyword`、`regexp` 保持各自语义。正则不展开、不改写
  匹配范围，全部交给真实 Xray 编译校验。未知类型或未展开的 `include:` 会停止构建。
- 官方 `*.example.com` 仅匹配子域名，通过正则保留范围；不会扩大到根域名。
- IP 精确选择来源网段，仅做不扩大地址集合的 CIDR 合并。Voice 前缀应用于所有
  TCP/UDP 目标端口，这是路由分类范围，不是对官方语音防火墙条件的逐项复刻。
- AdGuard 是**保守的域名级子集**。支持精确域名、域名锚点、可表达的主机名模式、
  正则、阻断型 hosts 和 `badfilter`。URL 路径、DNS 重写、上下文修饰符不能直接
  变成无条件域名拦截。`important` 不用于压过例外，可能少拦截，不能多拦截。
- AdGuard 例外在构建时解决。与例外相交或无法证明不相交的阻断规则被整体删除；
  不用几个样例匹配来冒充正则与无限后缀集合的交集证明。无法安全理解的例外使
  整次构建失败。遗漏及原因完整记录在 `rules/AdGuard/Sources/omissions.json`。
- “识别分类”与“访问成功”不同。规则不能保证代理节点可达、DNS 正确或某个服务
  接受出口 IP；也无法从未提供/未嗅探到域名的连接中凭空还原域名。

## 自动更新与验证

GitHub Actions 每天运行两次：UTC 17:17、21:43，即 UTC+8 的次日 01:17、05:43；
也支持手动运行。第二次是补充更新机会，GitHub 调度和上游网络不保证准点成功。
公开仓库长期无活动时 GitHub 可能暂停定时任务，需要维护者检查 Actions 状态。

每次先运行单元测试，再下载来源、校验结构、生成所有分类，使用固定版本
**Xray 26.9.9** 加载两个 DAT，并在本地环回接口测试真实路由选择。测试出口全部
为 blackhole，不访问任何测试域名。最后验证离线重建一致性和发布隐私。

来源失败、空数据、未知结构、重要分类显著缩减、正则错误或测试失败时，不提交
半成品，已发布版本继续保留。产物或来源校验信息变化才提交；不添加本机生成时间戳。
旁路由需要另行启用规则更新；GitHub 更新不会自动推送进路由器内存。

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m scripts.fetch_xray
.venv/bin/python -m scripts.build
.venv/bin/python -m scripts.verify
.venv/bin/python -m scripts.build --offline
.venv/bin/python -m scripts.privacy --history
```

官方 Xray 测试程序固定下载版本和 SHA-256，支持 Linux x86_64、macOS arm64；程序
和下载缓存只在被忽略的 `build/` 下，不随仓库发布。生成依赖固定为 maxminddb 3.1.1。

## 隐私与许可

公开内容只包含通用代码、公开上游规则和说明。提交使用通用 GitHub Actions
机器人身份；不上传路由器地址、节点认证、流量记录、个人邮箱、机器名或本地路径。

生成器采用 MIT；各来源数据继续遵循上游许可。特别是 AdGuard 衍生部分保留 GPLv3，
GeoLite 数据保留其许可和 MaxMind 署名。详见 [NOTICE.md](NOTICE.md) 和 `licenses/`。
