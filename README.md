# shadowrocket-auto

自动收集公共节点，并在本地生成 Shadowrocket 订阅。

## 订阅发布状态

出于凭据保护考虑，本仓库暂不公开发布节点订阅文件。采集结果只在运行环境本地生成，不会提交到 Git 历史；公开工作流仅更新不含节点 URI 的聚合质量报告。请不要把本仓库的公开地址当作可用订阅地址。

如需个人使用，请在可信环境本地运行采集器，并自行通过私有仓库或有访问控制的渠道托管订阅。不要把真实 UUID、密码或私有节点 URI 提交到公开仓库。

## 安全说明

- 订阅源响应上限 2 MiB；每源最多 5,000 条、总计最多 20,000 条候选；单行最多 8 KiB。
- 订阅源仅允许 HTTPS `raw.githubusercontent.com`，禁止自动跟随重定向，避免恶意源配置或跳转访问内网/本机服务。
- 域名解析通过 `getent ahosts` 子进程执行，硬超时为 2 秒；超时会终止解析进程并计入 timeout，不会无限占用采集线程。运行环境需要提供 `getent`（GitHub-hosted Ubuntu runner 默认具备）。
- VMess 主机和端口进行严格类型/范围校验；单个异常节点不会中断整批任务。
- DNS 答案只要包含非公网地址就拒绝；连接时使用已校验的解析结果。
- 每个节点有连接总时限，防止多地址轮询无限拖延。
- 公开工作流只提交不含节点 URI 的聚合质量报告；订阅文件不进入 Git 跟踪或公开发布。
- 无可用节点时保留上一版订阅；报告会标注订阅是否更新。

**重要：Base64 不是加密。** 公开仓库中的订阅任何人都能解码，节点 URI 可能包含 UUID、密码和服务器地址。请只发布你有权公开的节点。私用订阅应使用私有仓库或受访问控制的发布渠道。如果历史提交曾含明文节点或真实凭据，仅删除当前文件不足以消除泄露，应轮换凭据并清理 Git 历史。

DNS 检查只在收集时发生；客户端稍后会重新解析域名，因此无法保证发布后 DNS 不变。不要简单把域名替换成 IP，否则可能破坏 TLS SNI、Host 或证书验证。

## 检测含义

质量报告的检测类型为 tcp_connect_only。TCP 端口可连接不代表代理认证、TLS/传输层握手或实际隧道可用。地区按节点备注/主机名关键词推测，不是 IP 地理定位。

## 本地运行

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python scripts/collector.py
```

本地生成 docs/shadowrocket.txt（Base64 订阅）和 docs/quality_report.json（不含节点 URI 的聚合报告）；订阅文件已加入 .gitignore，请勿提交。

## 配置

订阅源位于 config/sources.txt，每行一个 URL，支持 # 注释。请只添加可信来源。
