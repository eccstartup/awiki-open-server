# 普通群 Base v1→v2 运维迁移

本工具只操作已由 Open Server 托管、具备原 Group DID/Key 的群，不替远端 Host 迁移，也不把缺失权威材料的 Legacy 本地群自动伪装成标准托管群。实现状态及公网验证见工作区升级计划的 execution.md。

## 前置条件

先按现有运维流程备份完整数据与签名材料，再在维护窗口升级依赖、代码和 SQLite schema。必须确保恢复服务时运行包含协议写入保护的新代码；旧进程不识别 quiescing，不能与新工具并存写入。

脚本的修改动作要求 `--stopped-unit`，检查指定受管 unit 已加载、inactive、MainPID=0。必须填写实际管理该数据目录的 Open Server unit，不得用无关 unit 绕过。直接启动的开发进程应先交给受管入口；脚本没有忽略运行状态的开关。测试代码可以在隔离 ASGI 数据目录调用同一内部实现验证事务。

运行脚本使用与服务相同的配置环境，特别是 Service DID、公共地址和签名材料。`--data-dir` 和 `--group-did` 必填；没有“默认全部迁移”。先用只读 inspect 确定快照摘要，修改必须提供该摘要。

## 操作顺序

```bash
# 只读预检，不初始化或修改数据库。
uv run --locked python scripts/migrate_group_protocol.py inspect \
  --data-dir /path/to/data --group-did 'did:wba:example.test:groups:...'

# 停止实际受管服务后，冻结此群并创建独立完整备份。
uv run --locked python scripts/migrate_group_protocol.py prepare \
  --data-dir /path/to/data --group-did 'did:wba:example.test:groups:...' \
  --plan-digest '<inspect 返回摘要>' --backup-dir /path/outside-data/backup \
  --stopped-unit awiki-open-server.service

# 有旧投递时，仅启动已包含协议保护的新版本，让原 worker 排空；随后再次停止服务。
# 无 pending/retry/in-flight/未解决 dead，且真实远端 Home 支持 v2 时才切换。
uv run --locked python scripts/migrate_group_protocol.py apply \
  --data-dir /path/to/data --group-did 'did:wba:example.test:groups:...' \
  --plan-digest '<原摘要>' --stopped-unit awiki-open-server.service
```

prepare 后该群拒绝新 mutation/send/rebind，保留读取和原队列排空。备份包含一致 SQLite、objects、group keys、实际 token 签名材料及配置中的 Service key；目标目录权限 0700，文件 0600，manifest 记录摘要。备份失败保留可见 preparing 状态，可换新备份目录重试或在切换前 cancel；不会覆盖既有备份。

apply 在网络发现结束后重新检查清单、准备代次、备份、群状态和队列，再以一个 SQLite 事务切换归属与 Group DID 文档。保留原 DID/Key/成员 DID/角色/历史对象/业务序号；只增加 DID 文档修订，新签名用于新文档，旧 proof/Receipt 不改。相同摘要重复 apply 不重复切换。工具拒绝尚未处理的旧 delivery，不能改 profile 或假报 delivered。

切换前可用同样的参数执行 `cancel`，仅解除该群写入暂停，不回退已完成投递。apply 后不提供自动在线降级。**恢复完整旧备份之前必须让整个服务停止，并确认所有数据域都没有需要保留的新写入；仅“本群没有新消息”不足以恢复整个 SQLite。** 有新写入时保留当前数据并向前修复。

切换后需重新启动受管服务并验证真实客户端：原 Group DID 可收发，当前成员和角色不变，旧历史/Receipt/附件可读，退出/移除立即失权，两个商业互通方向通过。未处理的群和队列逐项保留为阻塞，不能以其他群成功代替。

## 原始版本数据回归

拥有完整 Git 历史时可显式运行：

```bash
AWIKI_RUN_PROTOCOL_BASELINE=1 uv run --locked pytest \
  tests/test_original_version_upgrade.py -q --tb=short --show-capture=no
```

该测试从冻结提交 `8c6a6fcc450693ef3e100b8e509d54fddc7f9656` 导出只读历史源码包，在独立子进程中核对实际导入路径，用原版 RPC 创建身份、群、消息、附件和已读状态。随后候选代码打开同一数据库并执行 prepare/apply，核对原历史表摘要、Group DID/Key、分页正文/Receipt、附件下载摘要、连续序号和已读推进，并验证重启后读取。测试不创建 worktree、不修改历史源码，不用 SQL 构造业务状态；生成的测试凭据仅保存于私有临时目录。

这是原始数据的 owning protocol/storage gate，不代替最终正式 CLI、公网商业互通或旧 outbox 排空验收。它不覆盖带未完成远端投递的群，不能据此宣布这类群可迁移。

设置 `AWIKI_CLI_BIN=/path/to/candidate-awiki-cli` 后，同一测试模块会额外运行隔离 HTTPS 的真实 CLI 验收，通过 `--migration id import-v1` 导入原 RPC 身份备份，保持原成员 DID。该用例覆盖群历史/继续收发，并检查 Direct 历史、附件与已读；必须以整条用例的结果判定，不能用群子集通过替代后续步骤。当前候选 14 已通过该完整普通读取/收发 gate，修复及精确制品结果见工作区 execution.md；这不代替远端旧 outbox 排空、最终正式 CLI 或可靠 listener 的验收。

同一 opt-in 模块还包含 `test_original_signed_outbox_drains_before_protocol_cutover`：两个原版本 HTTPS 进程通过真实 RPC 创建跨域群，对端离线产生 retry/pending；新 worker 发送原 v1 通知并确认去重/FIFO，升级 Member Home 后才原地切换群并验证双方 v2 收发。它使用独立 namespace，不修改主机 hosts，不修改 outbox payload/status 来凑过验收。

迁移工具以成员文档绑定的 Member Home 自身能力判断 v2 支持，同时要求 Home 的 service DID 和 endpoint 与原绑定一致。不能只因为成员已签名的旧服务 profile 仍为 v1，就判定它的 Home 尚未升级。
