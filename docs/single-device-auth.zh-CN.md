# 单设备身份认证与续期

本文件描述当前工作区的单设备协议适配。它不表示已经发布或完成真实 CLI 公网验收；执行状态见工作区 `awiki-plan/20260917-open-server-protocol-upgrade/execution.md`。

## 身份边界

本地域仍只创建 WBA 身份。带 `deviceManifest` 的注册必须携带有效根签名，e1 指纹绑定根公钥，且恰好有一个有效设备。Manifest 的 type、闭合设备字段、签名/密钥协商引用和 verification relationships 使用固定 ANP SDK 校验。根键与设备签名键、密钥协商键的材料必须不同；null/非法 Manifest 不回落到 Legacy 注册。携带私钥材料的文档拒绝发布。

Python ANP 1.0.3 的 Manifest builder 将普通 Group Base v2 当成旧 draft foundation。adapter 只在验证副本中把当前 P1/P2 v1 下的普通 Group Base v2 映射为 Base v1；兼容输入中的既有 all-v2 draft foundation 也只在该副本中规范化，以使用 SDK 检查密钥角色。原签名文档、设备声明和公开 profile 不改变，不将这种验证映射作为 wire 选版或新能力声明。这不启用 P5/P6 或任何加密消息服务。

`single_device_accounts` 每 DID 一行，持久化稳定 account ID、device ID、根键/设备签名键引用、公钥材料指纹和授权代次。没有设备注册表产品、新设备加入、Root Transfer 或 Recovery API。`update_document` 可以更新同一根/设备的普通文档字段，不能替换根或设备、增删 Manifest 或借旧 token 换设备。

## Access token

注册与续期签发 EdDSA JWT，采用现有 Core 的 `awiki.device.access.v1` claims：

- `iss=user-service`，audience 同时含 `awiki-user-service` 和 `awiki-message-service`；
- `sub/did` 是完整 DID，`user_id` 是稳定 account ID；
- 精确 `device_id/key_id/auth_generation`；
- 唯一设备采用 ready-admin scopes：`device:manage`、`device:read`、`message:connect`。scope 不是能力声明，范围外设备管理方法仍不支持；
- `iat/nbf/exp/jti`，其中 `nbf=iat`，jti 每次签发唯一。

服务端仍首先核对数据库中的当前 token 和有效期，再校验签名、claims 及当前文档/持久绑定；不会因为 token 外观像 JWT 就接受。旧 `alg=none` 设备 token 不继续作为有效设备凭据。token、签名 proof 和私钥不进入日志。

已配置 Service Ed25519 key 时复用该受保护材料；未配置时，在 `AWIKI_DATA_DIR/auth-token-key.pem` 原子创建权限 0600 的本地签名键，重启复用。禁止以符号链接或公开权限文件替代。备份/恢复必须包含实际使用的 token 签名材料；切换签名键会使旧 token 失效，客户端需签名续期。

## 签名续期

`POST /user-service/v1/did-auth/rpc` 的 `get_me` 接受已注册唯一设备的 RFC 9421 HTTP Signature。验证实际公共 URL、请求正文 Content-Digest、有效时间和 nonce；根签名或其他授权键不能换取设备 token。

nonce 摘要保存在本地 SQLite，按 key ID 隔离并有期限；原始 nonce 和完整 Signature 不存入日志/表。相同签名重放在应用重建后也被拒绝。有效期最多 600 秒，时钟偏差最多 30 秒。失败请求不得通过 Bearer→签名隐式回落绕过；合法 Bearer `get_me` 只读取用户信息，不顺带续期。

成功设备注册/续期返回 body `access_token`，并在 `Authorization: Bearer ...` 响应头返回相同值，设置 `Cache-Control: no-store`。注册与续期的 account/device/key/generation 保持一致。

canonical DID-auth 凭据失效返回 HTTP 401；根键冒充设备返回 HTTP 403。显式 sync v2 的凭据失效使用 HTTP 401 和 `anp.unauthorized`，消息为 `session_unauthorized`；普通成员权限拒绝不能当作凭据过期反复登录。旧 local v1 façade 保留原响应格式。

公开 DID 字符串在正式模式下不能作为 token。历史 unsigned-dev façade 只允许没有 Manifest/设备绑定的 Legacy 身份使用这一开发兼容方式，不能绕过设备授权。

## 旧数据与验证

新表为增量迁移，不改用户 DID、消息、群、已读或 sync installation。已有有效单设备文档但缺少新绑定的账号，必须通过当前设备签名续期才能建立绑定，不能从旧 token 字符串推断授权。非法旧 Manifest 不自动修补或授予权限；数据保留，具体修复属于逐账号迁移检查。

两端共享 `community-device-access-v1.json` 的公开 claim 模板；真实密钥在测试运行时生成。`tests/test_single_device_auth.py` 覆盖过期、应用重建、签名续期、持久 nonce、防篡改、generation fence、Manifest 负例和根/设备不可替换；`tests/test_community_sync_contract.py` 覆盖 sync v2 的认证错误 fixture。真实进程重启、正式 CLI 接入和公网验收按执行计划另行提供证据。
