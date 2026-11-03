# MySQL 5.7 认证数据地基

本目录实现第 6-9 周阶段二的用户表与建库脚本，覆盖注册、登录、退出和本人信息查询所需的认证五表。

## 范围

- `user_account`：用户身份、口令四列、账号状态和登录保护字段。
- `app_role` 与 `user_role_relation`：系统角色及用户授权关系。
- `session_token`：仅保存令牌摘要、有效期和撤销状态。
- `login_log`：登录结果、内部失败原因和脱敏账号。
- 不包含商品、购物车、订单和支付表。

## 运行环境

- MySQL Server 5.7.44。
- 数据库字符集 `utf8mb4`。
- 服务名 `MySQL57`，默认监听 `127.0.0.1:3306`。
- 仓库不保存 root 密码、应用连接串或其他真实凭据。

`mysql57.ini.example` 是 Windows 本地配置模板，复制为 MySQL 的 `my.ini` 时需要按实际安装路径调整。

## 一条命令建表

先在 MySQL 中创建一个空数据库：

```sql
CREATE DATABASE IF NOT EXISTS cipherbook
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;
```

在仓库根目录使用 Windows 命令提示符执行：

```bat
"C:\Program Files\MySQL\MySQL Server 5.7\bin\mysql.exe" --protocol=TCP --host=127.0.0.1 --port=3306 --user=root -p cipherbook < db\schema.sql
```

脚本只负责在已有空库中建表，不负责创建数据库、数据库账号或授权。

## 结构验收

```bat
"C:\Program Files\MySQL\MySQL Server 5.7\bin\mysql.exe" --protocol=TCP --host=127.0.0.1 --port=3306 --user=root -p --table cipherbook < db\verify_schema.sql
```

所有 `result` 应为 `PASS`，口令列应依次为：

```text
password_algo, password_iterations, password_salt, password_derived
```

表中不得存在 `password_hash`、明文口令或其他可反推口令的字段。

## 与用户模块的字段契约

`src/user/password_port.py` 的 `hash_password()` 返回：

```text
pbkdf2_sha256$600000$<salt_b64url>$<derived_b64url>
```

注册逻辑调用 `split_stored()` 后直接对应四列：

```text
password_algo       = split_stored()["algo"]
password_iterations = split_stored()["iterations"]
password_salt       = split_stored()["salt"]
password_derived    = split_stored()["derived"]
```

登录逻辑用四列重新拼成同一存储串，再调用第 5 周模块的 `verify_password()`。盐固定为 16 字节，派生值固定为 32 字节，对应无填充 base64url 的 22 和 43 个字符。

## MySQL 5.7 注意事项

- MySQL 5.7 会解析但忽略 `CHECK` 约束，因此状态字段使用 `ENUM`，其余边界仍由应用层校验。
- `user_role_relation` 使用生成列和唯一索引，保证每个用户最多一个有效主角色。
- 所有查询必须由数据访问层参数化；本目录只定义结构，不执行用户输入。
- 手机号密文和 HMAC 指纹密钥必须由应用配置或密钥服务提供，不得写入数据库或仓库。
