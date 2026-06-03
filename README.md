# 森岳 2FA

一个可用 Docker Compose 部署的网页端 TOTP 2FA 验证器，支持公司成员共享同一套 2FA 数据。

## 特性

- 服务器端统一生成 6 位 TOTP 验证码
- 账号 Secret 使用公司共享主密码加密后保存到 Docker volume
- 首次输入的主密码会创建共享保险库，之后所有成员使用同一个主密码登录
- Docker Compose 包含 nginx 前端和 Node.js API 后端

## 部署

```bash
git clone https://github.com/SatanDS/senyue-2fa.git
cd senyue-2fa
docker compose up -d --build
```

访问：

```text
http://localhost:8070
```

服务器访问时把 `localhost` 换成服务器 IP 或域名。

如需修改端口，编辑 `docker-compose.yml`：

```yaml
ports:
  - "8070:80"
```

把左侧 `8070` 改成你想暴露的端口即可。

## 更新

```bash
git pull
docker compose up -d --build --force-recreate
```

## 数据保存位置

数据保存在 Docker volume：

```text
senyue-2fa-data
```

其中 Secret 不是明文保存，而是通过共享主密码派生密钥后使用 AES-256-GCM 加密保存。

## 重要说明

- 请妥善保存首次创建保险库时使用的共享主密码。
- 忘记共享主密码后无法恢复已保存的 Secret。
- 公司成员共用同一个主密码即可看到同一套 2FA 数据。
- 建议只在可信网络中使用，并为站点配置 HTTPS 和访问控制后再开放公网访问。