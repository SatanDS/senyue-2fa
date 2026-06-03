# 森岳 2FA

一个可用 Docker Compose 部署的网页端 TOTP 2FA 验证器，支持公司成员共享同一套 2FA 数据。

## 特性

- 服务器端统一生成 6 位 TOTP 验证码
- 账号 Secret 使用保险库密钥通过 AES-256-GCM 加密保存到 Docker volume
- 所有者可修改所有用户组密码，并可添加、删除账号
- 管理员可添加、删除账号，不能修改用户组密码
- 员工只能查看验证码，不能添加或删除账号
- 点击验证码会自动复制到剪贴板
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

## 无损更新

不会删除已添加账号的更新方式：

```bash
cd /opt/senyue-2fa/senyue-2fa
git pull
docker compose up -d --build --force-recreate
```

不要执行 `docker compose down -v`，也不要删除 Docker volume。

## 权限

- 所有者：最高权限，可修改所有者、管理员、员工三个用户组密码，也可添加和删除账号。
- 管理员：可添加和删除账号，不能修改用户组密码。
- 员工：只能查看验证码并点击复制。
- 旧版本已经创建过保险库时，原来的共享主密码会自动升级为所有者密码继续使用。
- 所有者登录后可以在页面里设置管理员密码和员工查看密码。

## 数据保存位置

数据保存在 Docker volume：

```text
senyue-2fa-data
```

其中 Secret 不是明文保存，而是通过 AES-256-GCM 加密保存。

## 重要说明

- 请妥善保存所有者密码。
- 忘记所有者密码后无法恢复已保存的 Secret，也无法修改其他用户组密码。
- 建议只在可信网络中使用，并为站点配置 HTTPS 和访问控制后再开放公网访问。