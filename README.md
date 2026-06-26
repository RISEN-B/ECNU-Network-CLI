# ECNU Network CLI

华东师范大学校园网 SRun 认证客户端，用于在命令行环境下登录/登出深澜认证系统。

在服务器、远程终端等无法访问网页登录页面的场景下，通过命令行完成校园网认证。

## 功能

- 登录 / 登出操作
- 一键安装到 `~/.local/bin/`，支持全局使用

## 使用

### 直接使用

```bash
python ecnunet-cli.py              # 登录（默认）
python ecnunet-cli.py login        # 登录
python ecnunet-cli.py logout       # 登出
```

### 安装使用

```bash
# 安装到 ~/.local/bin/
python ecnunet-cli.py install

# 安装后可直接使用
ecnunet              # 登录
ecnunet login        # 登录
ecnunet logout       # 登出
ecnunet uninstall    # 卸载
```

登录时输入学号和密码，密码不会回显。

## 依赖

- Python 3
- requests

```bash
pip install requests
```

## 致谢

本项目的 SRun 认证协议实现参考了 [iskoldt-X/SRUN-authenticator](https://github.com/iskoldt-X/SRUN-authenticator)，在此表示感谢。

## 许可证

本项目基于 [GNU General Public License v3.0](LICENSE) 开源。

如果觉得有用，欢迎给个 Star ⭐
