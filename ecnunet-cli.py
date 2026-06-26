#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# ECNU Network CLI
# GitHub: https://github.com/RISEN-B/ECNU-Network-CLI
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
用法:
    python ecnunet-cli.py              # 登录（默认）
    python ecnunet-cli.py login        # 登录
    python ecnunet-cli.py logout       # 登出
    python ecnunet-cli.py install      # 安装到 ~/.local/bin/
    python ecnunet-cli.py uninstall    # 从 ~/.local/bin/ 卸载
"""

import os
import sys
import time
import argparse
import getpass
import hashlib
import hmac
import json
import math
import random
import re
import shutil
from typing import Dict, Any
from pathlib import Path

import requests

BIN_DIR = Path.home() / ".local" / "bin"
BIN_DST = BIN_DIR / "ecnunet"

# ──────────────────────────────────────────────
#  SRun 认证协议实现
# ──────────────────────────────────────────────

class ECNUSrunAuthenticator:
    """华东师范大学 SRun 认证客户端"""

    # SRun 协议固定参数
    _AC_ID = "1"
    _N = "200"
    _TYPE = "1"
    _OS = "Linux"
    _NAME = "Linux"
    _DOUBLE_STACK = "0"
    _ENC_VER = "srun_bx1"

    # 自定义 Base64 字母表 (SRun 特有)
    _SRUN_BASE64_ALPHABET = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"

    def __init__(self, username: str, password: str):
        """
        初始化认证客户端
        
        Args:
            username: 学号
            password: 密码
        """
        self._username = username
        self._password = password
        self._client_ip = ""
        self._challenge_token = ""

        # 初始化会话
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Referer": "https://login.ecnu.edu.cn/srun_portal_pc?ac_id=1&theme=pro"
        })

    @staticmethod
    def _get_timestamp() -> int:
        """获取当前时间戳（毫秒）"""
        return int(time.time() * 1000)

    def _generate_callback_name(self) -> str:
        """
        生成 JSONP 回调函数名
        格式: jQuery<随机大整数>_<时间戳>
        """
        random_part = int(random.random() * 1e19)
        return f"jQuery{random_part}_{self._get_timestamp()}"

    def _custom_base64_encode(self, data: str) -> str:
        """
        SRun 自定义 Base64 编码
        
        Args:
            data: 待编码字符串
            
        Returns:
            编码后的字符串
        """
        result = []
        padding = len(data) % 3
        if padding:
            data += "\0" * (3 - padding)

        for i in range(0, len(data), 3):
            chunk = data[i:i + 3]
            # 合并三个字符为 24 位整数
            combined = (ord(chunk[0]) << 16) | (ord(chunk[1]) << 8) | ord(chunk[2])
            # 拆分为四个 6 位索引
            result.extend([
                self._SRUN_BASE64_ALPHABET[(combined >> 18)],
                self._SRUN_BASE64_ALPHABET[(combined >> 12) & 63],
                self._SRUN_BASE64_ALPHABET[(combined >> 6) & 63],
                self._SRUN_BASE64_ALPHABET[combined & 63]
            ])

        # 处理填充
        if padding == 1:
            result[-1] = "="
            result[-2] = "="
        elif padding == 2:
            result[-1] = "="

        return "".join(result)

    def _xencode(self, message: str, key: str) -> str:
        """
        SRun 自定义加密算法 (BX1)
        
        Args:
            message: 明文消息
            key: 加密密钥
            
        Returns:
            加密后的字符串
        """
        if not message:
            return ""

        def _ord_at(s: str, index: int) -> int:
            """安全获取字符串指定位置的 ASCII 值"""
            return ord(s[index]) if index < len(s) else 0

        def _serialize(s: str, include_length: bool) -> list:
            """将字符串序列化为 32 位整数列表"""
            length = len(s)
            words = []
            # 每 4 个字符合并为一个 32 位整数
            for i in range(0, length, 4):
                word = (
                    _ord_at(s, i) |
                    (_ord_at(s, i + 1) << 8) |
                    (_ord_at(s, i + 2) << 16) |
                    (_ord_at(s, i + 3) << 24)
                )
                words.append(word)
            if include_length:
                words.append(length)
            return words

        def _deserialize(words: list, include_length: bool) -> str:
            """将 32 位整数列表反序列化为字符串"""
            length = len(words)
            total_chars = (length - 1) << 2
            if include_length:
                actual_length = words[length - 1]
                if actual_length < total_chars - 3 or actual_length > total_chars:
                    return ""
                total_chars = actual_length

            chars = []
            for word in words:
                chars.extend([
                    chr(word & 0xFF),
                    chr((word >> 8) & 0xFF),
                    chr((word >> 16) & 0xFF),
                    chr((word >> 24) & 0xFF)
                ])
            return "".join(chars[:total_chars]) if include_length else "".join(chars)

        # 序列化消息和密钥
        msg_words = _serialize(message, True)
        key_words = _serialize(key, False)
        if len(key_words) < 4:
            key_words = key_words + [0] * (4 - len(key_words))
        n = len(msg_words) - 1
        z = msg_words[n]
        y = msg_words[0]
        c = 0x86014019 | 0x183639A0
        m = 0
        e = 0
        p = 0
        q = math.floor(6 + 52 / (n + 1))
        d = 0
        while 0 < q:
            d = d + c & (0x8CE0D9BF | 0x731F2640)
            e = d >> 2 & 3
            p = 0
            while p < n:
                y = msg_words[p + 1]
                m = z >> 5 ^ y << 2
                m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
                m = m + (key_words[(p & 3) ^ e] ^ z)
                msg_words[p] = msg_words[p] + m & (0xEFB8D130 | 0x10472ECF)
                z = msg_words[p]
                p = p + 1
            y = msg_words[0]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (key_words[(p & 3) ^ e] ^ z)
            msg_words[n] = msg_words[n] + m & (0xBB390742 | 0x44C6F8BD)
            z = msg_words[n]
            q = q - 1

        return _deserialize(msg_words, False)

    def _calculate_md5_password(self) -> str:
        """
        计算密码的 MD5 哈希值
        
        Returns:
            密码的 MD5 哈希（十六进制小写）
        """
        return hmac.new(self._challenge_token.encode(), self._password.encode(), hashlib.md5).hexdigest()

    def _calculate_checksum(self, md5_password: str, encoded_info: str) -> str:
        """
        计算请求校验和 (chksum)
        
        Args:
            md5_password: 密码的 MD5 哈希
            encoded_info: 加密后的 info 字段（含 {SRBX1} 前缀）
            
        Returns:
            SHA1 校验和
        """
        checksum_parts = [
            self._challenge_token, self._username,
            self._challenge_token, md5_password,
            self._challenge_token, self._AC_ID,
            self._challenge_token, self._client_ip,
            self._challenge_token, self._N,
            self._challenge_token, self._TYPE,
            self._challenge_token, encoded_info
        ]
        checksum_string = "".join(checksum_parts)
        return hashlib.sha1(checksum_string.encode()).hexdigest()

    def _build_user_info(self) -> str:
        """
        构建用户信息 JSON 字符串（无空格、紧凑格式）
        
        Returns:
            用户信息 JSON 字符串
        """
        info_dict = {
            "username": self._username,
            "password": self._password,  # 注意：此处为明文密码
            "ip": self._client_ip,
            "acid": self._AC_ID,
            "enc_ver": self._ENC_VER
        }
        # 使用紧凑 JSON 格式（无空格，与 JS 的 JSON.stringify 一致）
        return json.dumps(info_dict, separators=(",", ":"))

    def _fetch_client_ip(self) -> None:
        """从登用户信息接口提取客户端公网 IP"""
        response = self._session.get(
            f"https://login.ecnu.edu.cn/cgi-bin/rad_user_info?callback={self._generate_callback_name()}"
        )

        jsonp_match = re.search(r"\((\{.*\})\)", response.text)
        if not jsonp_match:
            raise ValueError("无法解析用户信息响应的 JSONP 数据")

        result: Dict[str, Any] = json.loads(jsonp_match.group(1))
        if 'client_ip' not in result:
            raise ValueError("响应中缺少 'client_ip' 字段")
        self._client_ip = result['client_ip']

    def _fetch_challenge_token(self) -> None:
        """获取服务器挑战令牌 (challenge)"""
        params = {
            "callback": self._generate_callback_name(),
            "username": self._username,
            "ip": self._client_ip,
            "_": self._get_timestamp()
        }
        response = self._session.get(
            "https://login.ecnu.edu.cn/cgi-bin/get_challenge",
            params=params
        )

        # 解析 JSONP 响应
        jsonp_match = re.search(r"\((\{.*\})\)", response.text)
        if not jsonp_match:
            raise ValueError("无法解析 get_challenge 的 JSONP 响应")

        response_data: Dict[str, Any] = json.loads(jsonp_match.group(1))
        if response_data.get("ecode") != 0:
            raise RuntimeError(f"获取 challenge 失败: {response_data.get('error_msg', '未知错误')}")

        self._challenge_token = response_data["challenge"]

    def login(self) -> None:
        """执行完整的登录流程"""
        # 步骤 1: 获取客户端 IP
        self._fetch_client_ip()
        print(f"客户端 IP: {self._client_ip}")

        # 步骤 2: 获取 challenge 令牌
        self._fetch_challenge_token()
        # print(f"Challenge 令牌: {self._challenge_token[:16]}...")

        # 步骤 3: 构建加密参数
        user_info = self._build_user_info()
        encrypted_info = self._xencode(user_info, self._challenge_token)
        encoded_info = self._custom_base64_encode(encrypted_info)
        full_encoded_info = f"{{SRBX1}}{encoded_info}"

        md5_password = self._calculate_md5_password()
        checksum = self._calculate_checksum(md5_password, full_encoded_info)

        # 步骤 4: 发送登录请求
        login_params = {
            "callback": self._generate_callback_name(),
            "action": "login",
            "username": self._username,
            "password": f"{{MD5}}{md5_password}",
            "os": self._OS,
            "name": self._NAME,
            "double_stack": self._DOUBLE_STACK,
            "chksum": checksum,
            "info": full_encoded_info,
            "ac_id": self._AC_ID,
            "ip": self._client_ip,
            "n": self._N,
            "type": self._TYPE,
            "_": self._get_timestamp()
        }

        response = self._session.get(
            "https://login.ecnu.edu.cn/cgi-bin/srun_portal",
            params=login_params
        )

        # 解析登录结果
        jsonp_match = re.search(r"\((\{.*\})\)", response.text)
        if not jsonp_match:
            raise ValueError("无法解析登录响应的 JSONP 数据")

        result: Dict[str, Any] = json.loads(jsonp_match.group(1))
        if result.get("ecode") != 0:
            error_msg = result.get("error_msg", "未知错误")
            raise RuntimeError(f"登录失败: {error_msg}")

        # print("登录成功！")

    def logout(self) -> None:
        """执行登出操作"""

        user_info_params = {
            "callback": self._generate_callback_name()
        }

        user_info = self._session.get(
            "https://login.ecnu.edu.cn/cgi-bin/rad_user_info",
            params=user_info_params
        )

        # 解析用户信息
        jsonp_match = re.search(r"\((\{.*\})\)", user_info.text)
        if not jsonp_match:
            raise ValueError("无法解析 rad_user_info 的 JSONP 响应")
        
        user_info: Dict[str, Any] = json.loads(jsonp_match.group(1))
        if user_info.get("error") != "ok":
            raise RuntimeError(f"获取用户信息失败: {user_info.get('error_msg', '未知错误')}")
        
        self._client_ip = user_info["online_ip"]
        self._username = user_info["user_name"]

        logout_params = {
            "callback": self._generate_callback_name(),
            "action": "logout",
            "username": self._username,
            "ip": self._client_ip,
            "ac_id": self._AC_ID,
            "_": self._get_timestamp()
        }

        response = self._session.get(
            "https://login.ecnu.edu.cn/cgi-bin/srun_portal",
            params=logout_params
        )

        # 解析登出结果
        jsonp_match = re.search(r"\((\{.*\})\)", response.text)
        if not jsonp_match:
            raise ValueError("无法解析登出响应的 JSONP 数据")
        
        result: Dict[str, Any] = json.loads(jsonp_match.group(1))
        if result.get("ecode") != 0:
            error_msg = result.get("error_msg", "未知错误")
            raise RuntimeError(f"登出失败: {error_msg}")
        
        # print("登出成功！")


# ──────────────────────────────────────────────
#  CLI 命令
# ──────────────────────────────────────────────

def is_connected():
    # 使用华为 generate_204 接口检测网络连通性
    url = 'http://connectivitycheck.platform.hicloud.com/generate_204'
    try:
        response = requests.get(url, timeout=5)
        return response.status_code == 204
    except Exception:
        return False

def cmd_login(_args):
    if is_connected():
        print("当前已联网，无需登录。")
        return
    username = input("请输入学号: ").strip()
    password = getpass.getpass("请输入密码: ")
    if not username or not password:
        print("错误：用户名或密码不能为空", file=sys.stderr)
        sys.exit(1)
    try:
        authenticator = ECNUSrunAuthenticator(username, password)
        authenticator.login()
        print("登录成功")
    except Exception as e:
        print(f"登录失败: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_logout(_args):
    try:
        authenticator = ECNUSrunAuthenticator("", "")
        authenticator.logout()
        print("已登出")
    except Exception as e:
        print(f"登出失败: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_install(_args):
    src = Path(__file__).resolve()
    if not src.is_file():
        print(f"错误：找不到可执行文件: {src}", file=sys.stderr)
        sys.exit(1)

    if BIN_DST.exists():
        print(f"已安装到 {BIN_DST}，无需重复安装。")
        return

    BIN_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, BIN_DST)
    BIN_DST.chmod(0o755)
    print(f"已安装到 {BIN_DST}")

    path_dirs = [p for p in os.environ.get("PATH", "").split(":") if p]
    if str(BIN_DIR) not in path_dirs:
        shell = Path(os.environ.get("SHELL", "")).name
        rc_path = Path({"zsh": "~/.zprofile", "bash": "~/.bashrc"}.get(shell, "~/.profile")).expanduser()
        path_line = 'export PATH="$HOME/.local/bin:$PATH"'
        existing = rc_path.read_text() if rc_path.exists() else ""
        if path_line in existing:
            print(f"\nPATH 配置已存在于 {rc_path}，请执行：")
            print(f"  source {rc_path}")
        else:
            ans = input(f"\n{BIN_DIR} 不在 PATH 中，是否自动写入 {rc_path}? (Y/n): ").strip().lower()
            if ans not in ("n", "no"):
                with open(rc_path, "a") as f:
                    f.write(f"\n{path_line}\n")
                print(f"已写入 {rc_path}，请执行：")
                print(f"  source {rc_path}")
            else:
                print(f"请手动添加以下行到 {rc_path}:")
                print(f"  {path_line}")
    else:
        print("\n安装完成，可直接运行: ecnunet")


def cmd_uninstall(_args):
    if BIN_DST.is_file():
        ans = input(f"删除 {BIN_DST}? (y/N): ").strip().lower()
        if ans in ("y", "yes"):
            BIN_DST.unlink()
            print("已删除可执行文件")
        else:
            print("已取消")
    else:
        print(f"可执行文件不存在: {BIN_DST}")
        print("无需卸载")


# ──────────────────────────────────────────────
#  入口
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="ecnunet",
        description="ECNU 校园网 SRun 认证客户端",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("login", help="登录校园网")

    sub.add_parser("logout", help="登出校园网")
    sub.add_parser("install", help="安装到 ~/.local/bin/")
    sub.add_parser("uninstall", help="卸载")

    args = parser.parse_args()

    if args.command is None:
        cmd_login(args)
        return

    {
        "login": cmd_login,
        "logout": cmd_logout,
        "install": cmd_install,
        "uninstall": cmd_uninstall,
    }[args.command](args)


if __name__ == "__main__":
    main()
