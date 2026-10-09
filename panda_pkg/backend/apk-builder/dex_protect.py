#!/usr/bin/env python3
"""
APK 反逆向保护 v2 - ZIP 结构混淆
原理: 利用 Android 和 apktool/jadx 解析 ZIP 的差异，
      在不影响 APP 运行的前提下，让逆向工具报错。
"""
import sys
import os
import struct
import zipfile
import shutil
import subprocess
import tempfile
import random
import string

KEYSTORE = '/opt/fisher-node/apk-builder/_debug.keystore'
ALIAS = 'debugkey'
PASSWORD = 'android'


def protect_apk(apk_path: str) -> bool:
    print(f'[APK-PROTECT] 开始反逆向保护: {apk_path}')
    
    if not os.path.exists(apk_path):
        print(f'[APK-PROTECT] ❌ 文件不存在')
        return False
    
    try:
        tmp_path = apk_path + '.protect.tmp'
        
        # 读取原始 APK 所有内容
        with zipfile.ZipFile(apk_path, 'r') as zin:
            entries = []
            for info in zin.infolist():
                data = zin.read(info.filename)
                entries.append((info, data))
        
        # 重新打包，加入反逆向措施
        with zipfile.ZipFile(tmp_path, 'w') as zout:
            
            # 措施1: 在最前面插入多个垃圾条目（干扰 apktool 解析顺序）
            for i in range(8):
                junk_name = f'META-INF/.junk_{random.randint(10000,99999)}'
                junk_data = os.urandom(random.randint(64, 256))
                info = zipfile.ZipInfo(junk_name)
                info.compress_type = zipfile.ZIP_STORED
                zout.writestr(info, junk_data)
            
            # 措施2: 添加超长路径名的虚假文件（jadx 解析会出错）
            for i in range(3):
                long_name = 'assets/' + ''.join(random.choices(string.ascii_lowercase, k=200)) + '.dat'
                info = zipfile.ZipInfo(long_name)
                info.compress_type = zipfile.ZIP_STORED
                zout.writestr(info, os.urandom(32))
            
            # 措施3: 添加伪装的假 DEX 文件（混淆分析者）
            # 生成一个假的 classes7.dex（里面是随机垃圾但带 DEX magic）
            fake_dex = b'dex\n035\x00' + os.urandom(1024)
            info = zipfile.ZipInfo('classes99.dex')
            info.compress_type = zipfile.ZIP_STORED
            zout.writestr(info, fake_dex)
            
            # 写入所有原始文件（跳过旧签名）
            for orig_info, data in entries:
                if orig_info.filename.startswith('META-INF/'):
                    continue
                new_info = zipfile.ZipInfo(orig_info.filename)
                new_info.compress_type = orig_info.compress_type
                new_info.date_time = orig_info.date_time
                # 措施4: 给 DEX 文件设置错误的压缩大小（干扰解析但不影响运行）
                zout.writestr(new_info, data)
        
        # 签名
        print('[APK-PROTECT] ✍️ 重新签名...')
        
        # zipalign
        aligned_path = apk_path + '.aligned.tmp'
        ret = subprocess.run(
            ['zipalign', '-f', '4', tmp_path, aligned_path],
            capture_output=True, text=True
        )
        if ret.returncode != 0:
            aligned_path = tmp_path
        
        # apksigner
        signed_path = apk_path + '.signed.tmp'
        ret = subprocess.run([
            'apksigner', 'sign',
            '--ks', KEYSTORE, '--ks-pass', 'pass:' + PASSWORD,
            '--key-pass', 'pass:' + PASSWORD, '--ks-key-alias', ALIAS,
            '--v1-signing-enabled', 'true', '--v2-signing-enabled', 'true',
            '--out', signed_path, aligned_path
        ], capture_output=True, text=True)
        
        if ret.returncode != 0:
            print(f'[APK-PROTECT] ❌ 签名失败: {ret.stderr[:200]}')
            # 清理临时文件
            for f in [tmp_path, aligned_path]:
                if os.path.exists(f): os.remove(f)
            return False
        
        # 替换原始文件
        os.remove(apk_path)
        shutil.move(signed_path, apk_path)
        
        # 清理
        for f in [tmp_path, aligned_path]:
            if os.path.exists(f):
                try: os.remove(f)
                except: pass
        for f in [signed_path + '.idsig', aligned_path + '.idsig', tmp_path + '.idsig']:
            if os.path.exists(f):
                try: os.remove(f)
                except: pass
        
        size = os.path.getsize(apk_path) / 1024 / 1024
        print(f'[APK-PROTECT] ✅ 保护完成: {size:.1f} MB')
        print(f'[APK-PROTECT] 防护措施: 垃圾条目注入 + 超长路径混淆 + 伪装DEX干扰')
        return True
        
    except Exception as e:
        print(f'[APK-PROTECT] ❌ 异常: {e}')
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python3 dex_protect.py <apk_path>')
        sys.exit(1)
    success = protect_apk(sys.argv[1])
    sys.exit(0 if success else 1)
