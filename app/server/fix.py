import os, re, subprocess, sys, zipfile
import nginx_cfg as n

pwd = n.get_password()
zip_path = n.RESTORE_ZIP
conf_path = n.NGINX_CONF

def read_entry(zp, name):
    try:
        with zipfile.ZipFile(zp) as z:
            return z.read(name, pwd=pwd)
    except Exception:
        return None

def strip_patch(raw):
    if raw is None:
        return None
    for enc in ('utf-8', 'gb18030', 'latin-1'):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = raw.decode('utf-8', 'replace')
    if hasattr(n, '_strip_nginx_patch'):
        stripped = n._strip_nginx_patch(text)
    else:
        stripped = re.sub(r'(?s)# >>> FnNginxConf map begin >>>.*?# <<< FnNginxConf map end <<<', '', text)
        stripped = re.sub(r'(?s)# >>> FnNginxConf redirect begin >>>.*?# <<< FnNginxConf redirect end <<<', '', stripped)
    if stripped == text:
        return None
    return stripped.encode(enc)

orig = None
label = None

if pwd:
    raw = read_entry(zip_path, 'nginx.conf.fnnginx.orig')
    if raw is not None:
        orig, label = raw, 'zip 原始备份'
    if orig is None:
        raw = read_entry(zip_path, 'nginx.conf')
        if raw is not None:
            if b'FnNginxConf' not in raw:
                orig, label = raw, 'zip nginx.conf'
            else:
                s = strip_patch(raw)
                if s is not None:
                    orig, label = s, 'zip nginx.conf（剥离补丁）'
    if orig is None:
        bak = zip_path + '.bak'
        if os.path.exists(bak):
            raw = read_entry(bak, 'nginx.conf')
            if raw is not None:
                if b'FnNginxConf' not in raw:
                    orig, label = raw, 'zip .bak'
                else:
                    s = strip_patch(raw)
                    if s is not None:
                        orig, label = s, 'zip .bak（剥离补丁）'

if orig is None:
    for path in ('/tmp/nginx.conf.bad', conf_path):
        try:
            raw = open(path, 'rb').read()
        except OSError:
            continue
        if b'FnNginxConf' not in raw:
            orig, label = raw, path
            break
        s = strip_patch(raw)
        if s is not None:
            orig, label = s, path + '（剥离补丁）'
            break

if orig is None:
    print('NO ORIGINAL FOUND')
    print('请把 /tmp/ng.conf.zip.bad 保留，并把下面信息发我:')
    print('zip entries:', zipfile.ZipFile(zip_path).namelist() if os.path.exists(zip_path) else 'zip missing')
    sys.exit(1)

tmp = conf_path + '.recover.tmp'
with open(tmp, 'wb') as f:
    f.write(orig)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, conf_path)
print('磁盘 nginx.conf 已恢复，来源:', label, '大小:', len(orig))

if pwd:
    print('zip nginx.conf 恢复:', n.upsert_zip_entry(zip_path, pwd, 'nginx.conf', orig))
    print('zip conf.d 清理:', n.remove_zip_entry(zip_path, pwd, 'conf.d/fnnginx_conf.conf'))
    print('zip 原始备份清理:', n.remove_zip_entry(zip_path, pwd, 'nginx.conf.fnnginx.orig'))

r = subprocess.run(['/usr/trim/nginx/sbin/nginx', '-t', '-p', '/usr/trim/nginx'],
                   capture_output=True, text=True)
print('nginx -t:', r.returncode)
print(r.stdout)
print(r.stderr)
if r.returncode == 0:
    r2 = subprocess.run(['systemctl', 'restart', 'trim_nginx'], capture_output=True, text=True)
    print('restart:', r2.returncode, r2.stderr)
else:
    print('nginx -t 失败，先不要重启，把上面输出发我')