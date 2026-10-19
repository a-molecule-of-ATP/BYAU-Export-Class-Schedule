# -*- coding: utf-8 -*-
"""教务系统课表 → CSV

每次运行都会弹「登录确认」框，已记住的账号密码预填好，点「开始抓取」才执行；
密码用 DPAPI 加密存在 %APPDATA%\\KbExport\\config.json（隐藏属性）。
学期开始日与总周数由「教学周历」自动识别。

    kb_to_csv.py [out.csv] [--reset] [--yes] [--gui]
    --reset 清空已存账号  --yes 跳过确认框（计划任务）  KB_NO_GUI=1 走命令行
"""
import base64, csv, ctypes, datetime, getpass, json, os, re, ssl, sys, time
import http.cookiejar, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor

FROZEN = getattr(sys, "frozen", False)
HERE = os.path.dirname(sys.executable if FROZEN else os.path.abspath(__file__))
CFG = os.path.join(os.environ.get("APPDATA", HERE), "KbExport", "config.json")
BASE, CAS = "http://10.1.4.41", "https://ids.byau.edu.cn"
SERVICE, MAIN = BASE + "/jsxsd/framework/xsMain.jsp", BASE + "/jsxsd/framework/xsMain_new.jsp"
KB, XKGL, JXZL = (BASE + "/jsxsd/framework/main_index_loadkb.jsp",
                  BASE + "/jsxsd/xkgl/loadXsxkjgList", BASE + "/jsxsd/jxzl/jxzl_query")
MODULUS = ("008aed7e057fe8f14c73550b0e6467b023616ddc8fa91846d2613cdb7f7621e3cada4cd5d812d627af6b87727ade4e26"
           "d26208b7326815941492b2204c3167ab2d53df1e3a2c9153bdb7c8c2e968df97a5e7e01cc410f92c4c2c2fba529b3ee988"
           "ebc1fca99ff5119e036d732c368acf8beba01aa2fdafa45b21e4de4928d0d403")
HDR = ["课程名称", "星期", "开始节数", "结束节数", "老师", "地点", "周数"]

RESET = "--reset" in sys.argv
YES = "--yes" in sys.argv                          # 跳过确认框（计划任务用）
GUI = ("--gui" in sys.argv or FROZEN) and os.environ.get("KB_GUI", "1") != "0"
OUT = next((a for a in sys.argv[1:] if not a.startswith("--")), os.path.join(HERE, "导出课表.csv"))
if sys.stdout is None:                            # pythonw / EXE 无控制台
    sys.stdout = open(os.devnull, "w")

ctx = ssl.create_default_context()
ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
OP = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                                 urllib.request.HTTPSHandler(context=ctx))
OP.addheaders = [("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36")]


def _tk():
    import tkinter as tk
    r = tk.Tk(); r.withdraw(); r.attributes("-topmost", True)
    return tk, r


def notice(msg, err=False):
    """--gui 时弹框（EXE 双击运行时唯一的反馈渠道）"""
    if GUI:
        try:
            tk, r = _tk()
            from tkinter import messagebox
            (messagebox.showerror if err else messagebox.showinfo)("课表导出", msg, parent=r)
            r.destroy()
        except Exception:
            pass


def ask(user="", pwd=""):
    """登录确认框：每次运行都会出现，已保存的账号密码预填好，点「开始抓取」才继续"""
    if not os.environ.get("KB_NO_GUI"):
        try:
            import tkinter as tk
            root = tk.Tk()
            root.title("课表导出 · 登录确认")
            root.attributes("-topmost", True)
            root.resizable(False, False)
            box = tk.Frame(root, padx=18, pady=14)
            box.pack()

            tk.Label(box, text="学号", anchor="e", width=5).grid(row=0, column=0, pady=5)
            e_user = tk.Entry(box, width=26)
            e_user.insert(0, user)
            e_user.grid(row=0, column=1, pady=5)

            tk.Label(box, text="密码", anchor="e", width=5).grid(row=1, column=0, pady=5)
            e_pwd = tk.Entry(box, width=26, show="*")
            e_pwd.insert(0, pwd)
            e_pwd.grid(row=1, column=1, pady=5)

            tk.Label(box, text="已记住账号，直接点「开始抓取」即可" if user else "请输入账号密码",
                     fg="#777").grid(row=2, column=0, columnspan=2, pady=(0, 10))

            res = {}

            def go(event=None):
                res["u"], res["p"] = e_user.get().strip(), e_pwd.get()
                root.destroy()

            def cancel(event=None):
                root.destroy()

            row = tk.Frame(box)
            row.grid(row=3, column=0, columnspan=2)
            tk.Button(row, text="开始抓取", width=10, command=go).pack(side="left", padx=6)
            tk.Button(row, text="取消", width=8, command=cancel).pack(side="left", padx=6)
            root.bind("<Return>", go)
            root.bind("<Escape>", cancel)
            e_user.focus_set()
            root.mainloop()
            if res.get("u") and res.get("p"):
                return res["u"], res["p"]
            sys.exit("已取消")
        except SystemExit:
            raise
        except Exception:
            pass
    print("命令行模式")
    if not sys.stdin or not sys.stdin.isatty():          # 管道输入（脚本/计划任务）
        lines = (sys.stdin.read().splitlines() + ["", ""]) if sys.stdin else ["", ""]
        return lines[0].strip() or user, lines[1] or pwd
    return input(f"学号 [{user}]: ").strip() or user, getpass.getpass(f"密码 [{pwd}]: ") or pwd


class _Blob(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint32), ("ptr", ctypes.POINTER(ctypes.c_char))]


def dpapi(data, protect=True):
    """Windows DPAPI，密文只对当前 Windows 用户可解"""
    src = ctypes.create_string_buffer(data, len(data))
    a, b = _Blob(len(data), ctypes.cast(src, ctypes.POINTER(ctypes.c_char))), _Blob()
    fn = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
    if not fn(ctypes.byref(a), None, None, None, None, 0, ctypes.byref(b)):
        raise OSError("DPAPI 失败")
    try:
        return ctypes.string_at(b.ptr, b.len)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(b.ptr, ctypes.c_void_p))


def hide(path):
    if os.name == "nt":
        try:
            k = ctypes.windll.kernel32
            k.GetFileAttributesW.restype = ctypes.c_uint32
            k.SetFileAttributesW(str(path), k.GetFileAttributesW(str(path)) | 0x02)
        except Exception:
            pass


def save_cfg(user, pwd):
    os.makedirs(os.path.dirname(CFG), exist_ok=True)
    try:
        mode, secret = "dpapi", base64.b64encode(dpapi(pwd.encode())).decode()
    except Exception:
        mode, secret = "b64", base64.b64encode(pwd.encode()).decode()
    with open(CFG, "w", encoding="utf-8") as f:
        json.dump({"user": user, "pwd": secret, "mode": mode}, f)
    hide(CFG)
    return mode


def credentials():
    """总是弹出确认框；--yes 时才直接用已保存的账号（无人值守）"""
    old = None if RESET else load_cfg()
    if YES and old:
        print("使用已保存账号：", old[0])
        return old
    user, pwd = ask(*(old or ("", "")))
    if not old or (user, pwd) != old:
        print(f"凭据已保存到 {CFG}（{save_cfg(user, pwd)}）")
    else:
        print("使用已保存账号：", user)
    return user, pwd


def load_cfg():
    try:
        with open(CFG, encoding="utf-8") as f:
            c = json.load(f)
        raw = base64.b64decode(c["pwd"])
        return c["user"], (dpapi(raw, False).decode() if c["mode"] == "dpapi" else raw.decode())
    except Exception:
        return None


def http(url, data=None, referer=None):
    req = urllib.request.Request(url, urllib.parse.urlencode(data).encode() if data else None)
    if data:
        req.add_header("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
    if referer:
        req.add_header("Referer", referer)
    r = OP.open(req, timeout=30)
    raw = r.read()
    for enc in ("utf-8", "gbk", "gb18030"):
        try:
            return r.geturl(), raw.decode(enc)
        except UnicodeDecodeError:
            pass
    return r.geturl(), raw.decode("utf-8", "replace")


def login(user, pwd):
    url = CAS + "/cas/login?service=" + urllib.parse.quote(SERVICE, safe="")
    html = OP.open(url, timeout=25).read().decode("utf-8", "replace")
    n, chunk = int(MODULUS, 16), 2 * ((len(MODULUS) + 3) // 4 - 1)
    a = [ord(c) for c in pwd]
    a += [0] * (-len(a) % chunk)                  # 网页端同款 RSA 分块加密
    secret = " ".join(format(pow(int.from_bytes(bytes(a[i:i + chunk]), "little"), 65537, n), "x")
                      for i in range(0, len(a), chunk))
    final, _ = http(url, {"username": user, "password": secret,
                          "execution": re.search(r'name="execution"[^>]*value="([^"]+)"', html)[1],
                          "_eventId": "submit", "loginType": "1", "encrypted": "true"}, referer=url)
    print("登录成功" if ("xsMain" in final or "xsrk" in final) else "登录失败", "→", final)
    return "xsMain" in final or "xsrk" in final


def semester():
    """教学周历：{周次: 周一}；失败则从本周往前逐周探问"""
    _, html = http(JXZL, referer=SERVICE)
    rows = re.findall(r"<td>(\d+)</td><td title='(\d{4})年(\d{2})月(\d{2})'", html)
    if len(rows) >= 10:
        m = re.search(r"(\d{4})-(\d{4})\s*学年\s*第\s*(\d)\s*学期", html.replace("&nbsp;", " "))
        return ({int(w): datetime.date(int(y), int(mo), int(d)) for w, y, mo, d in rows},
                f"{m[1]}-{m[2]}-{m[3]}" if m else "")

    _, home = http(MAIN, referer=SERVICE)
    m = re.search(r"第\s*\d+\s*周\s*/\s*(\d+)\s*周", home)
    total = int(m[1]) if m else 22
    today = datetime.date.today()
    day, cal = today - datetime.timedelta(days=today.weekday()), {}
    for _ in range(min(total, 30)):
        w = re.search(r"第(\d+)周", http(KB, {"rq": day.isoformat(), "sjmsValue": ""}, referer=MAIN)[1])
        if w:
            cal.setdefault(int(w[1]), day)
            if int(w[1]) == 1:
                break
        day -= datetime.timedelta(days=7)
    if 1 not in cal:
        return None, ""
    for w in range(1, total + 1):                 # 缺失周用最近的已知周补齐
        if w not in cal:
            base = max((k for k in cal if k < w), default=1)
            cal[w] = cal[base] + datetime.timedelta(days=7 * (w - base))
    return cal, ""


def parse_week(html):
    """一周课表 → [(课程, 星期, 节次, 地点, 周次)]"""
    out = []
    for row in re.findall(r"<tr>(.*?)</tr>", html, re.S):
        cells = re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)
        m = re.search(r"\((\d+),(\d+)小节\)", cells[0]) if len(cells) == 8 else None
        if not m:
            continue
        sec = f"{int(m[1]):02d}-{int(m[2]):02d}"
        for wd, cell in enumerate(cells[1:], 1):
            for t in re.findall(r"title\s*=\s*'([^']*)'", cell):
                d = dict(p.split("：", 1) for p in t.split("<br/>") if "：" in p)
                w = re.search(r"第(\d+)周", d.get("上课时间", ""))
                if d.get("课程名称"):
                    out.append((d["课程名称"], wd, sec, d.get("上课地点", ""), int(w[1]) if w else None))
    return out


def teachers(term):
    """选课结果里的任课教师，多人用顿号连接（避免破坏 CSV）"""
    _, html = http(XKGL, {"xnxqid": term}, referer=BASE + "/jsxsd/xkgl/xsxkjgcx")
    res = {}
    for row in re.findall(r"<tr>(.*?)</tr>", html, re.S):
        c = [re.sub(r"<[^>]+>", "", x).strip() for x in re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)]
        if len(c) >= 8 and c[0].isdigit():
            res[c[1]] = "、".join(t for t in c[3].split(",") if t.strip())
    return res


def write_csv(rows):
    out = OUT
    try:
        f = open(out, "w", encoding="gbk", newline="")
    except PermissionError:                       # 被 Excel 占用时改名
        out = f"{OUT.rsplit('.', 1)[0]}_{datetime.datetime.now():%H%M%S}.csv"
        print(f"！{OUT} 被占用，改写到 {out}")
        f = open(out, "w", encoding="gbk", newline="")
    with f:
        w = csv.writer(f, lineterminator="\r\n")
        w.writerow(HDR)
        w.writerows(rows)
    return out


def main():
    user, pwd = credentials()
    if not login(user, pwd):
        if RESET:
            sys.exit("登录失败，账号或密码不正确")
        print("保存的凭据已失效，请重新输入")
        user, pwd = ask(user, pwd)
        save_cfg(user, pwd)
        if not login(user, pwd):
            sys.exit("登录失败，账号或密码不正确")

    cal, term = semester()
    if not cal:
        sys.exit("无法识别教学周历")
    today = datetime.date.today()
    print(f"学期 {term or '未识别'} | 第1周 {cal[min(cal)]} | 共 {max(cal)} 周 | "
          f"当前第 {max((w for w in cal if cal[w] <= today), default=0)} 周")

    tmap = teachers(term) if term else {}

    def grab(item):                               # 并发抓各周；服务器偶尔超时，重试 3 次
        w, day = item
        for i in range(3):
            try:
                return w, parse_week(http(KB, {"rq": day.isoformat(), "sjmsValue": ""}, referer=MAIN)[1])
            except Exception:
                time.sleep(1 + i)
        return w, None

    with ThreadPoolExecutor(max_workers=4) as pool:
        weeks = list(pool.map(grab, sorted(cal.items())))

    for i, (w, got) in enumerate(weeks):          # 仍失败的，最后串行补抓一次
        if got is None:
            print(f"  第{w}周 重试中…")
            weeks[i] = (w, parse_week(http(KB, {"rq": cal[w].isoformat(), "sjmsValue": ""}, referer=MAIN)[1]))

    recs = set()
    for w, got in weeks:
        recs.update(r for r in got if r[4])
        print(f"  第{w:>2}周 {cal[w]}  {len(got):>2} 条")

    slots = {}
    for course, wd, sec, place, w in recs:
        slots.setdefault((course, wd, sec, place), set()).add(w)
    rows = []
    for (course, wd, sec, place), ws in slots.items():
        start = prev = min(ws)
        for w in sorted(ws)[1:] + [None]:         # 连续周次合并成一段，断开就另起一行
            if w is not None and w == prev + 1:
                prev = w
                continue
            rows.append([course, wd, int(sec[:2]), int(sec[3:]), tmap.get(course, ""), place,
                         f"{start}-{prev}" if start != prev else str(start)])
            if w is not None:
                start = prev = w
    rows.sort(key=lambda r: (r[1], r[2], r[0]))

    out = write_csv(rows)
    msg = f"已生成 {os.path.basename(out)}\n{len(rows)} 行 / {len({r[0] for r in rows})} 门课\n\n{out}"
    print("\n" + msg)
    notice(msg)


if __name__ == "__main__":
    if os.path.exists(CFG):
        hide(CFG)
    try:
        main()
    except SystemExit as e:
        if e.code not in (None, 0):
            print(e.code)
            notice(str(e.code), True)
            sys.exit(1)
    except Exception:
        import traceback
        tb = traceback.format_exc()
        try:
            with open(os.path.join(HERE, "导出错误.log"), "w", encoding="utf-8") as f:
                f.write(tb)
        except OSError:
            pass
        notice("运行出错，详情见 导出错误.log\n\n" + tb.strip().splitlines()[-1], True)
        sys.exit(1)
