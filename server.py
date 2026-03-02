# remote_server_v2_4_stable.py
# 필요한 패키지(수동 설치 권장): pillow pyautogui pyperclip pydirectinput
import socket, threading, struct, io, json, subprocess, sys, time, ctypes, shutil
import tkinter as tk
from tkinter import scrolledtext, messagebox

# 필수 패키지 로드 (실패 시 자동설치하지 않고 명확히 안내 후 종료)
_missing = []
try:
    from PIL import ImageGrab
except Exception:
    _missing.append("pillow")

try:
    import pyautogui
except Exception:
    _missing.append("pyautogui")

try:
    import pyperclip
except Exception:
    _missing.append("pyperclip")

if _missing:
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror(
        "필수 모듈 누락",
        "다음 패키지를 먼저 설치해주세요:\n\n"
        + " ".join(_missing)
        + "\n\n실행 명령:\npython -m pip install "
        + " ".join(_missing),
    )
    raise SystemExit(1)

# 선택 패키지(pydirectinput): 없어도 서버는 실행
pydirectinput = None
try:
    import pydirectinput as _pdi
    pydirectinput = _pdi
except Exception:
    pydirectinput = None

pyautogui.FAILSAFE = False
pyautogui.PAUSE = 0
if pydirectinput is not None:
    pydirectinput.FAILSAFE = False
    pydirectinput.PAUSE = 0

HOST = "0.0.0.0"
CMD_PORT = 9999
SCR_PORT = 9998
VIDEO_PORT = 9997  # H.264(하드웨어 인코더) 스트림 포트

USE_H264_STREAM = True
VIDEO_FPS = 15
VIDEO_BITRATE = "5M"


def ensure_ffmpeg(app_log=None):
    if shutil.which("ffmpeg"):
        return True
    try:
        if app_log:
            app_log("ffmpeg 없음 -> winget 자동 설치 시도")
        subprocess.run(["winget", "install", "-e", "--id", "Gyan.FFmpeg", "--accept-package-agreements", "--accept-source-agreements"],
                       check=False, capture_output=True, text=True, timeout=180)
    except Exception:
        pass
    ok = shutil.which("ffmpeg") is not None
    if app_log:
        app_log("ffmpeg 설치 성공" if ok else "ffmpeg 설치 실패(기존 JPEG 모드로 동작)")
    return ok

# ===== 보안/정책 =====
AUTH_TOKEN = "CHANGE_ME_STRONG_TOKEN_32+"  # 반드시 변경
ALLOW_IP_PREFIXES = ["127.", "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                     "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."]
ENABLE_SHELL = False  # 기본 OFF

# 게임 호환 입력 모드 (리니지/DirectX 게임 대응)
USE_DIRECT_INPUT = pydirectinput is not None
# 윈도우 SendInput 사용(게임 호환성 향상)
USE_WIN_SENDINPUT = True

# ---- Win32 SendInput (마우스) ----
INPUT_MOUSE = 0
MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_RIGHTDOWN = 0x0008
MOUSEEVENTF_RIGHTUP = 0x0010
MOUSEEVENTF_WHEEL = 0x0800
MOUSEEVENTF_ABSOLUTE = 0x8000

class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", ctypes.c_long),
        ("dy", ctypes.c_long),
        ("mouseData", ctypes.c_ulong),
        ("dwFlags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
    ]

class INPUT(ctypes.Structure):
    _fields_ = [("type", ctypes.c_ulong), ("mi", MOUSEINPUT)]


def _screen_size():
    u32 = ctypes.windll.user32
    return u32.GetSystemMetrics(0), u32.GetSystemMetrics(1)


def _to_absolute(x, y):
    sw, sh = _screen_size()
    ax = int(x * 65535 / max(1, sw - 1))
    ay = int(y * 65535 / max(1, sh - 1))
    return ax, ay


def _send_mouse(flags, x=None, y=None, data=0):
    if x is not None and y is not None:
        x = int(x); y = int(y)
        ctypes.windll.user32.SetCursorPos(x, y)
        ax, ay = _to_absolute(x, y)
        flags |= MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE
    else:
        ax, ay = 0, 0

    inp = INPUT(
        type=INPUT_MOUSE,
        mi=MOUSEINPUT(
            dx=ax,
            dy=ay,
            mouseData=data,
            dwFlags=flags,
            time=0,
            dwExtraInfo=None,
        ),
    )
    ctypes.windll.user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))

def _with_fallback(direct_fn, auto_fn):
    if USE_DIRECT_INPUT and pydirectinput is not None:
        try:
            return direct_fn()
        except Exception:
            return auto_fn()
    return auto_fn()

def mouse_move(x, y):
    if USE_WIN_SENDINPUT:
        return _send_mouse(0, x, y)
    return _with_fallback(
        lambda: pydirectinput.moveTo(x, y),
        lambda: pyautogui.moveTo(x, y),
    )

def mouse_down(x, y, btn="left"):
    if USE_WIN_SENDINPUT:
        if btn == "right":
            return _send_mouse(MOUSEEVENTF_RIGHTDOWN, x, y)
        return _send_mouse(MOUSEEVENTF_LEFTDOWN, x, y)
    return _with_fallback(
        lambda: (pydirectinput.moveTo(x, y), pydirectinput.mouseDown(button=btn)),
        lambda: pyautogui.mouseDown(x, y, button=btn),
    )

def mouse_up(x, y, btn="left"):
    if USE_WIN_SENDINPUT:
        if btn == "right":
            return _send_mouse(MOUSEEVENTF_RIGHTUP, x, y)
        return _send_mouse(MOUSEEVENTF_LEFTUP, x, y)
    return _with_fallback(
        lambda: (pydirectinput.moveTo(x, y), pydirectinput.mouseUp(button=btn)),
        lambda: pyautogui.mouseUp(x, y, button=btn),
    )

def mouse_click(x, y, btn="left"):
    if USE_WIN_SENDINPUT:
        mouse_down(x, y, btn)
        time.sleep(0.01)
        return mouse_up(x, y, btn)
    return _with_fallback(
        lambda: pydirectinput.click(x=x, y=y, button=btn),
        lambda: pyautogui.click(x, y, button=btn),
    )

def mouse_double(x, y):
    if USE_WIN_SENDINPUT:
        mouse_click(x, y, "left")
        time.sleep(0.02)
        return mouse_click(x, y, "left")
    return _with_fallback(
        lambda: pydirectinput.doubleClick(x=x, y=y),
        lambda: pyautogui.doubleClick(x, y),
    )

def mouse_scroll(delta):
    if USE_WIN_SENDINPUT:
        return _send_mouse(MOUSEEVENTF_WHEEL, data=int(delta) * 120)
    return _with_fallback(
        lambda: pydirectinput.scroll(delta),
        lambda: pyautogui.scroll(delta),
    )

def key_tap(k):
    return _with_fallback(
        lambda: pydirectinput.press(k),
        lambda: pyautogui.press(k),
    )

def key_combo(*keys):
    return _with_fallback(
        lambda: pydirectinput.hotkey(*keys),
        lambda: pyautogui.hotkey(*keys),
    )

# ===== 소켓 유틸 =====
def send_msg(sock, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)

def recv_msg(sock) -> bytes:
    hdr = _exact(sock, 4)
    if not hdr:
        return b""
    n = struct.unpack(">I", hdr)[0]
    if n <= 0 or n > 50_000_000:
        return b""
    return _exact(sock, n)

def _exact(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            return b""
        buf += c
    return buf

def allowed_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in ALLOW_IP_PREFIXES)

def auth_handshake(conn, expect_type: str, log):
    try:
        conn.settimeout(5.0)
        raw = recv_msg(conn)
        if not raw:
            return False
        msg = json.loads(raw.decode("utf-8", errors="replace"))
        ok = (
            msg.get("type") == "auth" and
            msg.get("token") == AUTH_TOKEN and
            msg.get("channel") == expect_type
        )
        if ok:
            send_msg(conn, json.dumps({"type": "auth_ok"}).encode())
            return True
        else:
            send_msg(conn, json.dumps({"type": "auth_fail"}).encode())
            return False
    except Exception as e:
        log(f"인증 오류({expect_type}): {e}")
        return False
    finally:
        try:
            conn.settimeout(None)
        except:
            pass

def get_lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except:
        return "127.0.0.1"
    finally:
        s.close()


def _h264_ffmpeg_cmd(encoder: str):
    # gdigrab + hw encoder (NVENC/QSV/AMF), fallback libx264
    base = [
        "ffmpeg", "-hide_banner", "-loglevel", "error",
        "-f", "gdigrab", "-framerate", str(VIDEO_FPS), "-i", "desktop",
        "-an", "-pix_fmt", "yuv420p",
    ]
    if encoder == "h264_nvenc":
        enc = ["-c:v", "h264_nvenc", "-preset", "p4", "-tune", "ll", "-b:v", VIDEO_BITRATE, "-g", "30"]
    elif encoder == "h264_qsv":
        enc = ["-c:v", "h264_qsv", "-preset", "veryfast", "-b:v", VIDEO_BITRATE, "-g", "30"]
    elif encoder == "h264_amf":
        enc = ["-c:v", "h264_amf", "-quality", "speed", "-b:v", VIDEO_BITRATE, "-g", "30"]
    else:
        enc = ["-c:v", "libx264", "-preset", "veryfast", "-tune", "zerolatency", "-b:v", VIDEO_BITRATE, "-g", "30"]

    return base + enc + ["-f", "mpegts", "pipe:1"]


def video_thread(conn, app_log, stop_evt):
    app_log("H.264 스트리밍 시작")
    candidates = ["h264_nvenc", "h264_qsv", "h264_amf", "libx264"]
    proc = None
    chosen = None

    for enc in candidates:
        try:
            cmd = _h264_ffmpeg_cmd(enc)
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(0.8)
            if p.poll() is None:
                proc = p
                chosen = enc
                break
            p.kill()
        except Exception:
            continue

    if proc is None:
        app_log("ffmpeg 인코더 시작 실패(설치/드라이버 확인)")
        return

    app_log(f"H.264 인코더: {chosen}")
    try:
        while not stop_evt.is_set():
            chunk = proc.stdout.read(32 * 1024)
            if not chunk:
                break
            conn.sendall(chunk)
    except Exception as e:
        app_log(f"H.264 스트리밍 종료: {e}")
    finally:
        try:
            proc.kill()
        except:
            pass

# ===== 화면 스트리밍 =====
def screen_thread(conn, app_log, stop_evt):
    app_log("화면 스트리밍 시작")
    tmp = tk.Tk(); tmp.withdraw()
    sw, sh = tmp.winfo_screenwidth(), tmp.winfo_screenheight()
    tmp.destroy()

    send_msg(conn, json.dumps({"type": "screen_size", "w": sw, "h": sh}).encode())

    try:
        while not stop_evt.is_set():
            img = ImageGrab.grab()
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=55, optimize=True)
            send_msg(conn, buf.getvalue())
            time.sleep(0.033)
    except Exception as e:
        app_log(f"화면 스트리밍 종료: {e}")

# ===== 명령 처리 =====
def cmd_thread(conn, app_log, stop_evt):
    app_log("명령 수신 대기")
    SPECIAL = {
        "enter":"enter","backspace":"backspace","tab":"tab","esc":"esc",
        "delete":"delete","up":"up","down":"down","left":"left","right":"right",
        "space":"space","f1":"f1","f2":"f2","f3":"f3","f4":"f4","f5":"f5",
        "f11":"f11","f12":"f12","win":"winleft","print_screen":"printscreen",
    }

    try:
        while not stop_evt.is_set():
            raw = recv_msg(conn)
            if not raw:
                break

            cmd = json.loads(raw.decode("utf-8", errors="replace"))
            a = cmd.get("action", "")

            if a == "mouse_move":
                mouse_move(int(cmd["x"]), int(cmd["y"]))
            elif a == "mouse_click":
                mouse_click(int(cmd["x"]), int(cmd["y"]), cmd.get("btn", "left"))
            elif a == "mouse_down":
                mouse_down(int(cmd["x"]), int(cmd["y"]), cmd.get("btn", "left"))
            elif a == "mouse_up":
                mouse_up(int(cmd["x"]), int(cmd["y"]), cmd.get("btn", "left"))
            elif a == "mouse_double":
                mouse_double(int(cmd["x"]), int(cmd["y"]))
            elif a == "mouse_scroll":
                mouse_scroll(int(cmd.get("delta", 3)))

            elif a == "key_press":
                k = cmd.get("key", "")
                sk = SPECIAL.get(k.lower())
                if sk:
                    key_tap(sk)
                elif len(k) == 1:
                    # 게임 창에서는 Ctrl+V보다 직접 키 입력이 안정적
                    ch = k.lower()
                    if ch.isalnum() or ch in "`-=[]\\;',./":
                        key_tap(ch)
                    else:
                        prev = pyperclip.paste()
                        pyperclip.copy(k)
                        key_combo("ctrl", "v")
                        time.sleep(0.03)
                        pyperclip.copy(prev)

            elif a == "key_combo":
                keys = cmd.get("keys", [])
                if keys:
                    key_combo(*keys)

            elif a == "shell":
                if not ENABLE_SHELL:
                    send_msg(conn, json.dumps({"type":"shell_result","output":"[보안정책] shell 비활성화"}).encode())
                    continue

                c = cmd.get("command", "")
                app_log(f"CMD: {c}")
                try:
                    r = subprocess.run(
                        c, shell=True, capture_output=True, text=True, timeout=30,
                        encoding="utf-8", errors="replace"
                    )
                    out = (r.stdout + r.stderr).strip() or "(출력 없음)"
                except subprocess.TimeoutExpired:
                    out = "[오류] 30초 시간 초과"
                except Exception as ex:
                    out = f"[오류] {ex}"
                send_msg(conn, json.dumps({"type":"shell_result","output":out}).encode())

    except Exception as e:
        app_log(f"명령 처리 종료: {e}")

# ===== GUI =====
class ServerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🖥️ 원격 제어 서버 v2.1")
        self.root.geometry("520x430")
        self.root.configure(bg="#1e1e2e")

        self.running = False
        self.stop_evt = threading.Event()
        self.servers = []
        self.client_socks = set()
        self.client_lock = threading.Lock()

        self._build()

    def _build(self):
        tk.Label(self.root, text="🖥️ 원격 제어 서버 v2.1", bg="#1e1e2e", fg="#89b4fa",
                 font=("Consolas", 16, "bold")).pack(pady=(16, 4))

        f = tk.Frame(self.root, bg="#313244", pady=10, padx=20)
        f.pack(fill="x", padx=20, pady=6)

        ip = get_lan_ip()
        tk.Label(f, text=f"내 IP 주소: {ip}", bg="#313244", fg="#a6e3a1",
                 font=("Consolas", 12, "bold")).pack(anchor="w")
        tk.Label(f, text=f"포트: CMD={CMD_PORT} | SCREEN={SCR_PORT} | H264={VIDEO_PORT}", bg="#313244",
                 fg="#cdd6f4", font=("Consolas", 10)).pack(anchor="w", pady=(4, 0))
        tk.Label(f, text=f"Shell: {'ON' if ENABLE_SHELL else 'OFF'} / 인증토큰 필요",
                 bg="#313244", fg="#f9e2af", font=("Consolas", 9)).pack(anchor="w", pady=(4, 0))

        self.sv = tk.StringVar(value="⏹ 중지됨")
        tk.Label(self.root, textvariable=self.sv, bg="#1e1e2e", fg="#fab387",
                 font=("Consolas", 11)).pack(pady=4)

        bf = tk.Frame(self.root, bg="#1e1e2e")
        bf.pack()

        self.b_start = tk.Button(bf, text="▶ 서버 시작", bg="#a6e3a1", fg="#1e1e2e",
                                 font=("Consolas", 11, "bold"), relief="flat",
                                 padx=16, pady=6, cursor="hand2", command=self.start)
        self.b_start.pack(side="left", padx=8)

        self.b_stop = tk.Button(bf, text="■ 서버 중지", bg="#f38ba8", fg="#1e1e2e",
                                font=("Consolas", 11, "bold"), relief="flat",
                                padx=16, pady=6, cursor="hand2", command=self.stop, state="disabled")
        self.b_stop.pack(side="left", padx=8)

        tk.Label(self.root, text="로그", bg="#1e1e2e", fg="#6c7086", font=("Consolas", 9)).pack(anchor="w", padx=22, pady=(8, 0))
        self.log_box = scrolledtext.ScrolledText(self.root, height=10, bg="#181825", fg="#cdd6f4",
                                                 font=("Consolas", 9), state="disabled", relief="flat")
        self.log_box.pack(fill="both", padx=20, pady=(0, 12), expand=True)

    def log(self, msg):
        ts = time.strftime("%H:%M:%S")
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"[{ts}] {msg}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def start(self):
        if self.running:
            return
        global USE_H264_STREAM
        if USE_H264_STREAM and not ensure_ffmpeg(self.log):
            USE_H264_STREAM = False

        self.running = True
        self.stop_evt.clear()
        self.b_start.configure(state="disabled")
        self.b_stop.configure(state="normal")
        self.sv.set("🟢 실행 중 - 연결 대기...")
        threading.Thread(target=self._listen, args=(CMD_PORT, False), daemon=True).start()
        threading.Thread(target=self._listen, args=(SCR_PORT, True), daemon=True).start()
        if USE_H264_STREAM:
            threading.Thread(target=self._listen_video, daemon=True).start()
        self.log("서버 시작됨")

    def stop(self):
        if not self.running:
            return
        self.running = False
        self.stop_evt.set()

        for s in self.servers[:]:
            try: s.close()
            except: pass
        self.servers.clear()

        with self.client_lock:
            for c in list(self.client_socks):
                try:
                    c.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                try:
                    c.close()
                except:
                    pass
            self.client_socks.clear()

        self.b_start.configure(state="normal")
        self.b_stop.configure(state="disabled")
        self.sv.set("⏹ 중지됨")
        self.log("서버 중지됨")

    def _listen(self, port, is_scr):
        name = "화면" if is_scr else "명령"
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, port))
        srv.listen(5)
        srv.settimeout(1.0)
        self.servers.append(srv)
        self.log(f"{name} 포트 {port} 대기 중...")

        while self.running and not self.stop_evt.is_set():
            try:
                conn, addr = srv.accept()
                ip = addr[0]

                if not allowed_ip(ip):
                    self.log(f"차단됨(IP): {ip} ({name})")
                    conn.close()
                    continue

                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                with self.client_lock:
                    self.client_socks.add(conn)

                ch = "scr" if is_scr else "cmd"
                if not auth_handshake(conn, ch, self.log):
                    self.log(f"인증 실패: {ip} ({name})")
                    with self.client_lock:
                        self.client_socks.discard(conn)
                    conn.close()
                    continue

                self.log(f"연결됨: {ip} ({name})")
                self.sv.set(f"🟢 연결됨: {ip}")

                fn = screen_thread if is_scr else cmd_thread
                threading.Thread(target=self._client_worker, args=(fn, conn), daemon=True).start()

            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                if self.running:
                    self.log(f"오류({name}): {e}")

        try: srv.close()
        except: pass

    def _listen_video(self):
        name = "H264"
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, VIDEO_PORT))
        srv.listen(2)
        srv.settimeout(1.0)
        self.servers.append(srv)
        self.log(f"{name} 포트 {VIDEO_PORT} 대기 중...")

        while self.running and not self.stop_evt.is_set():
            try:
                conn, addr = srv.accept()
                ip = addr[0]
                if not allowed_ip(ip):
                    self.log(f"차단됨(IP): {ip} ({name})")
                    conn.close()
                    continue

                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                with self.client_lock:
                    self.client_socks.add(conn)

                self.log(f"연결됨: {ip} ({name})")
                threading.Thread(target=self._client_worker, args=(video_thread, conn), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                if self.running:
                    self.log(f"오류({name}): {e}")

        try:
            srv.close()
        except:
            pass

    def _client_worker(self, fn, conn):
        try:
            fn(conn, self.log, self.stop_evt)
        finally:
            with self.client_lock:
                self.client_socks.discard(conn)
            try: conn.close()
            except: pass

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerApp(root)
    root.protocol("WM_DELETE_WINDOW", lambda: (app.stop(), root.destroy()))
    root.mainloop()
