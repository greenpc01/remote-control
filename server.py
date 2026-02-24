# remote_server_v2_1.py
# pip install pillow pyautogui pyperclip
import socket, threading, struct, io, json, subprocess, sys, time
import tkinter as tk
from tkinter import scrolledtext

try:
    from PIL import ImageGrab
    import pyautogui
    import pyperclip
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pillow", "pyautogui", "pyperclip"])
    from PIL import ImageGrab
    import pyautogui
    import pyperclip

pyautogui.FAILSAFE = False
pyautogui.PAUSE = 0

HOST = "0.0.0.0"
CMD_PORT = 9999
SCR_PORT = 9998

# ===== 보안/정책 =====
AUTH_TOKEN = "CHANGE_ME_STRONG_TOKEN_32+"  # 반드시 변경
ALLOW_IP_PREFIXES = ["127.", "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                     "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."]
ENABLE_SHELL = False  # 기본 OFF

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
                pyautogui.moveTo(int(cmd["x"]), int(cmd["y"]))
            elif a == "mouse_click":
                pyautogui.click(int(cmd["x"]), int(cmd["y"]), button=cmd.get("btn", "left"))
            elif a == "mouse_down":
                pyautogui.mouseDown(int(cmd["x"]), int(cmd["y"]), button=cmd.get("btn", "left"))
            elif a == "mouse_up":
                pyautogui.mouseUp(int(cmd["x"]), int(cmd["y"]), button=cmd.get("btn", "left"))
            elif a == "mouse_double":
                pyautogui.doubleClick(int(cmd["x"]), int(cmd["y"]))
            elif a == "mouse_scroll":
                pyautogui.scroll(int(cmd.get("delta", 3)))

            elif a == "key_press":
                k = cmd.get("key", "")
                sk = SPECIAL.get(k.lower())
                if sk:
                    pyautogui.press(sk)
                elif len(k) == 1:
                    prev = pyperclip.paste()
                    pyperclip.copy(k)
                    pyautogui.hotkey("ctrl", "v")
                    time.sleep(0.03)
                    pyperclip.copy(prev)

            elif a == "key_combo":
                keys = cmd.get("keys", [])
                if keys:
                    pyautogui.hotkey(*keys)

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
        tk.Label(f, text=f"포트: CMD={CMD_PORT} | SCREEN={SCR_PORT}", bg="#313244",
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
        self.running = True
        self.stop_evt.clear()
        self.b_start.configure(state="disabled")
        self.b_stop.configure(state="normal")
        self.sv.set("🟢 실행 중 - 연결 대기...")
        threading.Thread(target=self._listen, args=(CMD_PORT, False), daemon=True).start()
        threading.Thread(target=self._listen, args=(SCR_PORT, True), daemon=True).start()
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
