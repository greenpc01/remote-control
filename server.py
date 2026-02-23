"""
원격 제어 서버 v2 (제어 당하는 PC에서 실행)
pip install pillow pyautogui pynput
"""

import socket, threading, struct, io, json, subprocess, sys, time
import tkinter as tk
from tkinter import scrolledtext

try:
    from PIL import ImageGrab
    import pyautogui
    import pyperclip
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pillow", "pyautogui", "pynput", "pyperclip"])
    from PIL import ImageGrab
    import pyautogui
    import pyperclip

pyautogui.FAILSAFE = False
pyautogui.PAUSE = 0

HOST     = "0.0.0.0"
CMD_PORT = 9999
SCR_PORT = 9998

# ── 소켓 유틸 ─────────────────────────────────────────────────
def send_msg(sock, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)

def recv_msg(sock) -> bytes:
    hdr = _exact(sock, 4)
    if not hdr: return b""
    return _exact(sock, struct.unpack(">I", hdr)[0])

def _exact(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c: return b""
        buf += c
    return buf

# ── 화면 스트리밍 스레드 ──────────────────────────────────────
def screen_thread(conn, log):
    log("화면 스트리밍 시작")
    # 실제 화면 해상도를 클라이언트에 먼저 전달
    tmp = tk.Tk(); tmp.withdraw()
    sw, sh = tmp.winfo_screenwidth(), tmp.winfo_screenheight()
    tmp.destroy()
    send_msg(conn, json.dumps({"type": "screen_size", "w": sw, "h": sh}).encode())

    try:
        while True:
            img = ImageGrab.grab()          # 원본 해상도 캡처
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=55, optimize=True)
            send_msg(conn, buf.getvalue())
            time.sleep(0.033)               # ~30 fps
    except Exception as e:
        log(f"화면 스트리밍 종료: {e}")

# ── 명령 처리 스레드 ─────────────────────────────────────────
def cmd_thread(conn, log):
    log("명령 수신 대기")
    SPECIAL = {
        "enter":"enter","backspace":"backspace","tab":"tab","esc":"esc",
        "delete":"delete","up":"up","down":"down","left":"left","right":"right",
        "space":"space","f1":"f1","f2":"f2","f3":"f3","f4":"f4","f5":"f5",
        "f11":"f11","f12":"f12","win":"winleft","print_screen":"printscreen",
    }
    try:
        while True:
            raw = recv_msg(conn)
            if not raw: break
            cmd = json.loads(raw)
            a = cmd.get("action", "")

            if a == "mouse_move":
                pyautogui.moveTo(cmd["x"], cmd["y"])

            elif a == "mouse_click":
                pyautogui.click(cmd["x"], cmd["y"], button=cmd.get("btn", "left"))

            elif a == "mouse_down":
                pyautogui.mouseDown(cmd["x"], cmd["y"], button=cmd.get("btn", "left"))

            elif a == "mouse_up":
                pyautogui.mouseUp(cmd["x"], cmd["y"], button=cmd.get("btn", "left"))

            elif a == "mouse_double":
                pyautogui.doubleClick(cmd["x"], cmd["y"])

            elif a == "mouse_scroll":
                pyautogui.scroll(cmd.get("delta", 3))

            elif a == "key_press":
                k = cmd.get("key", "")
                sk = SPECIAL.get(k.lower())
                if sk:
                    pyautogui.press(sk)
                elif len(k) == 1:
                    # 클립보드 경유 붙여넣기 → 영어/한글/특수문자 모두 정확하게 입력됨
                    prev = pyperclip.paste()        # 기존 클립보드 백업
                    pyperclip.copy(k)
                    pyautogui.hotkey("ctrl", "v")
                    time.sleep(0.04)
                    pyperclip.copy(prev)            # 클립보드 복원

            elif a == "key_combo":
                pyautogui.hotkey(*cmd.get("keys", []))

            elif a == "shell":
                log(f"CMD: {cmd.get('command','')}")
                try:
                    r = subprocess.run(
                        cmd["command"], shell=True, capture_output=True,
                        text=True, timeout=30, encoding="utf-8", errors="replace"
                    )
                    out = (r.stdout + r.stderr).strip() or "(출력 없음)"
                except subprocess.TimeoutExpired:
                    out = "[오류] 30초 시간 초과"
                except Exception as ex:
                    out = f"[오류] {ex}"
                send_msg(conn, json.dumps({"type": "shell_result", "output": out}).encode())

    except Exception as e:
        log(f"명령 처리 종료: {e}")

# ── 서버 GUI ─────────────────────────────────────────────────
class ServerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🖥️ 원격 제어 서버 v2")
        self.root.geometry("480x400")
        self.root.configure(bg="#1e1e2e")
        self.running = False
        self._build()

    def _build(self):
        tk.Label(self.root, text="🖥️  원격 제어 서버 v2", bg="#1e1e2e",
                 fg="#89b4fa", font=("Consolas", 16, "bold")).pack(pady=(16, 4))

        f = tk.Frame(self.root, bg="#313244", pady=10, padx=20)
        f.pack(fill="x", padx=20, pady=6)

        try:
            ip = socket.gethostbyname(socket.gethostname())
        except:
            ip = "127.0.0.1"

        tk.Label(f, text=f"내 IP 주소:  {ip}", bg="#313244",
                 fg="#a6e3a1", font=("Consolas", 12, "bold")).pack(anchor="w")
        tk.Label(f, text=f"포트:  CMD={CMD_PORT}  |  SCREEN={SCR_PORT}",
                 bg="#313244", fg="#cdd6f4", font=("Consolas", 10)).pack(anchor="w", pady=(4, 0))
        tk.Label(f, text="(클라이언트에 IP를 알려주세요)",
                 bg="#313244", fg="#6c7086", font=("Consolas", 9)).pack(anchor="w")

        self.sv = tk.StringVar(value="⏹ 중지됨")
        tk.Label(self.root, textvariable=self.sv, bg="#1e1e2e",
                 fg="#fab387", font=("Consolas", 11)).pack(pady=4)

        bf = tk.Frame(self.root, bg="#1e1e2e")
        bf.pack()
        self.b_start = tk.Button(bf, text="▶  서버 시작", bg="#a6e3a1", fg="#1e1e2e",
                                  font=("Consolas", 11, "bold"), relief="flat",
                                  padx=16, pady=6, cursor="hand2", command=self.start)
        self.b_start.pack(side="left", padx=8)
        self.b_stop = tk.Button(bf, text="■  서버 중지", bg="#f38ba8", fg="#1e1e2e",
                                 font=("Consolas", 11, "bold"), relief="flat",
                                 padx=16, pady=6, cursor="hand2", command=self.stop, state="disabled")
        self.b_stop.pack(side="left", padx=8)

        tk.Label(self.root, text="로그", bg="#1e1e2e", fg="#6c7086",
                 font=("Consolas", 9)).pack(anchor="w", padx=22, pady=(8, 0))
        self.log_box = scrolledtext.ScrolledText(
            self.root, height=9, bg="#181825", fg="#cdd6f4",
            font=("Consolas", 9), state="disabled", relief="flat"
        )
        self.log_box.pack(fill="both", padx=20, pady=(0, 12))

    def log(self, msg):
        ts = time.strftime("%H:%M:%S")
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"[{ts}] {msg}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def start(self):
        self.running = True
        self.b_start.configure(state="disabled")
        self.b_stop.configure(state="normal")
        self.sv.set("🟢 실행 중 - 연결 대기...")
        threading.Thread(target=self._listen, args=(CMD_PORT, False), daemon=True).start()
        threading.Thread(target=self._listen, args=(SCR_PORT, True),  daemon=True).start()
        self.log("서버 시작됨")

    def stop(self):
        self.running = False
        self.b_start.configure(state="normal")
        self.b_stop.configure(state="disabled")
        self.sv.set("⏹ 중지됨")
        self.log("서버 중지됨")

    def _listen(self, port, is_scr):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, port))
        srv.listen(5)
        self.log(f"{'화면' if is_scr else '명령'} 포트 {port} 대기 중...")
        while self.running:
            try:
                srv.settimeout(1.0)
                conn, addr = srv.accept()
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.log(f"연결됨: {addr[0]} ({'화면' if is_scr else '명령'})")
                self.sv.set(f"🟢 연결됨: {addr[0]}")
                fn = screen_thread if is_scr else cmd_thread
                threading.Thread(target=fn, args=(conn, self.log), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.log(f"오류: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    ServerApp(root)
    root.mainloop()
