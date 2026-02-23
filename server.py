"""
원격 제어 서버 (제어 당하는 PC에서 실행)
필요 라이브러리: pip install pillow pyautogui pynput
"""

import socket
import threading
import struct
import io
import json
import subprocess
import sys
import tkinter as tk
from tkinter import ttk, scrolledtext
import time

try:
    from PIL import ImageGrab
    import pyautogui
    from pynput.mouse import Controller as MouseController, Button
    from pynput.keyboard import Controller as KeyboardController, Key
except ImportError:
    print("필요한 라이브러리를 설치합니다...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pillow", "pyautogui", "pynput"])
    from PIL import ImageGrab
    import pyautogui
    from pynput.mouse import Controller as MouseController, Button
    from pynput.keyboard import Controller as KeyboardController, Key

pyautogui.FAILSAFE = False

HOST = "0.0.0.0"
PORT = 9999
SCREEN_PORT = 9998

mouse = MouseController()
keyboard = KeyboardController()

# ── 특수키 매핑 ──────────────────────────────────────────────
SPECIAL_KEYS = {
    "enter": Key.enter, "space": Key.space, "backspace": Key.backspace,
    "tab": Key.tab, "escape": Key.esc, "delete": Key.delete,
    "up": Key.up, "down": Key.down, "left": Key.left, "right": Key.right,
    "ctrl": Key.ctrl, "alt": Key.alt, "shift": Key.shift,
    "win": Key.cmd, "f1": Key.f1, "f2": Key.f2, "f3": Key.f3,
    "f4": Key.f4, "f5": Key.f5, "f11": Key.f11, "f12": Key.f12,
}

def send_data(conn, data: bytes):
    """4바이트 길이 헤더 + 데이터 전송"""
    conn.sendall(struct.pack(">I", len(data)) + data)

def recv_data(conn) -> bytes:
    """4바이트 길이 헤더를 읽고 그만큼 수신"""
    raw = _recv_exact(conn, 4)
    if not raw:
        return b""
    length = struct.unpack(">I", raw)[0]
    return _recv_exact(conn, length)

def _recv_exact(conn, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf

# ── 화면 스트리밍 스레드 ─────────────────────────────────────
def screen_stream_handler(conn, log_func):
    try:
        log_func("화면 스트리밍 시작")
        while True:
            img = ImageGrab.grab()
            img = img.resize((img.width // 2, img.height // 2))  # 해상도 절반으로
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=40)
            data = buf.getvalue()
            send_data(conn, data)
            time.sleep(0.05)  # ~20fps
    except Exception as e:
        log_func(f"화면 스트리밍 종료: {e}")

# ── 명령 처리 스레드 ─────────────────────────────────────────
def command_handler(conn, log_func):
    try:
        while True:
            raw = recv_data(conn)
            if not raw:
                break
            cmd = json.loads(raw.decode("utf-8"))
            action = cmd.get("action")

            if action == "mouse_move":
                x, y = cmd["x"], cmd["y"]
                # 클라이언트 좌표(절반 해상도) → 실제 화면 좌표
                pyautogui.moveTo(x * 2, y * 2)

            elif action == "mouse_click":
                x, y = cmd["x"] * 2, cmd["y"] * 2
                btn = cmd.get("button", "left")
                pyautogui.click(x, y, button=btn)

            elif action == "mouse_double_click":
                x, y = cmd["x"] * 2, cmd["y"] * 2
                pyautogui.doubleClick(x, y)

            elif action == "mouse_scroll":
                pyautogui.scroll(cmd.get("delta", 1))

            elif action == "key_press":
                key = cmd.get("key", "")
                if key.lower() in SPECIAL_KEYS:
                    pyautogui.press(key.lower())
                elif len(key) == 1:
                    pyautogui.typewrite(key, interval=0.01)

            elif action == "key_combo":
                keys = cmd.get("keys", [])
                pyautogui.hotkey(*keys)

            elif action == "shell":
                command = cmd.get("command", "")
                log_func(f"명령 실행: {command}")
                try:
                    result = subprocess.run(
                        command, shell=True, capture_output=True,
                        text=True, timeout=30, encoding="utf-8", errors="replace"
                    )
                    output = result.stdout + result.stderr
                except subprocess.TimeoutExpired:
                    output = "[오류] 명령 실행 시간 초과 (30초)"
                except Exception as ex:
                    output = f"[오류] {ex}"
                send_data(conn, json.dumps({"type": "shell_result", "output": output}).encode("utf-8"))

            elif action == "ping":
                send_data(conn, json.dumps({"type": "pong"}).encode("utf-8"))

    except Exception as e:
        log_func(f"명령 처리 종료: {e}")

# ── 서버 GUI ─────────────────────────────────────────────────
class ServerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🖥️  원격 제어 서버")
        self.root.geometry("500x420")
        self.root.resizable(False, False)
        self.root.configure(bg="#1e1e2e")

        self.cmd_server = None
        self.scr_server = None
        self.running = False

        self._build_ui()

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TLabel", background="#1e1e2e", foreground="#cdd6f4", font=("Consolas", 10))
        style.configure("TButton", font=("Consolas", 10, "bold"))
        style.configure("Green.TButton", background="#a6e3a1", foreground="#1e1e2e")
        style.configure("Red.TButton", background="#f38ba8", foreground="#1e1e2e")

        header = tk.Label(self.root, text="🖥️  원격 제어 서버", bg="#1e1e2e",
                          fg="#89b4fa", font=("Consolas", 16, "bold"))
        header.pack(pady=(18, 4))

        # IP/Port 표시
        frame_info = tk.Frame(self.root, bg="#313244", pady=10, padx=20)
        frame_info.pack(fill="x", padx=20, pady=6)

        import socket as _s
        local_ip = _s.gethostbyname(_s.gethostname())
        tk.Label(frame_info, text=f"내 IP 주소:  {local_ip}", bg="#313244",
                 fg="#a6e3a1", font=("Consolas", 11, "bold")).pack(anchor="w")
        tk.Label(frame_info, text=f"명령 포트:  {PORT}    화면 포트:  {SCREEN_PORT}",
                 bg="#313244", fg="#cdd6f4", font=("Consolas", 10)).pack(anchor="w", pady=(4,0))
        tk.Label(frame_info, text="(클라이언트에 위 정보를 알려주세요)",
                 bg="#313244", fg="#6c7086", font=("Consolas", 9)).pack(anchor="w")

        # 상태
        self.status_var = tk.StringVar(value="⏹ 서버 중지됨")
        tk.Label(self.root, textvariable=self.status_var, bg="#1e1e2e",
                 fg="#fab387", font=("Consolas", 11)).pack(pady=4)

        # 버튼
        btn_frame = tk.Frame(self.root, bg="#1e1e2e")
        btn_frame.pack()
        self.btn_start = ttk.Button(btn_frame, text="▶  서버 시작", style="Green.TButton",
                                    command=self.start_server)
        self.btn_start.pack(side="left", padx=8, pady=4)
        self.btn_stop = ttk.Button(btn_frame, text="■  서버 중지", style="Red.TButton",
                                   command=self.stop_server, state="disabled")
        self.btn_stop.pack(side="left", padx=8, pady=4)

        # 로그
        tk.Label(self.root, text="로그", bg="#1e1e2e", fg="#cdd6f4",
                 font=("Consolas", 9)).pack(anchor="w", padx=22)
        self.log = scrolledtext.ScrolledText(self.root, height=10, bg="#181825",
                                             fg="#cdd6f4", font=("Consolas", 9),
                                             state="disabled", relief="flat")
        self.log.pack(fill="both", padx=20, pady=(0,14))

    def log_msg(self, msg):
        ts = time.strftime("%H:%M:%S")
        self.log.configure(state="normal")
        self.log.insert("end", f"[{ts}] {msg}\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def start_server(self):
        self.running = True
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.status_var.set("🟢 서버 실행 중 - 연결 대기...")
        threading.Thread(target=self._accept_loop, args=(PORT, False), daemon=True).start()
        threading.Thread(target=self._accept_loop, args=(SCREEN_PORT, True), daemon=True).start()
        self.log_msg("서버 시작됨")

    def stop_server(self):
        self.running = False
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.status_var.set("⏹ 서버 중지됨")
        try:
            if self.cmd_server: self.cmd_server.close()
            if self.scr_server: self.scr_server.close()
        except:
            pass
        self.log_msg("서버 중지됨")

    def _accept_loop(self, port, is_screen):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, port))
        srv.listen(1)
        if is_screen:
            self.scr_server = srv
        else:
            self.cmd_server = srv
        self.log_msg(f"{'화면' if is_screen else '명령'} 포트 {port} 대기 중...")
        while self.running:
            try:
                srv.settimeout(1.0)
                conn, addr = srv.accept()
                self.log_msg(f"연결됨: {addr[0]} ({'화면' if is_screen else '명령'})")
                self.status_var.set(f"🟢 연결됨: {addr[0]}")
                if is_screen:
                    threading.Thread(target=screen_stream_handler,
                                     args=(conn, self.log_msg), daemon=True).start()
                else:
                    threading.Thread(target=command_handler,
                                     args=(conn, self.log_msg), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.log_msg(f"오류: {e}")
                break

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerApp(root)
    root.mainloop()
