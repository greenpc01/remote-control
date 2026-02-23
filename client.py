"""
원격 제어 클라이언트 (제어하는 PC에서 실행)
필요 라이브러리: pip install pillow
"""

import socket
import threading
import struct
import io
import json
import subprocess
import sys
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import time

try:
    from PIL import Image, ImageTk
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pillow"])
    from PIL import Image, ImageTk

PORT = 9999
SCREEN_PORT = 9998

def send_data(conn, data: bytes):
    conn.sendall(struct.pack(">I", len(data)) + data)

def recv_data(conn) -> bytes:
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

# ── 클라이언트 GUI ────────────────────────────────────────────
class ClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🎮  원격 제어 클라이언트")
        self.root.geometry("1000x700")
        self.root.configure(bg="#1e1e2e")

        self.cmd_sock = None
        self.scr_sock = None
        self.connected = False
        self.screen_label = None
        self._pending_result = threading.Event()
        self._shell_result = ""

        self._build_ui()
        self.root.bind("<KeyPress>", self._on_key)

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TLabel", background="#1e1e2e", foreground="#cdd6f4")
        style.configure("TEntry", fieldbackground="#313244", foreground="#cdd6f4")
        style.configure("Connect.TButton", background="#89b4fa", foreground="#1e1e2e",
                         font=("Consolas", 10, "bold"))
        style.configure("Disconnect.TButton", background="#f38ba8", foreground="#1e1e2e",
                         font=("Consolas", 10, "bold"))
        style.configure("Send.TButton", background="#a6e3a1", foreground="#1e1e2e",
                         font=("Consolas", 10, "bold"))

        # ── 상단 연결 바 ──────────────────────────────────────
        top = tk.Frame(self.root, bg="#181825", pady=8)
        top.pack(fill="x")

        tk.Label(top, text="서버 IP:", bg="#181825", fg="#cdd6f4",
                 font=("Consolas", 10)).pack(side="left", padx=(14, 4))
        self.ip_var = tk.StringVar(value="192.168.0.1")
        self.ip_entry = ttk.Entry(top, textvariable=self.ip_var, width=16)
        self.ip_entry.pack(side="left", padx=4)

        self.btn_connect = ttk.Button(top, text="연결", style="Connect.TButton",
                                      command=self.connect)
        self.btn_connect.pack(side="left", padx=6)
        self.btn_disconnect = ttk.Button(top, text="연결 해제", style="Disconnect.TButton",
                                         command=self.disconnect, state="disabled")
        self.btn_disconnect.pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="⏹ 연결 안됨")
        tk.Label(top, textvariable=self.status_var, bg="#181825",
                 fg="#fab387", font=("Consolas", 10)).pack(side="left", padx=16)

        # ── 메인 영역 (화면뷰어 + 우측패널) ──────────────────
        main = tk.Frame(self.root, bg="#1e1e2e")
        main.pack(fill="both", expand=True, padx=10, pady=8)

        # 화면 뷰어
        screen_frame = tk.Frame(main, bg="#000000", bd=2, relief="solid")
        screen_frame.pack(side="left", fill="both", expand=True)

        self.screen_label = tk.Label(screen_frame, bg="#000000",
                                     text="화면 연결 대기 중...",
                                     fg="#6c7086", font=("Consolas", 13))
        self.screen_label.pack(fill="both", expand=True)
        self.screen_label.bind("<Motion>", self._on_mouse_move)
        self.screen_label.bind("<Button-1>", lambda e: self._on_click(e, "left"))
        self.screen_label.bind("<Button-3>", lambda e: self._on_click(e, "right"))
        self.screen_label.bind("<Double-Button-1>", self._on_double_click)
        self.screen_label.bind("<MouseWheel>", self._on_scroll)

        # 우측 패널
        right = tk.Frame(main, bg="#1e1e2e", width=310)
        right.pack(side="right", fill="y", padx=(10, 0))
        right.pack_propagate(False)

        # ── 단축키 버튼 모음 ──────────────────────────────────
        tk.Label(right, text="⌨  단축키", bg="#1e1e2e", fg="#89b4fa",
                 font=("Consolas", 11, "bold")).pack(anchor="w", pady=(0, 4))

        shortcuts = [
            ("Ctrl+C", ["ctrl", "c"]),  ("Ctrl+V", ["ctrl", "v"]),
            ("Ctrl+X", ["ctrl", "x"]),  ("Ctrl+Z", ["ctrl", "z"]),
            ("Ctrl+A", ["ctrl", "a"]),  ("Ctrl+S", ["ctrl", "s"]),
            ("Alt+F4", ["alt", "f4"]),  ("Win+D", ["win", "d"]),
            ("Win+E", ["win", "e"]),    ("Ctrl+Alt+Del", ["ctrl", "alt", "delete"]),
            ("PrtScr", ["print_screen"]),("F5 새로고침", ["f5"]),
        ]
        sc_frame = tk.Frame(right, bg="#1e1e2e")
        sc_frame.pack(fill="x")
        for i, (label, keys) in enumerate(shortcuts):
            btn = tk.Button(sc_frame, text=label, bg="#313244", fg="#cdd6f4",
                            font=("Consolas", 9), relief="flat", bd=0,
                            activebackground="#45475a", cursor="hand2",
                            command=lambda k=keys: self._send_combo(k))
            btn.grid(row=i // 3, column=i % 3, padx=2, pady=2, sticky="ew")
        for c in range(3):
            sc_frame.columnconfigure(c, weight=1)

        ttk.Separator(right, orient="horizontal").pack(fill="x", pady=10)

        # ── 텍스트 입력 전송 ──────────────────────────────────
        tk.Label(right, text="📝  텍스트 입력 전송", bg="#1e1e2e", fg="#89b4fa",
                 font=("Consolas", 11, "bold")).pack(anchor="w")
        self.text_var = tk.StringVar()
        text_entry = ttk.Entry(right, textvariable=self.text_var)
        text_entry.pack(fill="x", pady=4)
        text_entry.bind("<Return>", lambda e: self._send_text())
        ttk.Button(right, text="전송 (Enter)", style="Send.TButton",
                   command=self._send_text).pack(fill="x")

        ttk.Separator(right, orient="horizontal").pack(fill="x", pady=10)

        # ── 원격 명령 실행 ─────────────────────────────────────
        tk.Label(right, text="💻  원격 명령 실행 (CMD)", bg="#1e1e2e", fg="#89b4fa",
                 font=("Consolas", 11, "bold")).pack(anchor="w")
        self.cmd_var = tk.StringVar()
        cmd_entry = ttk.Entry(right, textvariable=self.cmd_var)
        cmd_entry.pack(fill="x", pady=4)
        cmd_entry.bind("<Return>", lambda e: self._send_command())

        # 빠른 명령 버튼
        quick_frame = tk.Frame(right, bg="#1e1e2e")
        quick_frame.pack(fill="x", pady=(0, 4))
        quick_cmds = [
            ("시스템 정보", "systeminfo | findstr /C:\"OS Name\" /C:\"Total Physical\""),
            ("IP 정보", "ipconfig"),
            ("프로세스 목록", "tasklist | head -20"),
            ("디스크 정보", "wmic logicaldisk get caption,freespace,size"),
        ]
        for label, cmd in quick_cmds:
            tk.Button(quick_frame, text=label, bg="#45475a", fg="#cdd6f4",
                      font=("Consolas", 8), relief="flat",
                      activebackground="#585b70", cursor="hand2",
                      command=lambda c=cmd: self._run_quick_cmd(c)
                      ).pack(side="left", padx=1)

        ttk.Button(right, text="▶  실행", style="Send.TButton",
                   command=self._send_command).pack(fill="x")

        # 결과창
        tk.Label(right, text="결과:", bg="#1e1e2e", fg="#6c7086",
                 font=("Consolas", 9)).pack(anchor="w", pady=(6,0))
        self.result_box = scrolledtext.ScrolledText(right, height=8, bg="#181825",
                                                    fg="#a6e3a1", font=("Consolas", 9),
                                                    state="disabled", relief="flat")
        self.result_box.pack(fill="both", expand=True)

    # ── 연결 / 해제 ───────────────────────────────────────────
    def connect(self):
        ip = self.ip_var.get().strip()
        if not ip:
            messagebox.showerror("오류", "서버 IP를 입력하세요.")
            return
        try:
            self.cmd_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.cmd_sock.connect((ip, PORT))
            self.scr_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.scr_sock.connect((ip, SCREEN_PORT))
            self.connected = True
            self.status_var.set(f"🟢 연결됨: {ip}")
            self.btn_connect.configure(state="disabled")
            self.btn_disconnect.configure(state="normal")
            threading.Thread(target=self._recv_screen_loop, daemon=True).start()
            threading.Thread(target=self._recv_cmd_loop, daemon=True).start()
        except Exception as e:
            messagebox.showerror("연결 실패", f"서버에 연결할 수 없습니다.\n{e}")

    def disconnect(self):
        self.connected = False
        try:
            if self.cmd_sock: self.cmd_sock.close()
            if self.scr_sock: self.scr_sock.close()
        except:
            pass
        self.status_var.set("⏹ 연결 안됨")
        self.btn_connect.configure(state="normal")
        self.btn_disconnect.configure(state="disabled")
        self.screen_label.configure(image="", text="화면 연결 해제됨")

    # ── 화면 수신 루프 ─────────────────────────────────────────
    def _recv_screen_loop(self):
        while self.connected:
            try:
                data = recv_data(self.scr_sock)
                if not data:
                    break
                img = Image.open(io.BytesIO(data))
                # 뷰어 크기에 맞게 조정
                w = self.screen_label.winfo_width() or 640
                h = self.screen_label.winfo_height() or 480
                img.thumbnail((w, h), Image.LANCZOS)
                photo = ImageTk.PhotoImage(img)
                self.screen_label.configure(image=photo, text="")
                self.screen_label.image = photo
            except Exception as e:
                if self.connected:
                    print(f"화면 수신 오류: {e}")
                break

    # ── 명령 수신 루프 ─────────────────────────────────────────
    def _recv_cmd_loop(self):
        while self.connected:
            try:
                data = recv_data(self.cmd_sock)
                if not data:
                    break
                msg = json.loads(data.decode("utf-8"))
                if msg.get("type") == "shell_result":
                    self._shell_result = msg.get("output", "")
                    self._pending_result.set()
            except Exception as e:
                if self.connected:
                    print(f"수신 오류: {e}")
                break

    # ── 마우스/키 이벤트 ──────────────────────────────────────
    def _send(self, obj):
        if not self.connected or not self.cmd_sock:
            return
        try:
            send_data(self.cmd_sock, json.dumps(obj).encode("utf-8"))
        except:
            pass

    def _on_mouse_move(self, e):
        self._send({"action": "mouse_move", "x": e.x, "y": e.y})

    def _on_click(self, e, btn):
        self.screen_label.focus_set()
        self._send({"action": "mouse_click", "x": e.x, "y": e.y, "button": btn})

    def _on_double_click(self, e):
        self._send({"action": "mouse_double_click", "x": e.x, "y": e.y})

    def _on_scroll(self, e):
        self._send({"action": "mouse_scroll", "delta": 1 if e.delta > 0 else -1})

    def _on_key(self, e):
        if not self.connected:
            return
        # 특수키
        key_map = {
            "Return": "enter", "BackSpace": "backspace", "Tab": "tab",
            "Escape": "escape", "Delete": "delete", "Up": "up", "Down": "down",
            "Left": "left", "Right": "right", "F5": "f5", "F11": "f11",
        }
        key = key_map.get(e.keysym)
        if key:
            self._send({"action": "key_press", "key": key})
        elif e.char and e.char.isprintable():
            self._send({"action": "key_press", "key": e.char})

    def _send_combo(self, keys):
        self._send({"action": "key_combo", "keys": keys})

    def _send_text(self):
        text = self.text_var.get()
        if not text:
            return
        for ch in text:
            self._send({"action": "key_press", "key": ch})
        self.text_var.set("")

    # ── 원격 명령 ─────────────────────────────────────────────
    def _send_command(self):
        cmd = self.cmd_var.get().strip()
        if not cmd:
            return
        self._run_quick_cmd(cmd)

    def _run_quick_cmd(self, cmd):
        if not self.connected:
            messagebox.showwarning("알림", "서버에 먼저 연결하세요.")
            return
        self._pending_result.clear()
        self._shell_result = ""
        self._send({"action": "shell", "command": cmd})
        self.cmd_var.set("")

        def wait_result():
            got = self._pending_result.wait(timeout=35)
            output = self._shell_result if got else "[타임아웃] 응답 없음"
            self.result_box.configure(state="normal")
            self.result_box.delete("1.0", "end")
            self.result_box.insert("end", output if output.strip() else "(출력 없음)")
            self.result_box.configure(state="disabled")

        threading.Thread(target=wait_result, daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientApp(root)
    root.mainloop()
