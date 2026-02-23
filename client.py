"""
원격 제어 클라이언트 v2 (제어하는 PC에서 실행)
pip install pillow
"""

import socket, threading, struct, io, json, subprocess, sys, time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

try:
    from PIL import Image, ImageTk
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pillow"])
    from PIL import Image, ImageTk

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

# ── 클라이언트 앱 ─────────────────────────────────────────────
class ClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🎮 원격 제어 클라이언트 v2")
        self.root.configure(bg="#1e1e2e")
        self.root.state("zoomed")           # 최대화로 시작

        self.cmd_sock = None
        self.scr_sock = None
        self.connected = False

        # 서버 실제 화면 해상도 (좌표 변환용)
        self.srv_w = 1920
        self.srv_h = 1080

        self._shell_result = ""
        self._result_evt = threading.Event()

        self._build()
        self.root.bind("<Configure>", lambda e: None)

    # ── UI 구성 ───────────────────────────────────────────────
    def _build(self):
        # 상단 바
        top = tk.Frame(self.root, bg="#181825", pady=6)
        top.pack(fill="x")

        tk.Label(top, text="서버 IP:", bg="#181825", fg="#cdd6f4",
                 font=("Consolas", 10)).pack(side="left", padx=(12, 4))
        self.ip_var = tk.StringVar(value="192.168.0.1")
        tk.Entry(top, textvariable=self.ip_var, width=16,
                 bg="#313244", fg="#cdd6f4", insertbackground="white",
                 relief="flat", font=("Consolas", 10)).pack(side="left", padx=4)

        self.b_conn = tk.Button(top, text="연결", bg="#89b4fa", fg="#1e1e2e",
                                 font=("Consolas", 10, "bold"), relief="flat",
                                 padx=12, pady=3, cursor="hand2", command=self.connect)
        self.b_conn.pack(side="left", padx=6)
        self.b_disc = tk.Button(top, text="해제", bg="#f38ba8", fg="#1e1e2e",
                                 font=("Consolas", 10, "bold"), relief="flat",
                                 padx=12, pady=3, cursor="hand2",
                                 command=self.disconnect, state="disabled")
        self.b_disc.pack(side="left", padx=2)

        self.st_var = tk.StringVar(value="⏹ 연결 안됨")
        tk.Label(top, textvariable=self.st_var, bg="#181825",
                 fg="#fab387", font=("Consolas", 10)).pack(side="left", padx=14)

        # FPS 표시
        self.fps_var = tk.StringVar(value="")
        tk.Label(top, textvariable=self.fps_var, bg="#181825",
                 fg="#6c7086", font=("Consolas", 9)).pack(side="right", padx=12)

        # 메인 영역
        main = tk.Frame(self.root, bg="#1e1e2e")
        main.pack(fill="both", expand=True)

        # ── 화면 뷰어 (왼쪽, 꽉 채움) ────────────────────────
        self.canvas = tk.Canvas(main, bg="#000000", cursor="crosshair",
                                highlightthickness=0)
        self.canvas.pack(side="left", fill="both", expand=True)
        # 캔버스 크기가 확정된 뒤 서버 해상도 정보 수신하도록 after 등록
        self.root.after(200, lambda: None)

        # 마우스 이벤트
        self.canvas.bind("<Motion>",          self._mv)
        self.canvas.bind("<ButtonPress-1>",   lambda e: self._md(e, "left"))
        self.canvas.bind("<ButtonRelease-1>", lambda e: self._mu(e, "left"))
        self.canvas.bind("<ButtonPress-3>",   lambda e: self._md(e, "right"))
        self.canvas.bind("<ButtonRelease-3>", lambda e: self._mu(e, "right"))
        self.canvas.bind("<Double-Button-1>", self._dbl)
        self.canvas.bind("<MouseWheel>",      self._scroll)
        self.canvas.bind("<Button-4>",        lambda e: self._send({"action":"mouse_scroll","delta":3}))
        self.canvas.bind("<Button-5>",        lambda e: self._send({"action":"mouse_scroll","delta":-3}))
        self.canvas.bind("<FocusIn>",         lambda e: None)

        # 키보드 (캔버스 포커스 필요)
        self.canvas.bind("<KeyPress>", self._key)
        self.canvas.configure(takefocus=True)

        # ── 우측 패널 ─────────────────────────────────────────
        right = tk.Frame(main, bg="#1e1e2e", width=280)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)

        def sec(title):
            tk.Label(right, text=title, bg="#1e1e2e", fg="#89b4fa",
                     font=("Consolas", 10, "bold")).pack(anchor="w", padx=10, pady=(10,2))

        # 단축키
        sec("⌨  단축키")
        sc_frame = tk.Frame(right, bg="#1e1e2e")
        sc_frame.pack(fill="x", padx=8)
        shortcuts = [
            ("Ctrl+C",  ["ctrl","c"]),   ("Ctrl+V",  ["ctrl","v"]),
            ("Ctrl+X",  ["ctrl","x"]),   ("Ctrl+Z",  ["ctrl","z"]),
            ("Ctrl+A",  ["ctrl","a"]),   ("Ctrl+S",  ["ctrl","s"]),
            ("Alt+F4",  ["alt","f4"]),   ("Win+D",   ["win","d"]),
            ("Win+E",   ["win","e"]),    ("F5",       ["f5"]),
            ("Ctrl+Alt+Del", ["ctrl","alt","delete"]),
            ("Win+L",   ["win","l"]),
        ]
        for i, (lbl, keys) in enumerate(shortcuts):
            tk.Button(sc_frame, text=lbl, bg="#313244", fg="#cdd6f4",
                      font=("Consolas", 8), relief="flat", cursor="hand2",
                      activebackground="#45475a",
                      command=lambda k=keys: self._send({"action":"key_combo","keys":k})
                      ).grid(row=i//3, column=i%3, padx=2, pady=2, sticky="ew")
        for c in range(3): sc_frame.columnconfigure(c, weight=1)

        tk.Frame(right, bg="#45475a", height=1).pack(fill="x", padx=10, pady=8)

        # 텍스트 전송
        sec("📝  텍스트 전송")
        self.txt_var = tk.StringVar()
        e = tk.Entry(right, textvariable=self.txt_var, bg="#313244", fg="#cdd6f4",
                     insertbackground="white", relief="flat", font=("Consolas", 10))
        e.pack(fill="x", padx=10, pady=(0,4))
        e.bind("<Return>", lambda ev: self._send_text())
        tk.Button(right, text="전송 (Enter)", bg="#a6e3a1", fg="#1e1e2e",
                  font=("Consolas", 10, "bold"), relief="flat", cursor="hand2",
                  command=self._send_text).pack(fill="x", padx=10)

        tk.Frame(right, bg="#45475a", height=1).pack(fill="x", padx=10, pady=8)

        # 명령 실행
        sec("💻  원격 명령 실행")
        self.cmd_var = tk.StringVar()
        ce = tk.Entry(right, textvariable=self.cmd_var, bg="#313244", fg="#cdd6f4",
                      insertbackground="white", relief="flat", font=("Consolas", 10))
        ce.pack(fill="x", padx=10, pady=(0,4))
        ce.bind("<Return>", lambda ev: self._exec_cmd())

        qf = tk.Frame(right, bg="#1e1e2e")
        qf.pack(fill="x", padx=10, pady=(0,4))
        for lbl, cmd in [("IP정보","ipconfig"), ("시스템정보","systeminfo | findstr OS"),
                          ("프로세스","tasklist"), ("디스크","wmic logicaldisk get caption,freespace,size")]:
            tk.Button(qf, text=lbl, bg="#45475a", fg="#cdd6f4",
                      font=("Consolas", 8), relief="flat", cursor="hand2",
                      command=lambda c=cmd: self._run_cmd(c)
                      ).pack(side="left", padx=1)

        tk.Button(right, text="▶  실행", bg="#a6e3a1", fg="#1e1e2e",
                  font=("Consolas", 10, "bold"), relief="flat", cursor="hand2",
                  command=self._exec_cmd).pack(fill="x", padx=10)

        tk.Label(right, text="결과:", bg="#1e1e2e", fg="#6c7086",
                 font=("Consolas", 8)).pack(anchor="w", padx=10, pady=(6,0))
        self.res_box = scrolledtext.ScrolledText(
            right, bg="#181825", fg="#a6e3a1", font=("Consolas", 8),
            state="disabled", relief="flat"
        )
        self.res_box.pack(fill="both", expand=True, padx=10, pady=(0,10))

        # FPS 카운터
        self._fps_count = 0
        self._fps_last  = time.time()

    # ── 좌표 변환: 캔버스 픽셀 → 서버 실제 픽셀 ─────────────
    def _to_srv(self, cx, cy):
        cw = self.canvas.winfo_width()
        ch = self.canvas.winfo_height()
        if cw <= 0 or ch <= 0:
            return int(cx), int(cy)
        # 캔버스 전체가 서버 화면에 1:1 매핑
        x = max(0, min(int(cx / cw * self.srv_w), self.srv_w - 1))
        y = max(0, min(int(cy / ch * self.srv_h), self.srv_h - 1))
        return x, y

    # ── 연결 / 해제 ───────────────────────────────────────────
    def connect(self):
        ip = self.ip_var.get().strip()
        if not ip:
            messagebox.showerror("오류", "IP를 입력하세요"); return
        try:
            self.cmd_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.cmd_sock.settimeout(5)
            self.cmd_sock.connect((ip, CMD_PORT))
            self.cmd_sock.settimeout(None)
            self.cmd_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            self.scr_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.scr_sock.settimeout(5)
            self.scr_sock.connect((ip, SCR_PORT))
            self.scr_sock.settimeout(None)
            self.scr_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            self.connected = True
            self.st_var.set(f"🟢 연결됨: {ip}")
            self.b_conn.configure(state="disabled")
            self.b_disc.configure(state="normal")

            threading.Thread(target=self._scr_loop, daemon=True).start()
            threading.Thread(target=self._cmd_loop, daemon=True).start()
        except Exception as e:
            messagebox.showerror("연결 실패", f"{e}")

    def disconnect(self):
        self.connected = False
        for s in [self.cmd_sock, self.scr_sock]:
            try: s.close()
            except: pass
        self.st_var.set("⏹ 연결 안됨")
        self.fps_var.set("")
        self.b_conn.configure(state="normal")
        self.b_disc.configure(state="disabled")
        self.canvas.delete("all")

    # ── 화면 수신 루프 ────────────────────────────────────────
    def _scr_loop(self):
        first = True
        while self.connected:
            try:
                data = recv_msg(self.scr_sock)
                if not data: break

                msg = None
                if first:
                    try:
                        msg = json.loads(data)
                    except:
                        pass

                if msg and msg.get("type") == "screen_size":
                    self.srv_w = msg["w"]
                    self.srv_h = msg["h"]
                    first = False
                    continue

                first = False
                img = Image.open(io.BytesIO(data))

                # 캔버스 크기에 맞게 stretch (letterbox 없음 → 꽉 참)
                cw = self.canvas.winfo_width()
                ch = self.canvas.winfo_height()
                if cw > 1 and ch > 1:
                    img = img.resize((cw, ch), Image.NEAREST)

                photo = ImageTk.PhotoImage(img)
                self.canvas.create_image(0, 0, anchor="nw", image=photo)
                self.canvas.image = photo

                # FPS 계산
                self._fps_count += 1
                now = time.time()
                if now - self._fps_last >= 1.0:
                    fps = self._fps_count / (now - self._fps_last)
                    self.fps_var.set(f"{fps:.0f} fps")
                    self._fps_count = 0
                    self._fps_last = now

            except Exception as e:
                if self.connected: print(f"화면 수신 오류: {e}")
                break

    # ── 명령 수신 루프 ────────────────────────────────────────
    def _cmd_loop(self):
        while self.connected:
            try:
                data = recv_msg(self.cmd_sock)
                if not data: break
                msg = json.loads(data)
                if msg.get("type") == "shell_result":
                    self._shell_result = msg.get("output", "")
                    self._result_evt.set()
            except Exception as e:
                if self.connected: print(f"수신 오류: {e}")
                break

    # ── 전송 ─────────────────────────────────────────────────
    def _send(self, obj):
        if not self.connected or not self.cmd_sock: return
        try:
            send_msg(self.cmd_sock, json.dumps(obj).encode())
        except: pass

    # ── 마우스 이벤트 ─────────────────────────────────────────
    def _mv(self, e):
        x, y = self._to_srv(e.x, e.y)
        self._send({"action": "mouse_move", "x": x, "y": y})

    def _md(self, e, btn):
        self.canvas.focus_set()
        x, y = self._to_srv(e.x, e.y)
        self._send({"action": "mouse_down", "x": x, "y": y, "btn": btn})

    def _mu(self, e, btn):
        x, y = self._to_srv(e.x, e.y)
        self._send({"action": "mouse_up",   "x": x, "y": y, "btn": btn})

    def _dbl(self, e):
        x, y = self._to_srv(e.x, e.y)
        self._send({"action": "mouse_double", "x": x, "y": y})

    def _scroll(self, e):
        delta = 3 if e.delta > 0 else -3
        self._send({"action": "mouse_scroll", "delta": delta})

    # ── 키보드 이벤트 ─────────────────────────────────────────
    def _key(self, e):
        KMAP = {
            "Return":"enter","BackSpace":"backspace","Tab":"tab",
            "Escape":"esc","Delete":"delete","Up":"up","Down":"down",
            "Left":"left","Right":"right","space":"space",
            "F1":"f1","F2":"f2","F3":"f3","F4":"f4","F5":"f5",
            "F11":"f11","F12":"f12","Print":"print_screen",
        }
        k = KMAP.get(e.keysym)
        if k:
            self._send({"action": "key_press", "key": k})
        elif e.char and e.char.isprintable() and len(e.char) == 1:
            # e.char 가 실제 입력 문자 (대소문자 구분, 한글 포함)
            self._send({"action": "key_press", "key": e.char})

    # ── 텍스트 전송 ───────────────────────────────────────────
    def _send_text(self):
        t = self.txt_var.get()
        if not t: return
        for ch in t:
            self._send({"action": "key_press", "key": ch})
        self.txt_var.set("")

    # ── 명령 실행 ─────────────────────────────────────────────
    def _exec_cmd(self):
        cmd = self.cmd_var.get().strip()
        if cmd:
            self.cmd_var.set("")
            self._run_cmd(cmd)

    def _run_cmd(self, cmd):
        if not self.connected:
            messagebox.showwarning("알림", "먼저 연결하세요"); return
        self._result_evt.clear()
        self._shell_result = ""
        self._send({"action": "shell", "command": cmd})

        def wait():
            ok = self._result_evt.wait(timeout=35)
            out = self._shell_result if ok else "[타임아웃]"
            self.res_box.configure(state="normal")
            self.res_box.delete("1.0", "end")
            self.res_box.insert("end", out)
            self.res_box.configure(state="disabled")

        threading.Thread(target=wait, daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    ClientApp(root)
    root.mainloop()
