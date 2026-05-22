"""
PayListener - WeChat payment monitor for vmq-go
Runs on Windows. Injects WeChatHook.dll into WeChat, listens for payment
notifications via WM_COPYDATA, and pushes them to vmq-go.
"""

import ctypes
import ctypes.wintypes as wintypes
import hashlib
import json
import logging
import logging.handlers
import os
import sys
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass

import requests

if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(os.path.realpath(sys.executable))
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)
LOG_DIR = os.path.join(BASE_DIR, "logs")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

os.makedirs(LOG_DIR, exist_ok=True)

log = logging.getLogger("PayListener")
log.setLevel(logging.DEBUG)

_formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)

_file_handler = logging.handlers.RotatingFileHandler(
    os.path.join(LOG_DIR, "pay_listener.log"),
    maxBytes=5 * 1024 * 1024,
    backupCount=3,
    encoding="utf-8",
)
_file_handler.setLevel(logging.DEBUG)
_file_handler.setFormatter(_formatter)

_console_handler = logging.StreamHandler()
_console_handler.setLevel(logging.INFO)
_console_handler.setFormatter(_formatter)

log.addHandler(_file_handler)
log.addHandler(_console_handler)

# Windows constants
WM_COPYDATA = 0x004A
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
INFINITE = 0xFFFFFFFF

LRESULT = ctypes.c_ssize_t

kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualAllocEx.restype = ctypes.c_void_p
kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype = wintypes.HMODULE
kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, ctypes.c_char_p]
kernel32.GetProcAddress.restype = ctypes.c_void_p
kernel32.CreateRemoteThread.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.GetExitCodeThread.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetExitCodeThread.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.DefWindowProcW.restype = LRESULT
user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
user32.FindWindowW.restype = wintypes.HWND
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD


class COPYDATASTRUCT(ctypes.Structure):
    _fields_ = [
        ("dwData", wintypes.LPARAM),
        ("cbData", wintypes.DWORD),
        ("lpData", ctypes.c_void_p),
    ]


WNDPROC = ctypes.WINFUNCTYPE(
    LRESULT, wintypes.HWND, wintypes.UINT,
    wintypes.WPARAM, wintypes.LPARAM,
)


class WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ("style", wintypes.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HANDLE),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
    ]


user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
user32.RegisterClassW.restype = wintypes.ATOM
user32.CreateWindowExW.argtypes = [
    wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
    ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
    wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, ctypes.c_void_p,
]
user32.CreateWindowExW.restype = wintypes.HWND
user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
user32.GetMessageW.restype = wintypes.BOOL
user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
user32.TranslateMessage.restype = wintypes.BOOL
user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
user32.DispatchMessageW.restype = LRESULT


@dataclass
class Config:
    host: str
    key: str
    ssl: bool = True
    wechat_folder: str = ""
    heartbeat_interval: int = 30

    @property
    def base_url(self) -> str:
        scheme = "https" if self.ssl else "http"
        host = self.host.rstrip("/")
        if host.startswith("http://") or host.startswith("https://"):
            return host
        return f"{scheme}://{host}"

    def save(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "CallbackHost": self.host,
                "CallbackKey": self.key,
                "Callbackssl": self.ssl,
                "WeChatFolder": self.wechat_folder,
                "HeartbeatInterval": self.heartbeat_interval,
            }, f, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, path: str) -> "Config":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(
            host=data.get("CallbackHost", ""),
            key=data.get("CallbackKey", ""),
            ssl=bool(data.get("Callbackssl", True)),
            wechat_folder=data.get("WeChatFolder", ""),
            heartbeat_interval=int(data.get("HeartbeatInterval", 30)),
        )


def md5hex(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


class VmqClient:
    def __init__(self, config: Config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "PayListener/2.0",
        })

    def heartbeat(self) -> bool:
        t = str(int(time.time()))
        sign = md5hex(t + self.config.key)
        try:
            resp = self.session.post(
                f"{self.config.base_url}/appHeart",
                json={"t": t, "sign": sign},
                timeout=10,
            )
            result = resp.json()
            if result.get("code") == 1:
                return True
            log.warning("心跳失败: %s", result.get("msg", "unknown"))
            return False
        except Exception as e:
            log.error("心跳异常: %s", e)
            return False

    def push_payment(self, pay_type: int, price: str) -> bool:
        t = str(int(time.time()))
        sign = md5hex(str(pay_type) + price + t + self.config.key)
        try:
            resp = self.session.post(
                f"{self.config.base_url}/appPush",
                json={"type": str(pay_type), "price": price, "t": t, "sign": sign},
                timeout=10,
            )
            result = resp.json()
            if result.get("code") == 1:
                log.info("收款上报成功: type=%d price=%s", pay_type, price)
                return True
            log.warning("收款上报失败: %s", result.get("msg", "unknown"))
            return False
        except Exception as e:
            log.error("收款上报异常: %s", e)
            return False


class HeartbeatWorker:
    def __init__(self, client: VmqClient, interval: int = 30):
        self.client = client
        self.interval = interval
        self._running = False
        self._thread = None

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        log.info("心跳已启动 (间隔=%ds)", self.interval)

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        log.info("心跳已停止")

    def _run(self):
        while self._running:
            self.client.heartbeat()
            time.sleep(self.interval)


class WeChatHook:
    def __init__(self, dll_path: str):
        self.dll_path = os.path.abspath(dll_path)
        self._hwnd = None
        self._on_payment = None
        self._wnd_proc_ref = None

    def set_payment_callback(self, callback):
        self._on_payment = callback

    def find_wechat_pid(self) -> int | None:
        for cls_name in ("WeChatMainWndForPC", "WeChatLoginWndForPC"):
            hwnd = user32.FindWindowW(cls_name, None)
            if hwnd:
                pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if pid.value:
                    return pid.value
        return None

    def inject(self, pid: int) -> bool:
        if not os.path.exists(self.dll_path):
            log.error("DLL 文件不存在: %s", self.dll_path)
            return False

        log.debug("注入 DLL 路径: %s", self.dll_path)
        dll_path_bytes = self.dll_path.encode("utf-16-le") + b"\x00\x00"

        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            log.error("无法打开进程 %d (GetLastError=%d)", pid, kernel32.GetLastError())
            return False

        try:
            remote_mem = kernel32.VirtualAllocEx(
                h_process, None, len(dll_path_bytes),
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
            )
            if not remote_mem:
                log.error("VirtualAllocEx 失败 (GetLastError=%d)", kernel32.GetLastError())
                return False

            written = ctypes.c_size_t(0)
            if not kernel32.WriteProcessMemory(
                h_process, remote_mem, dll_path_bytes,
                len(dll_path_bytes), ctypes.byref(written),
            ):
                log.error("WriteProcessMemory 失败 (GetLastError=%d)", kernel32.GetLastError())
                return False

            h_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
            load_library_addr = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryW")
            if not load_library_addr:
                log.error("GetProcAddress(LoadLibraryW) 失败")
                return False

            h_thread = kernel32.CreateRemoteThread(
                h_process, None, 0, load_library_addr, remote_mem, 0, None,
            )
            if not h_thread:
                log.error("CreateRemoteThread 失败 (GetLastError=%d)", kernel32.GetLastError())
                return False

            kernel32.WaitForSingleObject(h_thread, INFINITE)
            exit_code = wintypes.DWORD(0)
            kernel32.GetExitCodeThread(h_thread, ctypes.byref(exit_code))
            kernel32.CloseHandle(h_thread)

            if exit_code.value == 0:
                log.error("LoadLibraryW 返回 0, DLL 加载失败 (DLL可能是32位但微信是64位)")
                return False

            log.info("DLL 已注入微信 (PID=%d, module=0x%08X)", pid, exit_code.value)
            return True
        finally:
            kernel32.CloseHandle(h_process)

    def create_window(self):
        def wnd_proc(hwnd, msg, wparam, lparam):
            if msg == WM_COPYDATA:
                log.debug("收到 WM_COPYDATA 消息")
                cds = ctypes.cast(lparam, ctypes.POINTER(COPYDATASTRUCT)).contents
                log.debug("  dwData=%d, cbData=%d, lpData=0x%X", cds.dwData, cds.cbData, cds.lpData or 0)
                if cds.cbData > 0 and cds.lpData:
                    raw = ctypes.string_at(cds.lpData, cds.cbData)
                    try:
                        text = raw.decode("utf-8").rstrip("\x00")
                        log.debug("  内容: %s", text[:200])
                        self._handle_message(text)
                    except Exception as e:
                        log.error("处理消息异常: %s", e)
                return 0
            return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        self._wnd_proc_ref = WNDPROC(wnd_proc)

        wc = WNDCLASSW()
        wc.lpfnWndProc = self._wnd_proc_ref
        wc.lpszClassName = "PayListenerWnd"
        wc.hInstance = kernel32.GetModuleHandleW(None)

        if not user32.RegisterClassW(ctypes.byref(wc)):
            log.error("RegisterClassW 失败")
            return False

        self._hwnd = user32.CreateWindowExW(
            0, "PayListenerWnd", "支付监听回调", 0,
            0, 0, 0, 0, None, None, wc.hInstance, None,
        )
        if not self._hwnd:
            log.error("CreateWindowExW 失败")
            return False

        log.info("消息窗口已创建 (HWND=0x%X)", self._hwnd)

        verify_hwnd = user32.FindWindowW(None, "支付监听回调")
        if verify_hwnd:
            log.info("FindWindowW 验证成功 (HWND=0x%X)", verify_hwnd)
        else:
            log.error("FindWindowW 验证失败: 无法通过标题找到窗口")

        return True

    def run_message_loop(self):
        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

    def _handle_message(self, xml_text: str):
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return

        amount = self._extract_amount(root)
        if amount:
            log.info("检测到微信收款: ￥%s", amount)
            if self._on_payment:
                self._on_payment(1, amount)

    def _extract_amount(self, root: ET.Element) -> str | None:
        # Format: <line><key><word>收款金额</word></key><value><word>￥X.XX</word></value></line>
        for line in root.iter("line"):
            key_elem = line.find(".//key/word")
            val_elem = line.find(".//value/word")
            if key_elem is not None and val_elem is not None:
                if key_elem.text and "收款金额" in key_elem.text:
                    value = val_elem.text or ""
                    value = value.replace("￥", "").replace("¥", "").strip()
                    if value:
                        return value

        # Fallback: topline with ￥
        for word in root.iter("word"):
            if word.text and "￥" in word.text:
                value = word.text.replace("￥", "").strip()
                if value:
                    try:
                        float(value)
                        return value
                    except ValueError:
                        continue
        return None


def main():
    if not os.path.exists(CONFIG_PATH):
        Config(host="", key="").save(CONFIG_PATH)
        log.info("已生成配置文件: %s", CONFIG_PATH)
        log.info("请填写 CallbackHost 和 CallbackKey 后重新启动")
        return

    config = Config.load(CONFIG_PATH)
    if not config.host or not config.key:
        log.error("请在 config.json 中填写 CallbackHost 和 CallbackKey")
        return

    log.info("PayListener 启动")
    log.info("服务器: %s", config.base_url)

    client = VmqClient(config)

    log.info("测试心跳...")
    if client.heartbeat():
        log.info("心跳测试成功")
    else:
        log.warning("心跳测试失败, 请检查配置")

    heartbeat = HeartbeatWorker(client, interval=config.heartbeat_interval)
    heartbeat.start()

    dll_path = os.path.join(BASE_DIR, "WeChatHook.dll")
    hook = WeChatHook(dll_path)
    hook.set_payment_callback(client.push_payment)

    if not hook.create_window():
        log.error("无法创建消息窗口")
        heartbeat.stop()
        return

    log.info("查找微信进程...")
    pid = hook.find_wechat_pid()
    if pid:
        log.info("找到微信 (PID=%d), 注入 Hook...", pid)
        if hook.inject(pid):
            log.info("Hook 注入成功")
        else:
            log.error("Hook 注入失败")
    else:
        log.warning("未找到微信进程, 请先启动微信再重启本程序")

    try:
        hook.run_message_loop()
    except KeyboardInterrupt:
        pass
    finally:
        heartbeat.stop()
        log.info("PayListener 已退出")


if __name__ == "__main__":
    if sys.platform != "win32":
        print("本程序仅支持 Windows")
        sys.exit(1)
    main()
