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
import queue
import struct
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
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
MAX_MODULE_NAME32 = 255
MAX_PATH = 260

LRESULT = ctypes.c_ssize_t

kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", ctypes.c_wchar * (MAX_MODULE_NAME32 + 1)),
        ("szExePath", ctypes.c_wchar * MAX_PATH),
    ]

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
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32FirstW.restype = wintypes.BOOL
kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32NextW.restype = wintypes.BOOL
kernel32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
kernel32.IsWow64Process.restype = wintypes.BOOL

user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.DefWindowProcW.restype = LRESULT
user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
user32.FindWindowW.restype = wintypes.HWND
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD
user32.SetTimer.argtypes = [wintypes.HWND, ctypes.c_size_t, wintypes.UINT, ctypes.c_void_p]
user32.SetTimer.restype = ctypes.c_size_t


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
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        log.info("心跳已启动 (间隔=%ds)", self.interval)

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)
        log.info("心跳已停止")

    def _run(self):
        while not self._stop_event.is_set():
            self.client.heartbeat()
            self._stop_event.wait(self.interval)


class WeChatHook:
    MAX_PUSH_RETRIES = 3
    PUSH_RETRY_DELAY = 2

    def __init__(self, dll_path: str):
        self.dll_path = os.path.abspath(dll_path)
        self._hwnd = None
        self._on_payment = None
        self._wnd_proc_ref = None
        self._payment_queue = queue.Queue()
        self._worker_thread = None

    def set_payment_callback(self, callback):
        self._on_payment = callback
        self._worker_thread = threading.Thread(
            target=self._payment_worker, daemon=True
        )
        self._worker_thread.start()

    def _payment_worker(self):
        while True:
            pay_type, amount = self._payment_queue.get()
            for attempt in range(1, self.MAX_PUSH_RETRIES + 1):
                try:
                    if self._on_payment and self._on_payment(pay_type, amount):
                        break
                except Exception as e:
                    log.error("推送支付通知失败 (第%d次): %s", attempt, e)
                if attempt < self.MAX_PUSH_RETRIES:
                    time.sleep(self.PUSH_RETRY_DELAY)
                else:
                    log.error("推送支付通知最终失败: type=%d price=%s", pay_type, amount)
            self._payment_queue.task_done()

    def find_wechat_pid(self) -> int | None:
        for cls_name in ("WeChatMainWndForPC", "WeChatLoginWndForPC"):
            hwnd = user32.FindWindowW(cls_name, None)
            if hwnd:
                pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if pid.value:
                    return pid.value
        return None

    def _is_target_wow64(self, h_process) -> bool:
        is_wow64 = wintypes.BOOL(False)
        kernel32.IsWow64Process(h_process, ctypes.byref(is_wow64))
        return bool(is_wow64.value)

    def _get_remote_kernel32_base(self, pid: int) -> int | None:
        snap = kernel32.CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid
        )
        if snap == wintypes.HANDLE(-1).value or snap == -1:
            log.error("CreateToolhelp32Snapshot 失败")
            return None
        try:
            me = MODULEENTRY32W()
            me.dwSize = ctypes.sizeof(MODULEENTRY32W)
            if not kernel32.Module32FirstW(snap, ctypes.byref(me)):
                return None
            while True:
                mod_name = me.szModule.lower()
                if mod_name == "kernel32.dll":
                    return ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value
                if not kernel32.Module32NextW(snap, ctypes.byref(me)):
                    break
        finally:
            kernel32.CloseHandle(snap)
        return None

    def _get_load_library_addr(self, pid: int, h_process) -> int | None:
        we_are_64 = ctypes.sizeof(ctypes.c_void_p) == 8
        target_is_wow64 = self._is_target_wow64(h_process)

        if we_are_64 and target_is_wow64:
            log.debug("跨架构注入: 64位进程 -> 32位目标")
            remote_k32_base = self._get_remote_kernel32_base(pid)
            if not remote_k32_base:
                log.error("无法获取目标进程 kernel32 基址")
                return None
            log.debug("目标 kernel32 基址: 0x%08X", remote_k32_base)

            syswow64 = os.path.join(
                os.environ.get("SystemRoot", r"C:\Windows"),
                "SysWOW64", "kernel32.dll"
            )
            if not os.path.exists(syswow64):
                log.error("找不到 32 位 kernel32: %s", syswow64)
                return None

            with open(syswow64, "rb") as f:
                pe_data = f.read()

            pe_off = struct.unpack_from("<I", pe_data, 0x3C)[0]
            export_rva = struct.unpack_from("<I", pe_data, pe_off + 24 + 96)[0]

            sections = []
            num_sec = struct.unpack_from("<H", pe_data, pe_off + 6)[0]
            opt_size = struct.unpack_from("<H", pe_data, pe_off + 20)[0]
            sec_off = pe_off + 24 + opt_size
            for i in range(num_sec):
                s = sec_off + i * 40
                va = struct.unpack_from("<I", pe_data, s + 12)[0]
                raw_size = struct.unpack_from("<I", pe_data, s + 16)[0]
                raw_ptr = struct.unpack_from("<I", pe_data, s + 20)[0]
                v_size = struct.unpack_from("<I", pe_data, s + 8)[0]
                sections.append((va, v_size, raw_ptr, raw_size))

            def rva_to_file(rva):
                for va, vs, rp, rs in sections:
                    if va <= rva < va + max(vs, rs):
                        return rp + (rva - va)
                return None

            exp_off = rva_to_file(export_rva)
            if exp_off is None:
                log.error("无法解析 kernel32 导出表")
                return None

            num_funcs = struct.unpack_from("<I", pe_data, exp_off + 24)[0]
            num_names = struct.unpack_from("<I", pe_data, exp_off + 24)[0]
            addr_table_rva = struct.unpack_from("<I", pe_data, exp_off + 28)[0]
            name_table_rva = struct.unpack_from("<I", pe_data, exp_off + 32)[0]
            ord_table_rva = struct.unpack_from("<I", pe_data, exp_off + 36)[0]

            name_table_off = rva_to_file(name_table_rva)
            addr_table_off = rva_to_file(addr_table_rva)
            ord_table_off = rva_to_file(ord_table_rva)

            for i in range(num_names):
                name_rva = struct.unpack_from("<I", pe_data, name_table_off + i * 4)[0]
                name_off = rva_to_file(name_rva)
                end = pe_data.index(b"\x00", name_off)
                name = pe_data[name_off:end]
                if name == b"LoadLibraryW":
                    ordinal = struct.unpack_from("<H", pe_data, ord_table_off + i * 2)[0]
                    func_rva = struct.unpack_from("<I", pe_data, addr_table_off + ordinal * 4)[0]
                    addr = remote_k32_base + func_rva
                    log.debug("LoadLibraryW RVA=0x%X, 远程地址=0x%08X", func_rva, addr)
                    return addr

            log.error("在 32 位 kernel32 中找不到 LoadLibraryW")
            return None
        else:
            h_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
            addr = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryW")
            if not addr:
                log.error("GetProcAddress(LoadLibraryW) 失败")
            return addr

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

            load_library_addr = self._get_load_library_addr(pid, h_process)
            if not load_library_addr:
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
                log.error("LoadLibraryW 返回 0, DLL 加载失败")
                return False

            log.info("DLL 已注入微信 (PID=%d, module=0x%08X)", pid, exit_code.value)
            return True
        finally:
            kernel32.CloseHandle(h_process)

    def create_window(self, on_timer=None):
        WM_TIMER = 0x0113

        def wnd_proc(hwnd, msg, wparam, lparam):
            if msg == WM_COPYDATA:
                cds = ctypes.cast(lparam, ctypes.POINTER(COPYDATASTRUCT)).contents
                if cds.cbData > 0 and cds.lpData:
                    raw = ctypes.string_at(cds.lpData, cds.cbData)
                    try:
                        try:
                            text = raw.decode("utf-8").rstrip("\x00")
                        except UnicodeDecodeError:
                            text = raw.decode("gbk").rstrip("\x00")
                        self._handle_message(text)
                    except Exception as e:
                        log.error("处理消息异常: %s", e)
                return 0
            if msg == WM_TIMER and on_timer:
                on_timer()
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
            self._payment_queue.put((1, amount))

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

    injected_pid = None

    def check_and_inject():
        nonlocal injected_pid
        pid = hook.find_wechat_pid()
        if pid and pid != injected_pid:
            log.info("找到微信 (PID=%d), 注入 Hook...", pid)
            if hook.inject(pid):
                log.info("Hook 注入成功")
                injected_pid = pid
            else:
                log.error("Hook 注入失败")
        elif not pid and injected_pid:
            log.warning("微信已退出, 等待重新启动...")
            injected_pid = None

    if not hook.create_window(on_timer=check_and_inject):
        log.error("无法创建消息窗口")
        heartbeat.stop()
        return

    check_and_inject()
    user32.SetTimer(hook._hwnd, 1, 15000, None)

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
