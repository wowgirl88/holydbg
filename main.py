import os
import socket
import subprocess
import sys
import psutil
import re
import time
from types import FrameType
from typing import Dict, List, Optional, Tuple, Union

from pyinjector import inject
from prompt_toolkit import prompt
from prompt_toolkit.history import InMemoryHistory

BANNER = """
██╗  ██╗ ██████╗ ██╗  ██╗   ██╗██████╗ ██████╗  ██████╗ 
██║  ██║██╔═══██╗██║  ╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝ 
███████║██║   ██║██║   ╚████╔╝ ██║  ██║██████╔╝██║  ███╗
██╔══██║██║   ██║██║    ╚██╔╝  ██║  ██║██╔══██╗██║   ██║
██║  ██║╚██████╔╝███████╗██║   ██████╔╝██████╔╝╚██████╔╝
╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚═════╝ ╚═════╝  ╚═════╝ 
       
By Creative Name Here

my github: wowgirl88
my Telegram: @slvtb0y

Started scanning...
"""

def exception(e: str) -> None:
    """catches exception"""
    frame: Optional[FrameType] = sys._getframe().f_back
    stack: List[List[Union[str, int]]] = []
    while frame:
        _tmp_path: str = frame.f_code.co_filename
        dir_name: str = os.path.dirname(_tmp_path)
        tmp_path: str = os.path.join(
            os.path.basename(dir_name), os.path.basename(_tmp_path)
        )
        stack.append([frame.f_code.co_name, tmp_path, frame.f_lineno])
        frame: Optional[FrameType] = frame.f_back
    stack.reverse()
    print(f"[ERROR] {e}")
    for name, file, line in stack:
        print(f"> [{name}] {file}:{line}")


class HolyDebug:
    """debugger class"""

    def __init__(
        self, pid: Optional[int] = None, verbose: bool = False, gdb_prefix: str = ""
    ):
        self.pid: int = pid
        self.last_response: str = ""
        self.verbose: bool = verbose
        self.gdb_prefix: str = gdb_prefix
        self.lang: str = "en"
        self.help_text: dict = {
            "en": {
                "objects": "Display module structure. Usage: 'objects'",
                "dump": "Dump object bytecode. Usage: 'dump <object>'",
                "dis": "Disassemble object. Usage: 'dis <function>'",
                "get": "Get variable. Usage: 'get <variable>'",
                "objects-type": "Find vars by type. Usage: 'objects-type <type>'",
                "search": "Inspect class attributes. Usage: 'search <Class.attr>'",
                "rrun": "Execute code. Usage: 'rrun <file.py>'",
                "clear": "Clear dbg console. Usage: 'clear'",
                "capture": "Dump whole module. Usage: 'capture'",
                "modules": "Show loaded modules. Usage: 'modules'",
                "stack": "Shows stack. Usage: 'stack'",
                "tokens": "Search for Telegram bot and leak osint tokens. Usage: 'bot-tokens'",
                "dict": "Show class' __dict__. Usage: 'dict <class_name>'",
                "help": "Show help",
                "threads": "List active threads",
                "setlang": "Change dbg language. Usage: 'setlang ru/eng'",
                "locals": "Show local variables in all stack frames. Usage: 'locals'",
                "globals": "Show global variables in module frame. Usage: 'globals'",
                "find": "Finding the use of a variable in the code. Usage: 'find <var>'",
                "fnames": "Show all frames names. Usage: 'fnames'",
                "fdump": "Dump frame. Usage: 'fdump <index>",
                "fsdump": "Dump all frames. Usage: 'fsdump'",
                "fdis": "Disassemble frame. Usage: 'fdis <index>'",
                "export": "Save last command output to file. Usage: 'export <filename>'",
                "inject": "Inject .so in process. Usage: 'inject <soname>'",
                "struct": "Show program structure. Usage: 'struct'",
                "q": "Exit debugger",
            },
            "ru": {
                "objects": "Показать структуру модуля. Использование: 'objects'",
                "dump": "Выгрузить байткод объекта. Использование: 'dump <объект>'",
                "dis": "Дизассемблировать объект. Использование: 'dis <функция>'",
                "get": "Получить переменную. Использование: 'get <переменная>'",
                "objects-type": "Найти переменные по типу. Использование: 'objects-type <тип>'",
                "search": "Просмотреть атрибуты класса. Использование: 'search <Класс.атрибут>'",
                "rrun": "Выполнить код. Использование: 'rrun <файл.py>'",
                "clear": "Очистить консоль отладчика. Использование: 'clear'",
                "capture": "Сдампить весь модуль. Использование: 'capture'",
                "modules": "Показать загруженные модули. Использование: 'modules'",
                "stack": "Показать стек вызовов. Использование: 'stack'",
                "tokens": "Поиск токенов Telegram бота и leak osint. Использование: 'bot-tokens'",
                "dict": "Показать __dict__ класса. Использование: 'dict <имя_класса>'",
                "help": "Показать помощь",
                "threads": "Список активных потоков",
                "locals": "Показать локальные переменные во всех фреймах стека. Использование: 'locals'",
                "globals": "Показывать глобальные переменные во фрейме модуля. Использование: 'globals'",
                "find": "Найти использования переменной в коде. Использование: 'find <название_переменной>'",
                "fnames": "Показать имена всех фреймов. Использование: 'fnames'",
                "fdump": "Сдампить фрейм. Использование: 'fdump <индекс фрейма>'",
                "fsdump": "Сдампить все фреймы. Использование: 'fsdump'",
                "fdis": "Дизассемблировать фрейм. Использование: 'dis <индекс фрейма>'",
                "export": "Сохранить вывод последней команды в файл. Использование: 'export <имя файла>'",
                "inject": "Запустить .so код в процессе. Использование: 'inject <название.so>'",
                "struct": "Показывает структуру программы. Использование: 'struct'",
                "q": "Выйти из отладчика",
            },
        }

    def check_port(self) -> bool:
        """Check if server is running"""
        try:
            with socket.socket() as s:
                s.settimeout(1)
                s.connect(("127.1.4.88", 1161))
                return True
        except Exception:
            return False

    def send_command(self, cmd: str, payload: str = "") -> str:
        """send command to server and save response"""
        try:
            with socket.socket() as s:
                s.settimeout(3)
                s.connect(("127.1.4.88", 1161))
                s.sendall(f"{cmd}:{payload}".encode())
                data: bytes = b""
                while True:
                    chunk: bytes = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk

                response: str = data.decode()
                self.last_response = response
                return response
        except Exception as e:
            return exception(str(e))

    def dbg_loop(self) -> None:
        """Main debugger loop"""
        history: InMemoryHistory = InMemoryHistory()
        if not self.check_port():
            print("[holy-dbg] Injecting server...")
            inject(self.pid, "inject_server.so")
            time.sleep(2)
            if not self.check_port():
                print("[holy-dbg] Failed to start debug server")
                return
            print("[holy-dbg.Injector] Server injected")
        else:
            choice = input("[Holy-dbg.Server] Open port is found, restore connection?(y/n): ")
            if choice == "y":
                print("[holy-dbg] Connection restored!")
            else:
                sys.exit(0)

        print("[holy-dbg.Server] IP: 127.1.4.88")
        print(f"[holy-dbg.Server] Port: 1161")
        print("[holy-debug] by Creative Name Here")
        print("[TELEGRAM] slvtb0y.t.me")
        print(
            f"[holy-dbg.Server] Connected to process {self.pid}. Type 'help' for commands"
        )

        while True:
            try:
                user_input: List[str] = (
                    prompt("holy-dbg > ", history=history).strip().split()
                )
                if not user_input:
                    continue

                cmd: str = user_input[0].lower()
                args: str = " ".join(user_input[1:])

                if cmd == "q":
                    return
                if cmd == "pycdc":
                    subprocess.run(["pycdc", args])
                    continue
                if cmd == "pycdas":
                    subprocess.run(["pycdas", args])
                    continue
                if cmd == "setlang":
                    self.lang: str = args
                    continue
                if cmd == "inject":
                    inject(self.pid, args)
                    print("Injected")
                    continue
                if cmd == "help":
                    print(
                        "\n".join(
                            [
                                f"{cmd}: {desc}"
                                for cmd, desc in self.help_text[self.lang].items()
                            ]
                        )
                    )
                    continue
                if cmd == "clear":
                    os.system("clear")
                    print("[holy-dbg.Server] IP: 127.1.4.88")
                    print(f"[holy-dbg.Server] Port: 1161")
                    print("[holy-debug] by Creative Name Here")
                    print("[TELEGRAM] slvtb0y.t.me")
                    continue
                if cmd == "export":
                    if not args:
                        print("Usage: export <filename>")
                        continue
                    try:
                        with open(args, "w") as f:
                            f.write(self.last_response)
                        print(f"Output saved to {args}")
                    except Exception as e:
                        print(f"Error saving file: {str(e)}")
                    continue

                handlers: Dict[str, Tuple[str, str]] = {
                    "objects": ("structure", ""),
                    "dump": ("dump", args),
                    "dis": ("dis", args),
                    "get": ("getvar", args),
                    "objects-type": ("objects-type", args),
                    "search": ("search", args),
                    "rrun": (
                        "exec",
                        (
                            f'exec(open("{args}").read())'
                            if args.endswith(".py")
                            else args
                        ),
                    ),
                    "capture": ("capture", ""),
                    "modules": ("modules", ""),
                    "stack": ("backtrace", ""),
                    "threads": ("threads", ""),
                    "dict": ("searchattr", args),
                    "tokens": ("tokens", ""),
                    "locals": ("locals", ""),
                    "globals": ("globals", ""),
                    "find": ("findvar", args),
                    "fnames": ("fnames", ""),
                    "fsdump": ("fsdump", ""),
                    "fdump": ("fdump", args),
                    "fdis": ("fdis", args),
                    "codeinfo": ("codeinfo", args),
                    "struct": ("struct", "")
                }
                server_cmd: str
                payload: str
                result: tuple[str] = handlers.get(cmd, ("", ""))
                server_cmd: str = result[0]
                payload: str = result[1]
                response: str = self.send_command(server_cmd, payload)
                print(response)

            except KeyboardInterrupt:
                print("\nUse 'q' to quit")
            except Exception as e:
                exception(str(e))


def scan_linux():
    offset = 0
    processes = []
    regex_python_so = re.compile(r'libpython(\d+\.\d+|\d+)\.so')
    for proc in psutil.process_iter(['pid', 'name', 'memory_maps']):
        try:
            maps = proc.info['memory_maps']
            version = None
            if maps:
                for mem_map in maps:
                    if mem_map.path:
                        so_name = os.path.basename(mem_map.path)
                        match = regex_python_so.match(so_name)
                        if match:
                            version_part = match.group(1) if match.group(1) else ""
                            version = f"libpython{version_part}.so"
                            break 
            if version:
                pid = str(proc.info['pid'])
                name = proc.info['name']
                c_offset = max(len(pid), len(name), len(version))
                if c_offset > offset:
                    offset = c_offset
                processes.append((pid, name, version))

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except Exception as e:
            pass

    max_pid_len = max(len(p[0]) for p in processes) if processes else 3
    max_name_len = max(len(p[1]) for p in processes) if processes else 4
    max_version_len = max(len(p[2]) for p in processes) if processes else 7
    pid_offset = max(len("PID"), max_pid_len)
    name_offset = max(len("NAME"), max_name_len)
    version_offset = max(len("VERSION"), max_version_len) 
    splitter = f"+{'-' * (pid_offset + 2)}+{'-' * (name_offset + 2)}+{'-' * (version_offset + 2)}+"
    compiler = lambda a, b, c: f"| {str(a).ljust(pid_offset)} | {str(b).ljust(name_offset)} | {str(c).ljust(version_offset)} |"
    print(splitter)
    print(compiler("PID", "NAME", "VERSION"))
    print(splitter)
    for pid, name, version in processes:
        if int(pid) != os.getpid() and name != "kitty":
            print(compiler(pid, name, version))
    print(splitter)

def main() -> None:
    """main programm function"""
    print(BANNER)
    scan_linux()
    pid = int(input("Enter pid: "))
    dbg = HolyDebug(pid=pid)
    dbg.dbg_loop()

if __name__ == "__main__":
    main()
