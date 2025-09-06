import importlib._bootstrap_external
import socket
import inspect
import marshal
import os
import re
import types
import sys
import threading
from dis import dis
from types import ModuleType, FrameType
import io
import pprint
from typing import Optional, List, Any, Callable, Dict, Union


class _HolyNode:
    """Represents a node in the module structure tree."""

    __holy__: bool = True

    def __init__(self, name: str, children: Optional[List["_HolyNode"]] = None) -> None:
        self.name: str = name
        self.children: List[_HolyNode] = children or []

    def get_children(self) -> List["_HolyNode"]:
        """Returns the list of child nodes."""
        return self.children


class _HolyServer:
    """A remote debugger server."""

    __holy__: bool = True

    def __init__(self) -> None:
        self._holy_command_handlers: Dict[str, Callable[[str], str]] = {
            "dump": self._holy_handle_dump,
            "dis": self._holy_handle_dis,
            "structure": self._holy_handle_structure,
            "getvar": self._holy_handle_getvar,
            "exec": self._holy_handle_exec,
            "objects-type": self._holy_handle_objects_type,
            "searchattr": self._holy_handle_searchattr,
            "search": self._holy_handle_search,
            "capture": self._holy_handle_capture,
            "modules": self._holy_handle_modules,
            "backtrace": self._holy_handle_backtrace,
            "threads": self._holy_handle_threads,
            "tokens": self._holy_handle_tokens,
            "locals": self._holy_handle_locals,
            "globals": self._holy_handle_globals,
            "findvar": self._holy_handle_findvar,
            "fnames": self._holy_handle_frames_names,
            "fsdump": self._holy_handle_dump_all_frames,
            "fdump": self._holy_handle_frame_dump,
            "fdis": self._holy_handle_frame_dis,
            "struct": self._holy_handle_dump_module_structure,
        }

    @staticmethod
    def _holyexception(e: Exception) -> str:
        """Generates a detailed stack trace for an exception."""
        frame: Optional[types.FrameType] = sys._getframe().f_back
        stack: List[List[str]] = []
        while frame:
            tmppath: str = frame.f_code.co_filename
            dir_name: str = os.path.dirname(tmppath)
            tmp_path: str = os.path.join(
                os.path.basename(dir_name), os.path.basename(tmppath)
            )
            stack.append([frame.f_code.co_name, tmp_path, frame.f_lineno])
            frame: Optional[FrameType] = frame.f_back
        stack.reverse()
        error_msg: List[str] = [f"[ERROR] {e}"]
        for name, file, line in stack:
            error_msg.append(f"> [{name}] {file}:{line}")
        return "\n".join(error_msg)

    @staticmethod
    def _get_main_thread_frames() -> Optional[Dict[int, FrameType]]:
        """Returns frames for the main thread, if available."""
        main_thread = threading.main_thread()
        frames = sys._current_frames()
        return frames if main_thread.ident in frames else None

    @staticmethod
    def _get_main_module_frame() -> Optional[FrameType]:
        """Finds and returns the main module frame."""
        frames = _HolyServer._get_main_thread_frames()
        if not frames:
            return None
        frame = frames[threading.main_thread().ident]
        while frame and frame.f_code.co_name != '<module>':
            frame = frame.f_back
        return frame

    @staticmethod
    def _holyload_module_contents() -> Dict[str, Dict[str, Any]]:
        """Loads and categorizes all non-debugger-related content from the main module."""
        module_globals: Dict[str, Any] = globals()
        current_module_name: str = __name__

        def is_server_item(obj: Any) -> bool:
            return hasattr(obj, "__holy__") or any(
                name.startswith("_holy")
                for name in getattr(obj, "__qualname__", "").split(".")
            )

        classes: Dict[str, type] = {}
        functions: Dict[str, Callable] = {}
        modules: Dict[str, ModuleType] = {}
        threads: Dict[str, threading.Thread] = {}
        variables: Dict[str, Any] = {}

        for name, obj in module_globals.items():
            if (
                name.startswith("_holy")
                or name.startswith("_handle")
                or is_server_item(obj)
            ):
                continue
            if inspect.isclass(obj) and obj.__module__ == current_module_name:
                cls: type = obj
                classes[name] = cls
            elif inspect.isfunction(obj) and obj.__module__ == current_module_name:
                func: Callable = obj
                functions[name] = func
            else:
                if isinstance(obj, ModuleType):
                    mod: ModuleType = obj
                    modules[name] = mod
                elif isinstance(obj, threading.Thread):
                    thread: threading.Thread = obj
                    threads[name] = thread
                else:
                    var: Any = obj
                    variables[name] = var
        return {
            "classes": classes,
            "functions": functions,
            "modules": modules,
            "threads": threads,
            "variables": variables,
        }

    def _holy_handle_dump_module_structure(self, payload: str) -> str:
        """Dumps the structure of the main module."""
        frame = self._get_main_module_frame()
        if not frame:
            return "Error: Could not find <module> frame."

        module_globals = frame.f_globals
        output = []

        for name, obj in module_globals.items():
            if name.startswith('__') or not hasattr(obj, '__module__'):
                continue
            
            try:
                if obj.__module__ == module_globals['__name__']:
                    if name.lower().startswith('_holy'):
                        continue
                    if inspect.isclass(obj):
                        bases = [b.__name__ for b in obj.__bases__]
                        output.append(f"class {name}({', '.join(bases)}):")
                        for method_name, _ in inspect.getmembers(obj, inspect.isfunction):
                            if not method_name.startswith('__'):
                                output.append(f"    def {method_name}(...):")
                        output.append("")
                    elif inspect.isfunction(obj):
                        output.append(f"def {name}(...):")
                        output.append("")
                    elif isinstance(obj, (int, str, float, list, dict)):
                        if len(str(obj)) < 50:
                            output.append(f"{name} = {repr(obj)}")
                        else:
                            output.append(f"{name} = ...")
            except Exception as e:
                output.append(f"# Error processing {name}: {e}")
            
        return "\n".join(output)

    def _holy_handle_dump(self, payload: str) -> str:
        """Dumps bytecode of a function or class to a .pyc file."""
        if not payload.startswith("_holy"):
            obj: Any = eval(payload)
            code_obj: types.CodeType = obj.__code__
            pyc_header: bytes = importlib._bootstrap_external._code_to_timestamp_pyc(
                code_obj
            )
            with open(f"{payload}.pyc", "wb") as f:
                f.write(pyc_header)
                f.write(marshal.dumps(code_obj))
            return f"Bytecode dumped to {payload}.pyc"
        return "Skipped holy-prefixed object"

    def _holy_handle_dis(self, payload: str) -> str:
        """Disassembles a function or method."""
        if not payload.startswith("_holy"):
            obj: Any = eval(payload)
            code_obj: Optional[types.CodeType] = (
                obj.__code__
                if inspect.isfunction(obj) or inspect.ismethod(obj)
                else None
            )
            if code_obj:
                buf: io.StringIO = io.StringIO()
                sys.stdout = buf
                dis(code_obj)
                sys.stdout = sys.__stdout__
                return buf.getvalue()
        return "Invalid object for disassembly"

    def _holy_handle_structure(self, payload: str) -> str:
        """Dumps the module's structure as a tree."""
        contents: Dict[str, Any] = self._holyload_module_contents()
        root: _HolyNode = _HolyNode("Module")

        for cls_name, cls in contents["classes"].items():
            class_node: _HolyNode = _HolyNode(f"{cls_name} (class)")
            for name, _ in inspect.getmembers(cls, inspect.isfunction):
                class_node.children.append(_HolyNode(f"{name} (class method)"))
            root.children.append(class_node)

        for func_name in contents["functions"]:
            root.children.append(_HolyNode(f"{func_name} (function)"))

        for mod_name in contents["modules"]:
            root.children.append(_HolyNode(f"{mod_name} (module)"))

        for thread_name in contents["threads"]:
            root.children.append(_HolyNode(f"{thread_name} (thread)"))

        for var_name in contents["variables"]:
            root.children.append(_HolyNode(f"{var_name} (variable)"))

        def render_tree(node: _HolyNode, prefix: str = "", is_last: bool = True) -> str:
            result = prefix + ("└── " if is_last else "├── ") + node.name + "\n"
            new_prefix = prefix + ("    " if is_last else "│   ")
            for i, child in enumerate(node.get_children()):
                result += render_tree(child, new_prefix, i == len(node.get_children()) - 1)
            return result

        return root.name + "\n" + "".join(
            render_tree(child, "", i == len(root.get_children()) - 1)
            for i, child in enumerate(root.get_children())
        )


    def _holy_handle_getvar(self, payload: str) -> str:
        """Gets the type and value of a variable."""
        contents: Dict[str, Any] = self._holyload_module_contents()
        var_value: Any = (
            contents["variables"].get(payload)
            or contents["modules"].get(payload)
            or contents["threads"].get(payload)
        )
        if var_value is not None:
            return f"{payload}:\n  Type: {type(var_value).__name__}\n  Value: {repr(var_value)}"
        return f"Variable '{payload}' not found"

    def _holy_handle_exec(self, payload: str) -> str:
        """Executes a Python code string in the current globals."""
        exec(payload, globals())
        return "Code injected successfully"

    def _holy_handle_objects_type(self, payload: str) -> str:
        """Finds objects of a given type."""
        contents: Dict[str, Any] = self._holyload_module_contents()
        target_type: Optional[type] = getattr(__builtins__, payload, None)
        if not target_type:
            return f"Error: Type '{payload}' is not a valid built-in type."
        output_lines: List[str] = [f"Variables of type {payload} in module:"]
        found: bool = False
        for container in ("variables", "modules", "threads"):
            for name, obj in contents[container].items():
                if isinstance(obj, target_type):
                    output_lines.append(f"{name}:")
                    output_lines.append(f"  Type: {type(obj).__name__}")
                    output_lines.append(f"  Value: {repr(obj)}")
                    found = True
        if not found:
            output_lines.append(f"No variables of type {payload} found.")
        return "\n".join(output_lines)

    def _holy_handle_searchattr(self, payload: str) -> str:
        """Dumps attributes of a class."""
        contents: Dict[str, Any] = self._holyload_module_contents()
        cls: Optional[type] = contents["classes"].get(payload)
        if not cls:
            return f"Class '{payload}' not found"
        try:
            instance: object = cls()
            class_buf = io.StringIO()
            pprint.pprint(cls.__dict__, stream=class_buf, indent=4)
            instance_buf = io.StringIO()
            pprint.pprint(instance.__dict__, stream=instance_buf, indent=4)
            return (
                f"Class '{payload}' attributes:\n{class_buf.getvalue()}\n\n"
                f"Instance attributes:\n{instance_buf.getvalue()}"
            )
        except Exception as e:
            return self._holyexception(e)

    def _holy_handle_search(self, payload: str) -> str:
        """Searches for a nested attribute."""
        try:
            parts: List[str] = payload.split(".")
            current: Any = globals().get(parts[0])
            if current is None:
                return f"'{parts[0]}' not found"
            for part in parts[1:]:
                if inspect.isclass(current):
                    current: Any = current()
                current = getattr(current, part)
            return repr(current)
        except Exception as e:
            return self._holyexception(e)

    def _holy_handle_capture(self, payload: str) -> str:
        """Captures the main module's bytecode to a .pyc file."""
        frame = self._get_main_module_frame()
        if not frame:
            return "No module frame found"
        try:
            with open(f"module.pyc", "wb") as f:
                f.write(importlib._bootstrap_external._code_to_timestamp_pyc(frame.f_code))
            return "ok"
        except Exception as e:
            return self._holyexception(e)

    def _holy_handle_frames_names(self, payload: str) -> str:
        """Lists all frame names in the call stack."""
        frames = self._get_main_thread_frames()
        if not frames:
            return "No frames found"
        
        fnames = []
        frame = frames[threading.main_thread().ident]
        c = 0
        while frame:
            fnames.append(f"[{c}] {frame.f_code.co_name}")
            c += 1
            frame = frame.f_back
        return "Stack frames:\n" + "\n".join(fnames)

    def _holy_handle_dump_all_frames(self, payload: str) -> str:
        """Dumps bytecode for all frames in the main thread's stack."""
        frames = self._get_main_thread_frames()
        if not frames:
            return "Main thread frame not found"
        
        frame = frames[threading.main_thread().ident]
        index = 0
        dumped_count = 0
        while frame:
            filename = f"{index}_{frame.f_code.co_name}.pyc"
            with open(filename, "wb") as f:
                f.write(importlib._bootstrap_external._code_to_timestamp_pyc(frame.f_code))
            dumped_count += 1
            index += 1
            frame = frame.f_back
        return f"Dumped {dumped_count} frames"

    def _holy_handle_frame_dump(self, payload: str) -> str:
        """Dumps the bytecode of a specific frame by index."""
        try:
            index = int(payload)
        except ValueError:
            return "Error: Frame index must be an integer"
        
        frames = self._get_main_thread_frames()
        if not frames:
            return "Error: Main thread frame not found"
        
        current_frame: Optional[types.FrameType] = frames[threading.main_thread().ident]
        current_index = 0
        while current_frame:
            if current_index == index:
                filename = f"{current_frame.f_code.co_name}.pyc"
                try:
                    with open(filename, "wb") as f:
                        f.write(importlib._bootstrap_external._code_to_timestamp_pyc(current_frame.f_code))
                    return f"Frame {index} dumped to {filename}"
                except Exception as e:
                    return f"Error writing file: {str(e)}"
            current_index += 1
            current_frame = current_frame.f_back
        return f"Error: Frame index {index} out of range (max index: {current_index-1})"

    def _holy_handle_frame_dis(self, payload: str) -> str:
        """Disassembles a specific frame by index."""
        try:
            index = int(payload)
        except ValueError:
            return "Error: Frame index must be an integer"

        frames = self._get_main_thread_frames()
        if not frames:
            return "Error: Main thread frame not found"

        current_frame: Optional[types.FrameType] = frames[threading.main_thread().ident]
        current_index = 0
        while current_frame:
            if current_index == index:
                buf: io.StringIO = io.StringIO()
                sys.stdout = buf
                dis(current_frame.f_code)
                sys.stdout = sys.__stdout__
                return buf.getvalue()

            current_index += 1
            current_frame = current_frame.f_back

        return f"Error: Frame index {index} out of range (max index: {current_index-1})"

    def _holy_handle_modules(self, payload: str) -> str:
        """Lists all loaded modules."""
        return "Loaded modules:\n" + "\n".join(sorted(sys.modules.keys()))

    def _holy_handle_backtrace(self, payload: str) -> str:
        """Generates a backtrace of the call stack."""
        frames: List[str] = []
        frame: Optional[types.FrameType] = sys._getframe()
        while frame:
            if "_holy" not in frame.f_code.co_name:
                frames.append(
                    f"{frame.f_code.co_name} ({frame.f_code.co_filename}:{frame.f_lineno})"
                )
            frame: Optional[FrameType] = frame.f_back
        return "Call stack:\n" + "\n".join(reversed(frames))

    def _holy_handle_threads(self, payload: str) -> str:
        """Lists all active threads."""
        thread_lines: List[str] = [
            f"[{t.ident}] {t.name} (daemon={t.daemon})"
            for t in threading.enumerate()
            if "_holy" not in t.name
        ]
        return "Active threads:\n" + "\n".join(thread_lines)

    def _holy_handle_tokens(self, payload: str) -> str:
        """Searches for tokens (e.g., Telegram API) in variables."""
        try:
            contents: Dict[str, Any] = self._holyload_module_contents()
            token_patterns: List[Dict[str, Any]] = [
                {
                    "name": "Telegram bot tokens",
                    "pattern": re.compile(r"^\d{8,10}:[A-Za-z0-9_-]{35}$"),
                },
                {
                    "name": "leak api tokens",
                    "pattern": re.compile(r"^\d{8,10}:[A-Za-z0-9_-]{8}$"),
                },
            ]
            results: List[str] = []
            for token_type in token_patterns:
                matches: List[str] = []
                for var_name, val in contents["variables"].items():
                    if isinstance(val, str) and token_type["pattern"].match(val):
                        matches.append(f"Variable {var_name}: {val}")
                for cls_name, cls in contents["classes"].items():
                    try:
                        instance: object = cls()
                        for attr in dir(instance):
                            if attr.startswith("__"):
                                continue
                            val: Any = getattr(instance, attr)
                            if isinstance(val, str) and token_type["pattern"].match(
                                val
                            ):
                                matches.append(f"Class {cls_name}.{attr}: {val}")
                    except:
                        continue
                if matches:
                    results.append(
                        f"Found {token_type['name']}:\n" + "\n".join(matches)
                    )
            return "\n\n".join(results) if results else "No tokens found of any type"
        except Exception as e:
            return self._holyexception(e)

    def _holy_handle_locals(self, payload: str) -> str:
        """Dumps local variables for each function frame."""
        try:
            frames = self._get_main_thread_frames()
            if not frames:
                return "no non-module frames found"
            
            output = io.StringIO()
            frame = frames[threading.main_thread().ident]
            c = 0
            while frame:
                if frame.f_code.co_name != "<module>":
                    c += 1
                    print(f"frame {c}:  {frame.f_code.co_name}", file=output)
                    pprint.pprint(frame.f_locals, stream=output)
                frame = frame.f_back
            return output.getvalue()
        except Exception as e:
            return self._holyexception(e)

    def _holy_handle_globals(self, payload: str) -> str:
        """Dumps global variables from the main module frame."""
        try:
            frame = self._get_main_module_frame()
            if not frame:
                return "No module frame found"

            output = io.StringIO()
            pprint.pprint(frame.f_globals, stream=output)
            return output.getvalue()
        except Exception as e:
            return self._holyexception(e)

    def _holy_handle_findvar(self, payload: str) -> str:
        """Searches for a variable or attribute by name."""
        try:
            target = payload.strip()
            results = []
            visited = set()

            def scan_obj(obj: Any, prefix: str = "") -> List[str]:
                if id(obj) in visited or isinstance(obj, (int, float, str, bytes, bool, type(None))):
                    return []
                visited.add(id(obj))
                matches = []
                if hasattr(obj, "__dict__"):
                    for attr, val in vars(obj).items():
                        if target in attr or (isinstance(val, str) and target in val):
                            matches.append(f"{prefix}.{attr} = {repr(val)}")
                        matches.extend(scan_obj(val, f"{prefix}.{attr}"))
                elif isinstance(obj, dict):
                    for k, v in obj.items():
                        if isinstance(k, str) and target in k:
                            matches.append(f"{prefix}[{repr(k)}] = {repr(v)}")
                        elif isinstance(v, str) and target in v:
                            matches.append(f"{prefix}[{repr(k)}] = {repr(v)}")
                        matches.extend(scan_obj(v, f"{prefix}[{repr(k)}]"))
                elif isinstance(obj, (list, tuple, set)):
                    for i, item in enumerate(obj):
                        matches.extend(scan_obj(item, f"{prefix}[{i}]"))
                return matches

            frames = self._get_main_thread_frames()
            if not frames:
                return f"Variable or attribute '{target}' not found"

            for tid, frame in frames.items():
                while frame:
                    for name, val in frame.f_locals.items():
                        if target in name and "_holy" not in frame.f_code.co_name:
                            results.append(
                                f"[TID {tid}] {frame.f_code.co_name} ({frame.f_code.co_filename}:{frame.f_lineno}): {name} = {repr(val)}"
                            )
                        matches = scan_obj(val, name)
                        for match in matches:
                            results.append(
                                f"[TID {tid}] {frame.f_code.co_name} ({frame.f_code.co_filename}:{frame.f_lineno}): {match}"
                            )
                    frame = frame.f_back

            return "\n".join(results) if results else f"Variable or attribute '{target}' not found"
        except Exception as e:
            return self._holyexception(e)

    def _holy_handle_client(self, conn: socket.socket) -> None:
        """Handles a single client connection."""
        with conn:
            try:
                data: str = conn.recv(1024).decode()
                cmd: str
                payload: str
                cmd, payload = data.split(":", 1) if ":" in data else (data, "")
                handler: Optional[Callable[[str], str]] = (
                    self._holy_command_handlers.get(cmd)
                )
                output: str
                if handler:
                    output = handler(payload)
                else:
                    output: str = f"Unknown command: {cmd}"
            except Exception as e:
                output: str = self._holyexception(e)
            conn.sendall(output.encode())

    def _holy_start_server(self) -> None:
        """Starts the server and listens for connections."""
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('127.1.4.88', 1161))
            s.listen()
            while True:
                conn, _ = s.accept()
                threading.Thread(target=self._holy_handle_client, args=(conn,), name="_holy_client_thread").start()

    def _holy_create_thread(self) -> None:
        """Creates and starts the server thread."""
        _holy_server_thread = threading.Thread(
            target=self._holy_start_server,
            name="_holy_server",
            daemon=True
        )
        _holy_server_thread.start()

if __name__ == '__main__':
    _holy_serv = _HolyServer()
    _holy_serv._holy_create_thread()

