# HolyDebug - Advanced Python Debugger

<img width="1536" height="672" alt="Gemini_Generated_Image_1uuq6t1uuq6t1uuq" src="https://github.com/user-attachments/assets/e78e4d92-9537-4f27-a6bf-41b654df3f8c" />


HolyDebug is a powerful runtime debugger and introspection tool for Python applications that allows you to attach to running Python processes and perform advanced debugging operations without stopping the execution.

## Features

- 🔍 **Process Injection**: Attach to running Python processes
- 📡 **Remote Debugging**: Connect via socket interface (127.1.4.88:1161)
- 🏗️ **Code Introspection**: Examine modules, classes, and functions
- 🔧 **Bytecode Analysis**: Dump and disassemble Python bytecode
- 🕵️ **Token Detection**: Automatically find API tokens and secrets
- 📊 **Memory Analysis**: Inspect frames, stacks, and variables
- 🌐 **Multi-language Support**: English and Russian interfaces
- 🧵 **Thread Management**: Analyze and monitor thread activity

## Prerequisites

- Python 3.6+
- GCC compiler
- Linux environment
- `psutil` Python package
- `prompt_toolkit` Python package
- `pyinjector` Python package

## Installation

1. Clone the repository:
```bash
git clone https://github.com/wowgirl88/holydbg.git
cd holydebug
```

2. Install Python dependencies:
```bash
pip install psutil prompt_toolkit pyinjector
```

3. Compile the injector module:
```bash
make
```

## Usage

1. Start the debugger:
```bash
python main.py
```

2. The tool will scan for running Python processes and display them in a table:
```
+------+----------+-----------+
| PID  | NAME     | VERSION   |
+------+----------+-----------+
| 1234 | python3  | libpython3.8.so |
| 5678 | myapp    | libpython3.8.so |
+------+----------+-----------+
```

3. Enter the PID of the process you want to debug

4. Use the interactive prompt with various commands:

## Available Commands

- `objects` - Display module structure
- `dump <object>` - Dump object bytecode
- `dis <function>` - Disassemble function
- `get <variable>` - Get variable value
- `search <Class.attr>` - Inspect class attributes
- `rrun <file.py>` - Execute Python code
- `modules` - Show loaded modules
- `stack` - Show call stack
- `tokens` - Search for API tokens
- `threads` - List active threads
- `inject <soname>` - Inject shared library
- `help` - Show help information
- `q` - Quit debugger

## Project Structure

```
holydebug/
├── inject_server.c    # C code for process injection
├── inject_server.so   # Compiled shared library
├── main.py           # Main debugger interface
├── server.py         # Debug server implementation
└── Makefile          # Build configuration
```

## Building from Source

The project includes a Makefile for easy compilation:

```bash
# Compile the injector module
make

# Clean build artifacts
make clean
```

## Security Notes

- This tool performs process injection which may be flagged by security software
- Use only on processes you own or have permission to debug
- The debug server binds to localhost (127.1.4.88) on port 1161

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

- GitHub: [wowgirl88](https://github.com/wowgirl88)
- Telegram: [@onehourlater](https://t.me/onehourlater)

## Disclaimer

This tool is intended for educational purposes and legitimate debugging use only. The authors are not responsible for any misuse of this software.
