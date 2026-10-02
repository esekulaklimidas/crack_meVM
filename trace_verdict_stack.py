import subprocess
import time
import ctypes
from ctypes import wintypes
import frida

# Structs for WriteConsoleInput
class KEY_EVENT_RECORD(ctypes.Structure):
    class uChar(ctypes.Union):
        _fields_ = [("UnicodeChar", wintypes.WCHAR), ("AsciiChar", wintypes.CHAR)]
    _fields_ = [
        ("bKeyDown", wintypes.BOOL),
        ("wRepeatCount", wintypes.WORD),
        ("wVirtualKeyCode", wintypes.WORD),
        ("wVirtualScanCode", wintypes.WORD),
        ("uChar", uChar),
        ("dwControlKeyState", wintypes.DWORD)
    ]

class INPUT_RECORD(ctypes.Structure):
    class Event(ctypes.Union):
        _fields_ = [("KeyEvent", KEY_EVENT_RECORD)]
    _fields_ = [
        ("EventType", wintypes.WORD),
        ("Event", Event)
    ]

def send_key(hConIn, char):
    rec_down = INPUT_RECORD()
    rec_down.EventType = 1
    rec_down.Event.KeyEvent.bKeyDown = True
    rec_down.Event.KeyEvent.wRepeatCount = 1
    rec_down.Event.KeyEvent.wVirtualKeyCode = ord(char) if ord(char) < 256 else 0
    rec_down.Event.KeyEvent.uChar.UnicodeChar = char
    rec_down.Event.KeyEvent.dwControlKeyState = 0

    rec_up = INPUT_RECORD()
    rec_up.EventType = 1
    rec_up.Event.KeyEvent.bKeyDown = False
    rec_up.Event.KeyEvent.wRepeatCount = 1
    rec_up.Event.KeyEvent.wVirtualKeyCode = ord(char) if ord(char) < 256 else 0
    rec_up.Event.KeyEvent.uChar.UnicodeChar = char
    rec_up.Event.KeyEvent.dwControlKeyState = 0

    written = wintypes.DWORD()
    records = (INPUT_RECORD * 2)(rec_down, rec_up)
    ctypes.windll.kernel32.WriteConsoleInputW(hConIn, records, 2, ctypes.byref(written))

kernel32 = ctypes.windll.kernel32
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
OPEN_EXISTING = 3

hConIn = kernel32.CreateFileW("CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None)

p = subprocess.Popen([r"C:\Users\arda\Desktop\CRAKME\XD\arda\crackme_NoVM.exe"])
session = frida.attach(p.pid)

js = r"""
var base = Process.enumerateModules()[0].base;

Process.setExceptionHandler(function(details) {
    return false;
});

function hookWrite(name, fn) {
    if (!fn) return;
    Interceptor.attach(fn, {
        onEnter: function(args) {
            var buf = args[1];
            var len = args[2].toInt32();
            var strA = '', strW = '';
            try { strA = buf.readUtf8String(len); } catch(e){}
            try { strW = buf.readUtf16String(len); } catch(e){}
            
            var s = strA || strW || '';
            if (s.includes('Incorrect') || s.includes('Correct') || s.includes('password') || s.includes('check') || s.includes('*')) {
                var bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(addr => {
                        var mod = Process.findModuleByAddress(addr);
                        if (mod) {
                            return mod.name + '!' + addr.sub(mod.base).toString(16);
                        }
                        return addr.toString();
                    }).join(' <- ');
                send({type: 'console_write', api: name, buf: buf.toString(), text: s, backtrace: bt});
            }
        }
    });
}

hookWrite('WriteConsoleW', Module.findExportByName('kernelbase.dll', 'WriteConsoleW'));
hookWrite('WriteConsoleA', Module.findExportByName('kernelbase.dll', 'WriteConsoleA'));
hookWrite('WriteFile', Module.findExportByName('kernelbase.dll', 'WriteFile'));
"""

def on_message(msg, data):
    print("[EVENT]", msg.get('payload'), flush=True)

script = session.create_script(js)
script.on('message', on_message)
script.load()

print("[*] Waiting 1.5 seconds for prompt...")
time.sleep(1.5)

test_password = "AAAAAAAAAA\r"
print(f"[*] Injecting keystrokes: {test_password!r}")
for ch in test_password:
    send_key(hConIn, ch)
    time.sleep(0.05)

p.wait(timeout=10)
try: session.detach()
except: pass
