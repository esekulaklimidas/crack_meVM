import subprocess
import time
import ctypes
from ctypes import wintypes
import frida
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

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
    vk = ord(char) if char != '\r' else 0x0D
    for down in [True, False]:
        rec = INPUT_RECORD()
        rec.EventType = 1
        rec.Event.KeyEvent.bKeyDown = down
        rec.Event.KeyEvent.wRepeatCount = 1
        rec.Event.KeyEvent.wVirtualKeyCode = vk
        rec.Event.KeyEvent.uChar.UnicodeChar = char
        rec.Event.KeyEvent.dwControlKeyState = 0
        written = wintypes.DWORD()
        ctypes.windll.kernel32.WriteConsoleInputW(hConIn, ctypes.byref(rec), 1, ctypes.byref(written))

kernel32 = ctypes.windll.kernel32
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
OPEN_EXISTING = 3

hConIn = kernel32.CreateFileW("CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None)
kernel32.FlushConsoleInputBuffer(hConIn)

p = subprocess.Popen([r"C:\Users\arda\Desktop\CRAKME\XD\arda\crackme_NoVM.exe"])
session = frida.attach(p.pid)

js = r"""
var base = Process.enumerateModules()[0].base;
Process.setExceptionHandler(function(details) { return false; });

var checking = false;

var vfprintf_addr = base.add(0x12D278);
Interceptor.attach(vfprintf_addr, {
    onEnter: function(args) {
        var fmt = '';
        try { fmt = args[2].readUtf8String(); } catch(e){}
        if (fmt.includes('You have 10 seconds')) {
            send({type: 'READY'});
        } else if (fmt.includes('Let me check')) {
            checking = true;
            send({type: 'CHECKING'});
        }
    }
});

var veh_count = 0;
var veh_addr = base.add(0x85BA0);

Interceptor.attach(veh_addr, {
    onEnter: function(args) {
        if (!checking) return;
        veh_count++;
        
        try {
            var pExpInfo = args[0].not();
            var pCtx = pExpInfo.add(8).readPointer();
            var rip = pCtx.add(0xF8).readPointer();
            var rip_rva_num = rip.sub(base).toInt32();
            
            // Skip the countdown loop if hit
            if (rip_rva_num === 0x79c2a || rip_rva_num === 0x79c6b || rip_rva_num === 0x79c75 || rip_rva_num === 0x79c7d) {
                return;
            }
            
            var rax = pCtx.add(0x78).readPointer();
            var rbx = pCtx.add(0x90).readPointer();
            var rcx = pCtx.add(0x80).readPointer();
            var rdx = pCtx.add(0x88).readPointer();
            var rsi = pCtx.add(0xA8).readPointer();
            var rdi = pCtx.add(0xB0).readPointer();
            var r8  = pCtx.add(0xB8).readPointer();
            var r9  = pCtx.add(0xC0).readPointer();
            var r10 = pCtx.add(0xC8).readPointer();
            var r15 = pCtx.add(0xF0).readPointer();
            
            send({
                type: 'STEP_5CHAR',
                n: veh_count,
                rip: '0x' + rip_rva_num.toString(16),
                rax: rax.toString(),
                rbx: rbx.toString(),
                rcx: rcx.toString(),
                rdx: rdx.toString(),
                rsi: rsi.toString(),
                rdi: rdi.toString(),
                r8:  r8.toString(),
                r9:  r9.toString(),
                r10: r10.toString()
            });
        } catch(e) {
            send({type: 'VEH_ERR', err: e.message});
        }
    }
});
"""

keys_injected = False
test_password = "AAAAA\r"

def on_message(msg, data):
    global keys_injected
    if msg['type'] == 'send':
        p_load = msg['payload']
        t = p_load.get('type')
        if t == 'READY' and not keys_injected:
            keys_injected = True
            print(f"[*] Prompt detected! Feeding 5-char password {test_password!r}...", flush=True)
            kernel32.FlushConsoleInputBuffer(hConIn)
            time.sleep(0.1)
            for ch in test_password:
                send_key(hConIn, ch)
                time.sleep(0.03)
            print("[*] Fed 5 keys!", flush=True)
        elif t == 'STEP_5CHAR':
            print(f"  [STEP #{p_load['n']:03d}] RIP={p_load['rip']:10s} rax={p_load['rax']} rcx={p_load['rcx']} rdx={p_load['rdx']} rbx={p_load['rbx']}", flush=True)
        elif t == 'VEH_ERR':
            print(f"  [VEH_ERR] {p_load['err']}", flush=True)
        else:
            print(f"  [{t}] {p_load}", flush=True)
    elif msg['type'] == 'error':
        print(f"  [ERROR] {msg.get('description','')[:150]}", flush=True)

script = session.create_script(js)
script.on('message', on_message)
script.load()

p.wait(timeout=15)
try: session.detach()
except: pass
print(f"[*] Process exited with code {p.returncode}")
