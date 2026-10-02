"""
Dynamic crackme solver via Frida instrumentation.
Strategy:
  1. Spawn crackme_NoVM.exe
  2. Hook _getch_nolock to feed characters
  3. Hook _kbhit_nolock to always return 1
  4. Hook the XChaCha20-Poly1305 decryption to capture:
     - The key derived from password (32 bytes)
     - The return value (0 = success, non-zero = fail)
  5. Hook the XXH3 function to see the hash input and output
  6. Hook the SHA-256 function to see intermediate hashes
  7. Monitor console output for "Correct"/"Incorrect"
  
  Since the password is 10 chars → XXH3_64bits → SHA256 → SHA256 → 32-byte key → XChaCha20-Poly1305,
  we need to brute-force or find the correct 10 characters.
  
  First, let's trace what happens with "AAAAAAAAAA" to understand the full flow.
"""

import sys
import os
import time
import struct

sys.stdout.reconfigure(line_buffering=True)

import frida

TEST_PASSWORD = "AAAAAAAAAA"  # 10 chars

js = r"""
var base = Process.enumerateModules()[0].base;
var baseInt = base.toInt32 ? parseInt(base) : base;

// Pass all SEH exceptions (the VM is exception-driven)
Process.setExceptionHandler(function(details) {
    return false;
});

// ==================== INPUT INJECTION ====================
var kbhit_nolock = base.add(0x12D8A4);
var getch_nolock = base.add(0x12D644);
var testPass = "AAAAAAAAAA\r";
var passIdx = 0;

Interceptor.attach(kbhit_nolock, {
    onLeave: function(retval) {
        if (passIdx < testPass.length)
            retval.replace(ptr(1));
    }
});

Interceptor.attach(getch_nolock, {
    onLeave: function(retval) {
        if (passIdx < testPass.length) {
            var c = testPass.charCodeAt(passIdx);
            passIdx++;
            retval.replace(ptr(c));
            send({type: 'input', char: testPass[passIdx-1], idx: passIdx, code: c});
        }
    }
});

// ==================== XXH3 HOOK ====================
// sub_14007F330 = XXH3_64bits
var xxh3_addr = base.add(0x7F330);
Interceptor.attach(xxh3_addr, {
    onEnter: function(args) {
        this.input_ptr = args[0];
        this.input_len = args[1].toInt32();
        var inputBytes = [];
        try {
            for (var i = 0; i < this.input_len && i < 32; i++) {
                inputBytes.push(this.input_ptr.add(i).readU8());
            }
        } catch(e) {}
        send({type: 'xxh3_enter', len: this.input_len, input_hex: inputBytes.map(function(b){return ('0'+b.toString(16)).slice(-2)}).join('')});
    },
    onLeave: function(retval) {
        // XXH3 returns uint64 in rax
        send({type: 'xxh3_leave', result: retval.toString()});
    }
});

// ==================== SHA-256 HOOK ====================
// sub_140098470 = SHA-256 full hash (takes input, len, output_buf)
var sha256_addr = base.add(0x98470);
Interceptor.attach(sha256_addr, {
    onEnter: function(args) {
        this.input_ptr = args[0];
        this.input_len = args[1].toInt32();
        this.output_ptr = args[2];
        var inputBytes = [];
        try {
            for (var i = 0; i < Math.min(this.input_len, 64); i++) {
                inputBytes.push(this.input_ptr.add(i).readU8());
            }
        } catch(e) {}
        send({type: 'sha256_enter', len: this.input_len, input_hex: inputBytes.map(function(b){return ('0'+b.toString(16)).slice(-2)}).join('')});
    },
    onLeave: function(retval) {
        // Read 32 bytes of output
        var outputBytes = [];
        try {
            for (var i = 0; i < 32; i++) {
                outputBytes.push(this.output_ptr.add(i).readU8());
            }
        } catch(e) {}
        send({type: 'sha256_leave', output_hex: outputBytes.map(function(b){return ('0'+b.toString(16)).slice(-2)}).join('')});
    }
});

// ==================== XChaCha20-Poly1305 HOOK ====================
// sub_1400A0B30 = outer XChaCha decryption wrapper
var xchacha_outer = base.add(0xA0B30);
Interceptor.attach(xchacha_outer, {
    onEnter: function(args) {
        // a1 = ciphertext vector (ptr, end, capacity)
        // a2 = output vector
        // a3 = key vector (ptr, end, capacity)
        var a1 = args[0];
        var c_start = a1.readPointer();
        var c_end = a1.add(8).readPointer();
        var c_len = c_end.sub(c_start).toInt32();
        
        var a3 = args[2];
        var k_start = a3.readPointer();
        var k_end = a3.add(8).readPointer();
        var k_len = k_end.sub(k_start).toInt32();
        
        // Read the key
        var keyBytes = [];
        try {
            for (var i = 0; i < Math.min(k_len, 64); i++) {
                keyBytes.push(k_start.add(i).readU8());
            }
        } catch(e) {}
        
        send({type: 'xchacha_enter', c_len: c_len, k_len: k_len, 
              key_hex: keyBytes.map(function(b){return ('0'+b.toString(16)).slice(-2)}).join('')});
    },
    onLeave: function(retval) {
        send({type: 'xchacha_leave', ret: retval.toInt32()});
    }
});

// ==================== CONSOLE OUTPUT HOOK ====================
var writeConsoleW = Module.findExportByName('kernelbase.dll', 'WriteConsoleW');
if (writeConsoleW) {
    Interceptor.attach(writeConsoleW, {
        onEnter: function(args) {
            var txt = '';
            try { txt = args[1].readUtf16String(args[2].toInt32()); } catch(e){}
            if (txt.length > 0)
                send({type: 'console', text: txt});
        }
    });
}

var writeFile = Module.findExportByName('kernelbase.dll', 'WriteFile');
if (writeFile) {
    Interceptor.attach(writeFile, {
        onEnter: function(args) {
            var len = args[2].toInt32();
            if (len > 0 && len < 4096) {
                var txt = '';
                try { txt = args[1].readUtf8String(len); } catch(e){}
                if (txt.length > 0)
                    send({type: 'file_write', text: txt});
            }
        }
    });
}

send({type: 'hooks_ready'});
"""

events = []

def on_message(msg, data):
    if msg['type'] == 'send':
        p = msg['payload']
        events.append(p)
        t = p.get('type', '')
        if t == 'input':
            print(f"  [INPUT] char='{p['char']}' idx={p['idx']}", flush=True)
        elif t == 'xxh3_enter':
            print(f"  [XXH3] input len={p['len']} hex={p['input_hex']}", flush=True)
        elif t == 'xxh3_leave':
            print(f"  [XXH3] result={p['result']}", flush=True)
        elif t == 'sha256_enter':
            print(f"  [SHA256] input len={p['len']} hex={p['input_hex']}", flush=True)
        elif t == 'sha256_leave':
            print(f"  [SHA256] output={p['output_hex']}", flush=True)
        elif t == 'xchacha_enter':
            print(f"  [XCHACHA] ciphertext_len={p['c_len']} key_len={p['k_len']} key={p.get('key_hex','')}", flush=True)
        elif t == 'xchacha_leave':
            print(f"  [XCHACHA] ret={p['ret']} ({'SUCCESS' if p['ret']==0 else 'FAIL'})", flush=True)
        elif t in ('console', 'file_write'):
            txt = p.get('text', '')
            if txt.strip():
                print(f"  [OUTPUT] {txt.strip()}", flush=True)
        elif t == 'hooks_ready':
            print("[*] All hooks installed!", flush=True)
        else:
            print(f"  [{t}] {p}", flush=True)
    elif msg['type'] == 'error':
        print(f"  [ERROR] {msg.get('description','')[:120]}", flush=True)

device = frida.get_local_device()
pid = device.spawn([r'C:\Users\arda\Desktop\CRAKME\XD\arda\crackme_NoVM.exe'])
session = device.attach(pid)
script = session.create_script(js)
script.on('message', on_message)
script.load()
device.resume(pid)

print(f"[*] Spawned PID {pid}, feeding password: {TEST_PASSWORD!r}", flush=True)

# Wait for it to finish
for i in range(15):
    time.sleep(1)
    print(f"[*] {i+1}s elapsed", flush=True)

print("\n[*] === EVENT SUMMARY ===", flush=True)
for ev in events:
    t = ev.get('type', '')
    if t in ('xxh3_enter', 'xxh3_leave', 'sha256_enter', 'sha256_leave', 'xchacha_enter', 'xchacha_leave', 'console', 'file_write'):
        print(f"  {ev}", flush=True)

try:
    session.detach()
except:
    pass
os._exit(0)
