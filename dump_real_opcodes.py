import subprocess
import time
import frida
import json

p = subprocess.Popen([r"C:\Users\arda\Desktop\CRAKME\XD\arda\crackme_NoVM.exe"])
session = frida.attach(p.pid)

js = r"""
var base = Process.enumerateModules()[0].base;

var vfprintf_addr = base.add(0x12D278);
Interceptor.attach(vfprintf_addr, {
    onEnter: function(args) {
        var fmt = '';
        try { fmt = args[2].readUtf8String(); } catch(e){}
        if (fmt.includes('You have 10 seconds')) {
            dumpOriginalOpcodes();
        }
    }
});

function dumpOriginalOpcodes() {
    try {
        var ptr_162ae0 = base.add(0x162AE0).readPointer();
        var myhead = ptr_162ae0.readPointer();
        var root = myhead.add(8).readPointer();
        
        var instructions = [];
        var visited = new Set();
        
        function walk(node) {
            var ptrStr = node.toString();
            if (visited.has(ptrStr)) return;
            visited.add(ptrStr);
            
            if (node.equals(myhead)) return;
            if (node.add(25).readU8() !== 0) return;
            
            walk(node.readPointer());
            
            var key_rip = node.add(32).readPointer();
            var val_ptr = node.add(40).readPointer();
            var rva = key_rip.sub(base).toInt32();
            
            if (rva >= 0x7A000 && rva <= 0x7A500) {
                // val_ptr + 16 has pointer to raw bytes, or val_ptr + 40
                var pBytes = val_ptr.add(16).readPointer();
                var pBytesEnd = val_ptr.add(24).readPointer();
                var len1 = pBytesEnd.sub(pBytes).toInt32();
                
                var pBytes2 = val_ptr.add(40).readPointer();
                var pBytesEnd2 = val_ptr.add(48).readPointer();
                var len2 = pBytesEnd2.sub(pBytes2).toInt32();
                
                var dump1 = [];
                var dump2 = [];
                if (len1 > 0 && len1 < 100) {
                    for (var i = 0; i < len1; i++) dump1.push(pBytes.add(i).readU8());
                }
                if (len2 > 0 && len2 < 100) {
                    for (var j = 0; j < len2; j++) dump2.push(pBytes2.add(j).readU8());
                }
                
                instructions.push({
                    rip: '0x' + rva.toString(16),
                    len1: len1,
                    bytes1: dump1.map(b => ('0' + b.toString(16)).slice(-2)).join(' '),
                    len2: len2,
                    bytes2: dump2.map(b => ('0' + b.toString(16)).slice(-2)).join(' ')
                });
            }
            
            walk(node.add(16).readPointer());
        }
        
        walk(root);
        send({type: 'OPCODES', list: instructions});
    } catch(e) {
        send({type: 'ERR', msg: e.message});
    }
}
"""

def on_msg(m, d):
    if m['type'] == 'send':
        p_load = m['payload']
        if p_load.get('type') == 'OPCODES':
            print(f"[+] Total original opcode patches: {len(p_load['list'])}")
            with open('real_validator_opcodes.json', 'w') as f:
                json.dump(p_load['list'], f, indent=2)
            print("[+] Saved to real_validator_opcodes.json")
        else:
            print(p_load)
    else:
        print("[MSG]", m)

s = session.create_script(js)
s.on('message', on_msg)
s.load()
time.sleep(3)
p.kill()
