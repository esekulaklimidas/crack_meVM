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
            dumpAll();
        }
    }
});

function dumpAll() {
    try {
        var ptr_162ae0 = base.add(0x162AE0).readPointer();
        var myhead = ptr_162ae0.readPointer();
        var root = myhead.add(8).readPointer();
        
        var nodes = [];
        var visited = new Set();
        
        function walk(node) {
            var ptrStr = node.toString();
            if (visited.has(ptrStr)) return;
            visited.add(ptrStr);
            
            if (node.equals(myhead)) return;
            var is_nil = node.add(25).readU8();
            if (is_nil !== 0) return;
            
            var left = node.readPointer();
            var right = node.add(16).readPointer();
            
            walk(left);
            
            var key_rip = node.add(32).readPointer();
            var val_ptr = node.add(40).readPointer();
            
            // Read 32 bytes from node+32
            var dump = [];
            for (var i = 0; i < 64; i++) {
                try { dump.push(node.add(32 + i).readU8()); } catch(e){ break; }
            }
            
            // Also let's check what val_ptr points to if it's a valid pointer
            var val_dump = [];
            try {
                for (var j = 0; j < 64; j++) {
                    val_dump.push(val_ptr.add(j).readU8());
                }
            } catch(e){}
            
            nodes.push({
                rip_rva: '0x' + key_rip.sub(base).toString(16),
                rip_raw: key_rip.toString(),
                hex: dump.map(b => ('0' + b.toString(16)).slice(-2)).join(' '),
                val_ptr: val_ptr.toString(),
                val_hex: val_dump.map(b => ('0' + b.toString(16)).slice(-2)).join(' ')
            });
            
            walk(right);
        }
        
        walk(root);
        send({type: 'SUCCESS', count: nodes.length, nodes: nodes});
    } catch(e) {
        send({type: 'ERR', msg: e.message});
    }
}
"""

def on_msg(m, d):
    if m['type'] == 'send':
        p_load = m['payload']
        t = p_load.get('type')
        if t == 'SUCCESS':
            print(f"[+] Total VM Nodes in Tree: {p_load['count']}")
            with open('vm_tree_dump.json', 'w') as f:
                json.dump(p_load['nodes'], f, indent=2)
            print("[+] Saved to vm_tree_dump.json")
            # print some interesting ones around 0x7A000 - 0x7A500
            for n in p_load['nodes']:
                rva = int(n['rip_rva'], 16)
                if 0x7A080 <= rva <= 0x7A450:
                    print(f"  RIP={n['rip_rva']:10s} data={n['hex'][:40]} | val={n['val_hex'][:40]}")
        elif t == 'ERR':
            print(f"[-] Error: {p_load['msg']}")
    else:
        print("[MSG]", m)

s = session.create_script(js)
s.on('message', on_msg)
s.load()
time.sleep(3)
p.kill()
