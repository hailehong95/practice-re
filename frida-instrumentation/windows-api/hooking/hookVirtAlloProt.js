var hookVirtualAlloc = Module.getExportByName(null, "VirtualAlloc");
var hookVirtualProtect = Module.getExportByName(null, "VirtualProtect");
//var hookVirtualAlloc = Module.findExportByName("KERNEL32.dll", "VirtualAlloc");
//var hookVirtualProtect = Module.findExportByName("KERNEL32.dll", "VirtualProtect");


Interceptor.attach(hookVirtualAlloc, {
    onEnter: function (args) {
        console.log("[*] VirtualAlloc Hooked!");
        console.log("  Size (bytes): " + args[1].toInt32());
        console.log("  Protect: " + args[3]);
    },

    onLeave: function (retval) {
        console.log("  VirtualAlloc Returned: " + retval);
    }
});


Interceptor.attach(hookVirtualProtect, {
    onEnter: function (args) {
        console.log("[*] VirtualProtect Hooked!");
        console.log("  Address: " + args[0]);
        console.log("  Size: " + args[1].toInt32());
        console.log("  NewProtect: " + args[2]);
        console.log("  Hexdump:\n" + hexdump(args[0]));
        if (args[0].readAnsiString(2) == "MZ") {
            console.log("  Found an MZ!");
            var exeContent = args[0].readByteArray(args[1].toInt32());
            var filename = args[0] + "_dump.bin";
            var file = new File(filename, "wb");
            file.write(exeContent);
            file.flush();
            file.close();
            console.log("  Success dump file: " + filename);
        }
    }
});
