var unlinkPtr = Module.findExportByName(null, 'unlink');

Interceptor.replace(unlinkPtr, new NativeCallback(function (a) {
    console.log("[+] Unlink : " + Memory.readUtf8String(ptr(a)))
}, 'int', ['pointer']));