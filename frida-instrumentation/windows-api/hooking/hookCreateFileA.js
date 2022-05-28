var hookCreateFileA = Module.getExportByName(null, "CreateFileA");

Interceptor.attach(hookCreateFileA, {
    onEnter: function(args)
    {
		console.log("\nhookCreateFileA at: " + hookCreateFileA);		
        console.log("  Name of the File or Device: " + Memory.readUtf16String(args[0]));
        //console.log("  Name of the File or Device: " + args[0].readAnsiString());
    }
});
