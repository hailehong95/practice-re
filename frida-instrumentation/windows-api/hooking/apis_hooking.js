var messageBox = Module.getExportByName(null, "MessageBoxW");
var writeFile = Module.getExportByName(null, "WriteFile");
var buff = Memory.allocUtf16String("F*ck y0u!!!!!!!")

Interceptor.attach(messageBox, {
    onEnter: function(args)
    {
		args[1] = buff
		args[2] = buff
		console.log("\nMessageBoxW at: " + messageBox);		
        console.log("  lpText: " + Memory.readUtf16String(args[1]));
        console.log("  lpCaption: " + Memory.readUtf16String(args[2]));
    }
});

Interceptor.attach(writeFile, {
    onEnter: function(args)
    {
		args[1] = buff
		console.log("\nWriteFile at: " + writeFile);
        console.log("  Buffer dump:\n" + hexdump(args[1]));
        console.log("  Buffer via utf16String: " + Memory.readUtf16String(args[1]));
    }
});