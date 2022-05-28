var strncmp = Module.findExportByName("msvcrt.dll", "strncmp");

Interceptor.attach(strncmp, {
    /*
    onEnter: function(args)
    {
		console.log("\nstrncmp at: " + strncmp);		
        console.log("  str1: " + Memory.readUtf8String(args[0]));
        console.log("  str2: " + Memory.readUtf8String(args[1]));
        console.log("   num: " + args[2]);
    }
    */

    onEnter: function(args)
    {
        args[1] = args[0]
		console.log("\nstrncmp at: " + strncmp);		
        console.log("  str1: " + Memory.readUtf8String(args[0]));
        console.log("  str2: " + Memory.readUtf8String(args[1]));
    }
});