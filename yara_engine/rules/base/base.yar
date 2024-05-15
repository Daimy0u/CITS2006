rule isExecutable {
    strings:
        $exe_signature = { 4D 5A }
        $elf_magic = { 7f 45 4c 46 }
    condition:
        $exe_signature at 0 or
        $elf_magic at 0
}

rule isHidden {
    strings:
        $hidden_attribute = "H" wide ascii
    condition:
        $hidden_attribute at 0
}

rule isScript {
    strings:
        $script_signature = { 23 21 }
        $shell_script = "#!/bin/sh"
        $bash_function = "(){"
        $reverse_shell = "bash -i >& /dev/tcp/"
        $base64_data = /[A-Za-z0-9+\/]{50,}={0,2}/
     condition:
        $script_signature at 0 or
        ($shell_script or $bash_function) and
        ($reverse_shell or $base64_data)
}

rule isMaliciousScript {
    strings:
        $sa1 = "curl http" base64
		$sa2 = "wget http" base64
		$sb1 = "chmod 777 " base64
		$sb2 = "/tmp/" base64
    condition:
        1 of ($sa*) and 1 of ($sb*)
}

rule isUrl {
    strings:
        $url = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/ nocase
    condition:
        $url
}

rule isAccessingNetwork {
    strings:
        $socket = "socket" wide
        $connect = "connect" wide
        $send = "send" wide
        $recv = "recv" wide
        $getaddrinfo = "getaddrinfo" wide
        $gethostbyname = "gethostbyname" wide

    condition:
        any of ($socket, $connect, $send, $recv, $getaddrinfo, $gethostbyname)
}