rule isExecutable {
    strings:
        $s = { 7f 45 4c 46 }
    condition:
        $s at 0
}

rule isHiddenUnencrypted {
    strings:
        $s= "E" wide ascii
    condition:
        $s at 0
}

rule isScript {
    strings:
        $signature = { 23 21 }
        $s1 = "#!/bin/sh"
        $s2 = "#!/bin/bash"
        $s3 = "#!/bin/zsh"
        $function = "(){"
        $reverse_shell = "bash -i >& /dev/tcp/"
        $base64 = /[A-Za-z0-9+\/]{50,}={0,2}/
     condition:
        $signature at 0 or
        ((any of ($s*)) or $function) or
        ($reverse_shell or $base64)
}

rule isMaliciousScript {
    strings:
        $a1 = "curl http" base64
		$a2 = "wget http" base64
		$b1 = "chmod 777 " base64
		$b2 = "/tmp/" base64
    condition:
        1 of ($a*) and 1 of ($b*)
}

rule isUrl {
    strings:
        $url = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/ nocase
    condition:
        $url
}

rule isIp {
    strings:
        $ip = /([^:]+:[^@]+@)?(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?/
    condition:
        $ip
}

rule isDDE {
    strings:
        $s1 = /(^|\n|,)=\s*cmd\|/ nocase
    condition:
        $s1
}

rule isMaliciousZip {
    strings:
        $b1 = { 50 4B 03 04 }
        $b2 = ".zip"
        $s1 = { 50 4B 01 02 [42] 2E 2E 2F}
    condition:
        ($b1 and $b2) or $s1
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