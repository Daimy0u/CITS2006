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

rule isSketchyTLD {
    strings:
        $tld_signature = /(?:http|https):\/\/[^\/]+\.([a-z]{3,})\/.*/ nocase
    condition:
        $tld_signature
}
