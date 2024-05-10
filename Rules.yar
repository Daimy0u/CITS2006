rule isExecutable {
    strings:
        $exe_signature = { 4D 5A }
    condition:
        $exe_signature at 0
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
    condition:
        $script_signature at 0
}

rule isSketchyTLD {
    strings:
        $tld_signature = /(?:http|https):\/\/[^\/]+\.([a-z]{3,})\/.*/ nocase
    condition:
        $tld_signature
}