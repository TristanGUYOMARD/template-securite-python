rule Flag_ESGI
{
    meta:
        description = "Contient un flag au format ESGI{...}"
    strings:
        $flag = /ESGI\{[^}]{1,100}\}/
    condition:
        $flag
}

rule Persistance_Registre
{
    meta:
        description = "Clé Run du registre Windows"
    strings:
        $run = "CurrentVersion\\Run" nocase
        $run16 = "CurrentVersion\\Run" nocase wide
    condition:
        any of them
}

rule Injection_Processus
{
    meta:
        description = "API d'injection de code"
    strings:
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
    condition:
        2 of them
}

rule Packer_UPX
{
    meta:
        description = "Sections UPX"
    strings:
        $a = "UPX0"
        $b = "UPX1"
    condition:
        all of them
}
