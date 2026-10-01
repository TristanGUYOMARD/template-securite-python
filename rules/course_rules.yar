rule Suspicious_Downloader
{
    meta:
        description = "Télécharge un fichier via urlmon"
    strings:
        $a = "urlmon.dll" nocase
        $b = "URLDownloadToFile" nocase
        $c = { 68 ?? ?? ?? ?? FF D0 }
    condition:
        2 of them
}
