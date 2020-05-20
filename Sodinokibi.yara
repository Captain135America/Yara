rule Sodinokibi
{
     meta:
          author = "Dinesh" 
          date = "2020-03"
          description = "Designed to catch Sodinokibi Ransomware Variants"
        strings:
          $s1 = "\\BaseNamedObjects" wide
          $s2 = "kernel32.dll" wide ascii
          $s3 = "kernelbase.dll" wide
          $s4 = "CreateThread"
          $s5 = "CloseHandle"
          $s6 = "kexpand"
          $s7 = {E8 58 3F 00 00}
          $s8 = {FF 35 24 E0 01 10}
          $s9 = {40 3D 00 01 00 00}
     condition:
          all of ($s*)
}