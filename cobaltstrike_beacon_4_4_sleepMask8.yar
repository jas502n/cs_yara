rule cobaltstrike_beacon_4_2_sleepMask8
{
meta:
    author = "Elastic"
    description = "Identifies deobfuscation routine used in Cobalt Strike Beacon DLL version 4.2."
strings:
    $a_x64 = {89 C2 45 09 C2 74 1F 41 39 C0 76 E9 4C 8B 13 49 89 C3 41 83 E3 07 49 01 C2 46 8A 5C 1B 10 48 FF C0 45 30 1A}
    $a_x86 = {8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2}
condition:
     any of them
}