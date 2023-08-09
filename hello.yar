/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-08
   Identifier: Hello
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule HelloWorld {
   meta:
      description = "Hello - file HelloWorld.txt"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-08"
      hash1 = "07f2bdef34ed16e3a1ba0dbb7e47b8fd981ce0ccb3e1bfe564d82c423cba7e47"
   strings:
      $s1 = "Hello World !" fullword ascii
   condition:
      uint16(0) == 0x6548 and filesize < 1KB and
      all of them
}

