/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-07
   Identifier: Art
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule The_Art_of_Memory_Forensics___Detecting_Malware_and_Threats_in_Windows__Linux__and_Mac_Memory__2014_ {
   meta:
      description = "Art - file The Art of Memory Forensics - Detecting Malware and Threats in Windows, Linux, and Mac Memory (2014).pdf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-07"
      hash1 = "a87355591cb5c314008dc2a0ad80b478e6a004555680795b2ba72b501ebff20f"
   strings:
      $s1 = "DDDDDDDDDDP" fullword ascii /* reversed goodware string 'PDDDDDDDDDD' */
      $s2 = "DDDDDDDDDDE" ascii /* reversed goodware string 'EDDDDDDDDDD' */
      $s3 = "DDDDDDDT" fullword ascii /* reversed goodware string 'TDDDDDDD' */
      $s4 = "QQQYYY" fullword ascii /* reversed goodware string 'YYYQQQ' */
      $s5 = "WWWWVV" fullword ascii /* reversed goodware string 'VVWWWW' */
      $s6 = "            xmlns:pdfx=\"http://ns.adobe.com/pdfx/1.3/\">" fullword ascii
      $s7 = "            xmlns:pdf=\"http://ns.adobe.com/pdf/1.3/\">" fullword ascii
      $s8 = "            xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\">" fullword ascii
      $s9 = "            xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\">" fullword ascii
      $s10 = "nnn%%%" fullword ascii /* reversed goodware string '%%%nnn' */
      $s11 = "MMMaaa" fullword ascii /* reversed goodware string 'aaaMMM' */
      $s12 = "<</DecodeParms<</Columns 4/Predictor 12>>/Filter/FlateDecode/ID[<8D927BB6A1864FDBB7C74408D0F36E96><3AD19FA075DC86498A4EEE9114CD3" ascii
      $s13 = ":::zzz" fullword ascii /* reversed goodware string 'zzz:::' */
      $s14 = "<</DecodeParms<</Columns 5/Predictor 12>>/Filter/FlateDecode/ID[<8D927BB6A1864FDBB7C74408D0F36E96><3AD19FA075DC86498A4EEE9114CD3" ascii
      $s15 = "O@@@@@" fullword ascii /* reversed goodware string '@@@@@O' */
      $s16 = "(+++--" fullword ascii /* reversed goodware string '--+++(' */
      $s17 = "444455" ascii /* reversed goodware string '554444' */
      $s18 = "[$!!!!" fullword ascii
      $s19 = "@!!!!!!!!" fullword ascii
      $s20 = "^1h!!!" fullword ascii
   condition:
      uint16(0) == 0x5025 and filesize < 22000KB and
      8 of them
}

