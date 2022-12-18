rule Venom {
   meta:
      description = "Venom"
      author = "Ido Veltzman"
      reference = "https://github.com/Idov31/Venom"
      date = "2022-12-17"
   strings:
      $s1 = "WS2_32.dll" fullword ascii
      $s2 = "[ - ] Failed to create process: " fullword ascii
      $s3 = "[ + ] Created detached hidden msedge process: " fullword ascii
      $s4 = "WSASocketW" fullword ascii
      $s5 = "[ - ] Failed to get socket." fullword ascii
      $s6 = ">[ - ] Could not initialize the usage of sockets: " fullword ascii
      $s7 = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe --no-startup-window" fullword wide
      $s8 = "WSADuplicateSocketW" fullword ascii
      $s9 = "[ - ] Failed to send data: " fullword ascii
      $s10 = "[ - ] Failed to allocate sysHandleInfo: " fullword ascii
      $s11 = "[ - ] Failed to duplicate socket: " fullword ascii
      $s12 = "[ - ] Failed to allocate objNameInfo: " fullword ascii
      $s13 = "[ - ] Failed to load critical functions: " fullword ascii
      $s18 = "[ + ] Data sent!" fullword ascii
      $s19 = "[ + ] Socket obtained!" fullword ascii

      $op0 = { 4c 8b f0 48 3b c1 48 b8 ff ff ff ff ff ff ff 7f }
      $op1 = { 48 8b cf e8 1c 34 00 00 48 8b 5c 24 30 48 8b c7 }
      $op2 = { 48 8b da 48 8b f9 45 33 f6 48 85 c9 0f 84 34 01 }
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      (4 of ($s*) and all of ($op*) )
}
