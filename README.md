unHooker
========

Kernel (Ring0) - SSDT unhook driver
this is the full code of unHooker project , the driver and the loader 

- What it does ? 
  unhooking the any intlized ssdt hook , by reset the service pointer to the real one
  after retiving it from the 'ntoskrnl.exe' by the function OrginalAddress using the index of the service
  it do load the ntoskrnl and search for the pointer on it then passing it to the driver using cHook structer 
  the driver disable the system write protection then edit the ssdt with the real pointer using the index of the service
  after that , it return the protection and continue working . 
  
About
========

I have coded this source with help from my team friend simon (DPCODERS)
coded before 6 months or more of releasing it here . 
just don't forget to credit if you use it :) .
