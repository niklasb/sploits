This is an exploit for CVE-2018-2860, which covers two bugs:
https://www.zerodayinitiative.com/advisories/ZDI-18-783/ and
https://www.zerodayinitiative.com/advisories/ZDI-18-782/. Details at
https://github.com/phoenhex/files/blob/master/slides/thinking_outside_the_virtualbox.pdf

Code is based on https://github.com/Cr4sh/fwexpl, which is GPL code hence the
GPL license. The actual exploit code is in `source/pwn2ownuser/main.cpp`, the
final exploit script used at Pwn2Own 2018 is in `exploit/doit.cmd`
