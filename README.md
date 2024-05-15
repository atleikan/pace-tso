# pace-tso

This repository contains the files we have used to modify, build and test a modified version of the CoreNIC firmware for the Netronome Agiliio CX 2x10GbE, which enables it to pace out TSO packets at a static rate.
 
## Modifying firmware to enable pacing
The original CoreNIC can be found in Netronome's GitHub repository: https://github.com/Netronome/nic-firmware.git

The modifications required to the CoreNIC firmware to enable pacing only involves modifying one file, being `notify.c`. This can be done by replacing `/nic-firmware/deps/ng-nfd.git/me/blocks/vnic/pci_in/notify.c` in the original firmware folder with the modified `notify.c` found in this repo.

While it may have been more convenient if the entirety of the CoreNIC firmware, including our modifications, could be cloned from our repository, we have not been able to allow for this. The reason for this is that our modifications have been performed within the NFD submodule of the CoreNIC repo. Attempting to upload the entirety of the CoreNIC firmware to our repository therefore results in GitHub referencing the original submodule repository, rather than including our modified version of the submodule.
However, seeing as our implementation only modifies one file in the original firmware, this should hopefully not introduce too much inconvenience.

## Building modified firmware
The firmware can be built using the makefile located in the nic-firmware folder. This makefile takes an optional argument that specifies which hardware target to build for. Issuing make `nic/nic_AMDA0096-0001_2x10.nffw` will build the firmware specifically for the Agilio CX 2x10GbE model of the card.

Building the firmware will generate `.nffw` files, located in `nic-firmware/firmware/nffw`, which contain the built firmware for the specified card. To load the built firmware onto the NIC, these `.nffw` files must be moved to `/lib/firmware/netronome`. 

Finally, the following commands can be used to reload the NFP driver, which will result in the card being rebooted with the new firmware.
```
depmod -a
rmmod nfp
modprobe nfp nfp_dev_cpp=1
update-initramfs -u
```

`build-agilio-firmware.sh` contains a script that performs this building process.

## FTP client script for testing
`ftp_client.sh` contains a script that initiates a given number of FTP connections a server while recording incoming traffic using tcpdump.
By running running the modified Agilio firmware on the server's NIC, this can be used to examine its resulting traffic.

`pcap_parser.py` parses and plots information from .pcap-files recorded during the FTP connections

 
