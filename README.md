# dmdecrypt

Decrypt [dmcrypt](https://gitlab.com/cryptsetup/cryptsetup/-/wikis/DMCrypt) volumes using OpenSSL.

dmcrypt uses [Encrypted salt-sector initialization vector (ESSIV)](https://en.wikipedia.org/wiki/Disk_encryption_theory#Encrypted_salt-sector_initialization_vector_(ESSIV)) in which each sector of the volume is encrypted through AES-CBC, using the same key but a different IV for each sector. The IV is obtained by encrypting the padded sector number with the SHA256 hash of the key.

## Usage
```
De(En)crypts a dmcrypt-style aes-cbc-essiv:sha256 disk volume
Usage: dmdecrypt [-e] [-y] [-q] input output key
  -e     Encrypt; if not specified, default is to decrypt.
  -y     Overwrite output file if it exists.
  -q     Quiet output. Only print errors.
  input  Input disk volume. Size in bytes must be a multiple of 512.
  output Output disk volume.
  key    Key file. Must be either 16, 24 or 32 bytes long.
```

## Compiling

On recent Debian / Ubuntu just:

```
apt install gcc cmake pkg-config libssl-dev git
git clone https://github.com/francescovannini/dmdecrypt.git
cd dmdecrypt
mkdir build
cd build
cmake ..
make
./dmdecrypt
```

### Example use case: recover data from Android Adopted Storage

This tool has been successfully used to recover data from a crashed Android phone (thanks to Nikolay Elenkov for this excellent [post](https://nelenkov.blogspot.com/2015/06/decrypting-android-m-adopted-storage.html)).
The data was stored on an external SD card mounted as Android adopted storage which is essentially based on dmcrypt; but once the phone was unable to properly boot, the data in the SD card became inaccessible. 

To recover it, I had to:
* Boot the phone using a recovery image
* Extract the key file `/data/misc/vold/expand_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.key`
* Run this tool against the second partition of the SD card (the largest one) and the key above
* Mount the decrypted volume under Linux via loopback
* Access the files
