#!/usr/bin/env python3

# Run like this:
#
# Prerequisite:
# For legal reasons you have to obtain your own IVs.
# They can be found in most Spike 1 / 2 binaries.
# 
# Any of these should work:
#
# /usr/local/bin/spk
# /usr/local/spike/spike_menu/game
# /games/game
#
# Because these files are also part of (uncompressed) SPK updates, you can also supply the path to some SPK update file.
#
# `./extract ivs.bin <spike-binary-path>` - Requires: Some Spike `spk` or supported `game` binary
#
# For Spike 1:
# `./extract spi_factory_key-1_0_0.key eeprom-0x51.bin` - Also requires: ivs.bin cpu-serial.bin mac-address.bin
#
# For Spike 2:
# `./extract cpu-serial.bin` - Requires: HW_OCOTP_CFG0.bin HW_OCOTP_CFG1.bin
# `./extract mac-address.bin` - Requires: HW_OCOTP_MAC0.bin HW_OCOTP_MAC1.bin
# `./extract spi_factory_key-1_0_0.key eeprom-0x50.bin` - Also requires: ivs.bin cpu-serial.bin mac-address.bin

import sys
import mmap
import hashlib
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


ivsName = "ivs.bin"
cpuSerialName = "cpu-serial.bin"
macAddressName = "mac-address.bin"
factoryKeyName = "spi_factory_key-1_0_0.key"


argIndex = 1
def getArg(name):
    global argIndex
    argIndex += 1
    if len(sys.argv) <= argIndex:
        print("Error: Missing required argument: <%s>" % name)
        sys.exit(1)
    return sys.argv[argIndex]

def save(filename, data):
    try:
        with open(filename, 'xb') as f:
            f.write(data)
        print("Created %s" % filename)
        sys.exit(0)
    except FileExistsError:
        oldData = open(filename, 'rb').read()
        if (oldData == data):
            print("Note: '%s' already exists but matches result." % filename)
            sys.exit(0)
        else:
            print("Error: '%s' already exists but differs from result!" % filename)
            sys.exit(1)
        
def load(filename):
    try:
        f = open(filename, 'rb')
        return mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
    except FileNotFoundError:
        print("Error: Required file '%s' does not exist." % filename)
        sys.exit(1)

def loadRequiredPath(name):
    path = getArg(name)
    return load(path), path

def loadRequired(filename):
    return load(filename)

def extractIvs():
    data, dataPath = loadRequiredPath('spike-binary-path')    

    def search():

        # Checks if this offset matches the IVs
        def tryOffset(offset):
            ivs = data[offset:offset + 0x20]

            # Ensure the found IVs are correct
            return hashlib.md5(ivs).hexdigest() == "e9a3330715cbd401512e9b12d503241e"

        # These rather reliably appear around kek_iv and aes_iv
        needles = [
            (b'/games/\x00EACCES\x00\x00EBUSY\x00\x00\x00', -0x20),
            (b'/media/spi_factory_key-1_0_0.key\x00', -0x20),
        ]
        for needle in needles:
            needleStart = max(0, -needle[1])
            while True:
                needleStart = data.find(needle[0], needleStart)
                if needleStart == -1:
                    break
                offset = needleStart + needle[1]
                if tryOffset(offset):
                    return offset
                needleStart += 1
        
        # If we didn't have any luck, try brute-force search
        print("Note: Unable to detect known IV locations, using aggressive search")
        for offset in range(0, len(data) - 0x20 + 1):
            if tryOffset(offset):
                return offset

        return -1
    
    ivsStart = search()

    if ivsStart == -1:
        print("Error: Unable to find IVs in '%s'" % dataPath)
        sys.exit(1)

    ivs = data[ivsStart:ivsStart + 0x20]

    print("Note: Result confirmed by checksum!")

    save(ivsName, ivs)

def textToData(text):
    text = text.decode('ascii')
    assert(text[0:2] == '0x')
    return int(text[2:], 16)

def extractCpuSerial():
    cfg0Value = textToData(loadRequired("HW_OCOTP_CFG0.bin"))
    cfg1Value = textToData(loadRequired("HW_OCOTP_CFG1.bin"))

    cpuSerial = bytes([
        (cfg0Value >> 0) & 0xFF,
        (cfg0Value >> 8) & 0xFF,
        (cfg0Value >> 16) & 0xFF,
        (cfg0Value >> 24) & 0xFF,
        (cfg1Value >> 0) & 0xFF,
        (cfg1Value >> 8) & 0xFF,
        (cfg1Value >> 16) & 0xFF,
        (cfg1Value >> 24) & 0xFF
    ] + [0x00] * 8)
  
    save(cpuSerialName, cpuSerial)

def extractMacAddress():
    mac0 = loadRequired("HW_OCOTP_MAC0.bin")
    mac1 = loadRequired("HW_OCOTP_MAC1.bin")

    # Untested and probably broken!
    # This probably needs to extract bits from text like extractCpuSerial
    assert(False)
  
    macAddress = bytes([
        mac0[0],
        mac0[1],
        mac0[2],
        mac0[3],
        mac1[0],
        mac1[1]
    ])

    save(macAddressName, macAddress)


def extractFactoryKey():
    
    cpuSerial = loadRequired(cpuSerialName)
    assert(len(cpuSerial) == 16)
    macAddress = loadRequired(macAddressName)
    assert(len(macAddress) == 6)
    ivs = loadRequired(ivsName)
    assert(len(ivs) == 0x20)
    eeprom, eepromPath = loadRequiredPath('eeprom-path')
    # Spike 1 eeprom_0x51.bin is 0x100
    # Spike 2 eeprom_0x50.bin is 0x8000 (all EEPROMs on Spike 2 are that size)
    assert(len(eeprom) in [0x100, 0x8000])

    kek_iv = ivs[0x0:0x10]
    aes_iv = ivs[0x10:0x20]

    # Based on sys_factory_key_generate_factory_key_encryption_key
    sha256sum = hashlib.new('sha256')
    sha256sum.update(macAddress)
    sha256sum.update(kek_iv)
    sha256sum.update(cpuSerial)
    encryptionKey = sha256sum.digest()[4:4+0x18]
    assert(len(encryptionKey) == 0x18)

    # Based on aes_192_decrypt
    encryptedFactoryKey = eeprom[0x40:0x40 + 0xC0]
    decryptor = Cipher(algorithms.AES(encryptionKey), modes.OFB(aes_iv), backend=default_backend()).decryptor()
    factoryKey = decryptor.update(encryptedFactoryKey) + decryptor.finalize()

    # Based on sys_factory_key_verify_checksum (CRC32 Polynomial 0xedb88320)
    sha1sum = hashlib.sha1(factoryKey).digest()
    checksum = zlib.crc32(sha1sum)

    # This checksum is part of the Stern code to verify the file
    # It's purely used to verify the key, so it's not considered a secret
    assert(checksum == 0xf2dda920)
    print("Note: Result confirmed by checksum!")

    save(factoryKeyName, factoryKey)


if __name__ == "__main__":

    extractors = {}
    extractors[ivsName] = extractIvs
    extractors[cpuSerialName] = extractCpuSerial
    extractors[macAddressName] = extractMacAddress
    extractors[factoryKeyName] = extractFactoryKey

    def showOptions():
        print("Need to specify a valid output name:")
        for extractor in extractors:
            print("- %s" % extractor)
        sys.exit(1)

    if len(sys.argv) < 2:
        showOptions()

    target = sys.argv[1]

    extractor = extractors.get(target, None)
    if extractor != None:
        extractor()
    else:
        showOptions()