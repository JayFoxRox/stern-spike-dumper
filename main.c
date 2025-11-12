// Stern Spike pinball machine EEPROM and fuse dumper
//
// (C)2025 Jannik Vogel

#ifndef SPIKE
#warning No Spike version selected, this is dangerous
#endif

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <unistd.h>


#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))


void printNow(const char* text) {
  fputs(text, stdout);
  fflush(stdout);
}


void dumpBuffer(const char* path, const void* data, size_t size) {
  FILE* f = fopen(path, "wb");
  assert(f != NULL);
  size_t writtenSize = fwrite(data, 1, size, f);
  assert(writtenSize == size);
  fclose(f);
}


void dumpFile(const char* path, const char* sourcePath) {
  FILE* f = fopen(sourcePath, "rb");
  assert(f != NULL);
  fseek(f, 0, SEEK_END);
  size_t size = ftell(f);
  fseek(f, 0, SEEK_SET);
  void* data = malloc(size);
  assert(data != NULL);
  size_t readSize = fread(data, 1, size, f);
  // We can't confirm the size here, as files in /sys/ or /proc/ might appear larger than they are
  fclose(f);
  dumpBuffer(path, data, readSize);
  free(data);
}

// Based on ReadRegisters and eep_read_mac_address
int readRegisters(const char* i2cPath, uint16_t slaveAddress, uint8_t address, uint8_t count, uint8_t* output) {
  int fd = open(i2cPath, O_RDWR);
  if (fd < 0) {
    return -1;
  }

  while(count-- > 0) {

    // Set slave address
    // Stern Logic: Do it before each write
    int ret = ioctl(fd, I2C_SLAVE, slaveAddress);
    if (ret < 0) {
      close(fd);
      return -1;
    }

    // Read byte
    struct i2c_smbus_ioctl_data ioctl_data = {0};
    union i2c_smbus_data data = {0};
    ioctl_data.read_write = I2C_SMBUS_READ;
    ioctl_data.size = I2C_SMBUS_BYTE_DATA;
    ioctl_data.command = address++;
    ioctl_data.data = &data;
    ret = ioctl(fd, I2C_SMBUS, &ioctl_data);
    if (ret != 0) {
      close(fd);
      return -1;
    }
    *output++ = data.byte;

  }

  close(fd);
  return 0;
}


int eep_ioctl_I2C_RDWR(int fd, struct i2c_rdwr_ioctl_data* msgset) {
  unsigned int attempts = 10;
  while(true) {

    int ret = ioctl(fd, I2C_RDWR, msgset);
    if (ret >= 0) {
      return ret;
    }

    if (attempts-- == 0) {
      return ret;
    }

    usleep(1000);
  }
}


// Based on eep_read_bytes
unsigned int eep_read_bytes(const char* i2cPath, uint16_t slaveAddress, uint16_t address, uint8_t* output, uint32_t size, unsigned int addrSize) {
  int ret;

  struct i2c_rdwr_ioctl_data msgset = {0};
  struct i2c_msg msg = {0};
  uint8_t buffer[256];

  if (size == 0) {
    return 0;
  }

  int fd = open(i2cPath, O_RDWR);
  if (fd < 0) {
    return 0;
  }

  // Set slave address
  ret = ioctl(fd, I2C_SLAVE, slaveAddress);
  if (ret < 0) {
    close(fd);
    return 0;
  }

  // Set address
  {
    msg.addr = slaveAddress;
    msg.flags = 0;
    msg.buf = buffer;
    if (addrSize == 1) {
      buffer[0] = address & 0xFF;
      msg.len = 1;
    } else if (addrSize == 2) {
      buffer[0] = (address >> 8) & 0xFF;
      buffer[1] = (address >> 0) & 0xFF;
      msg.len = 2;
    } else {
      assert(false);
    }

    msgset.nmsgs = 1;
    msgset.msgs = &msg;

    ret = eep_ioctl_I2C_RDWR(fd, &msgset);
    if (ret < 0) {
      close(fd);
      return 0;
    }
  }

  while(size > 0) {

    uint32_t chunkSize = size;
    if (chunkSize >= 0x100) {
      chunkSize = 0x100;
    }

    // Read
    {
      msg.addr = slaveAddress;
      msg.flags = I2C_M_RD;
      msg.buf = buffer;
      msg.len = chunkSize;

      msgset.nmsgs = 1;
      msgset.msgs = &msg;

      ret = eep_ioctl_I2C_RDWR(fd, &msgset);
    }

    // Copy to output
    for(uint32_t i = 0; i < chunkSize; i++) {
      *output++ = buffer[i];
    }
    size -= chunkSize;

    // Check for read errors
    // Stern logic: Copy to output buffer, even if read failed
    if (ret < 0) {
      close(fd);
      return 0;
    }

  }

  close(fd);
  return 1;
}


int main() {
  int ret;

  printf("Compiled for running on Spike %d\n", SPIKE);

  typedef struct {
    const char* dumpPath;
    uint16_t slaveAddress;
    size_t size;
    unsigned int addrSize;
  } Eeprom;


#if SPIKE == 1

  const char* i2cPath = "/dev/i2c-0";
  const Eeprom eeproms[] = {
    { "eeprom_0x50.bin", 0x50, 0x8000, 2 },
    { "eeprom_0x51.bin", 0x51,  0x100, 1 },
    { "eeprom_0x52.bin", 0x52, 0x4000, 2 }
  };

  printNow("Dumping CPU serial.. ");
  uint8_t cpuSerial[16];
  memset(cpuSerial, 0x00, sizeof(cpuSerial));
  ret = readRegisters(i2cPath, 0x59, 0x80, sizeof(cpuSerial), cpuSerial);
  assert(ret == 0);
  dumpBuffer("cpu-serial.bin", cpuSerial, sizeof(cpuSerial));
  printNow("done\n");

  printNow("Dumping MAC address.. ");
  uint8_t macAddress[6];
  memset(macAddress, 0x00, sizeof(macAddress));
  ret = readRegisters(i2cPath, 0x59, 0x9A, sizeof(macAddress), macAddress);
  assert(ret == 0);
  dumpBuffer("mac-address.bin", macAddress, sizeof(macAddress));
  printNow("done\n");

#elif SPIKE == 2

  const char* i2cPath = "/dev/i2c-1";
  const Eeprom eeproms[] = {
    { "eeprom_0x50.bin", 0x50, 0x8000, 2 },
    { "eeprom_0x51.bin", 0x51, 0x8000, 2 },
    { "eeprom_0x52.bin", 0x52, 0x8000, 2 }
  };

  // Guesswork, not actually tested or based on Stern code

  // CPU serial
  printNow("Dumping CPU serial.. ");
  dumpFile("HW_OCOTP_CFG0.bin", "/sys/fsl_otp/HW_OCOTP_CFG0");
  dumpFile("HW_OCOTP_CFG1.bin", "/sys/fsl_otp/HW_OCOTP_CFG1");
  printNow("done\n");

  // MAC address
  printNow("Dumping MAC address.. ");
  uint8_t macAddress[6];
  memset(macAddress, 0x00, sizeof(macAddress));
  if (readRegisters(i2cPath, 0x5B, 0x9A, sizeof(macAddress), macAddress) == 0) {
    dumpBuffer("mac-address.bin", macAddress, sizeof(macAddress));
    printNow("done (I2C)\n");
  } else {
    dumpFile("HW_OCOTP_MAC0.bin", "/sys/fsl_otp/HW_OCOTP_MAC0");
    dumpFile("HW_OCOTP_MAC1.bin", "/sys/fsl_otp/HW_OCOTP_MAC1");
    printNow("done (OTP)\n");
  }

#else

  #error Unknown Spike version

#endif

  for(unsigned int i = 0; i < ARRAY_SIZE(eeproms); i++) {
    const Eeprom* eeprom = &eeproms[i];
    char message[512];
    sprintf(message, "Dumping EEPROM at 0x%X.. ", eeprom->slaveAddress);
    printNow(message);
    uint8_t* buffer = malloc(eeprom->size);
    ret = eep_read_bytes(i2cPath, eeprom->slaveAddress, 0, buffer, eeprom->size, eeprom->addrSize);
    assert(ret == 1);
    dumpBuffer(eeprom->dumpPath, buffer, eeprom->size);
    free(buffer);
    printNow("done\n");
  }

  return 0;
}
