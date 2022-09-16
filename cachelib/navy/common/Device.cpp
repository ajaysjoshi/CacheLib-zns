/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cachelib/navy/common/Device.h"

#include <folly/File.h>
#include <folly/Format.h>

#include <cstring>
#include <numeric>

// If BlockZoned header doesn't exist,
// then define all the required definitions
#ifdef NO_BLOCKZONED
//From linux/blkzoned.h
struct blk_zone {
  uint64_t   start;          /* Zone start sector */
  uint64_t   len;            /* Zone length in number of sectors */
  uint64_t   wp;             /* Zone write pointer position */
  uint8_t     type;           /* Zone type */
  uint8_t     cond;           /* Zone condition */
  uint8_t     non_seq;        /* Non-sequential write resources active */
  uint8_t     reset;          /* Reset write pointer recommended */
  uint8_t     reserved[36];
};

struct blk_zone_report {
  uint64_t  sector;
  uint32_t  nr_zones;
  uint8_t    reserved[4];
  struct blk_zone zones[0];
};

struct blk_zone_range {
  uint64_t  sector;
  uint64_t  nr_sectors;
};

#ifndef BLKRESETZONE
#define BLKRESETZONE    _IOW(0x12, 131, struct blk_zone_range)
#endif
#ifndef BLKREPORTZONE
#define BLKREPORTZONE   _IOWR(0x12, 130, struct blk_zone_report)
#endif
#ifndef BLKGETZONESZ
#define BLKGETZONESZ    _IOR(0x12, 132, __u32)
#endif
#ifndef BLKGETNRZONES
#define BLKGETNRZONES   _IOR(0x12, 133, __u32)
#endif
/*
* BLKFINISHZONE ioctl commands
* were introduced with kernel 5.5. If they are not defined on the
* current system, manually define these operations here to generate
* code portable to newer kernels.
*/

#ifndef BLKFINISHZONE
#define BLKFINISHZONE _IOW(0x12, 136, struct blk_zone_range)
#endif

#else
#include <linux/blkzoned.h>
#ifndef BLKFINISHZONE
#define BLKFINISHZONE _IOW(0x12, 136, struct blk_zone_range)
#endif
#endif

#include <sys/ioctl.h>

namespace facebook {
namespace cachelib {
namespace navy {
namespace {

using IOOperation =
    std::function<ssize_t(int fd, void* buf, size_t count, off_t offset)>;

// Device on Unix file descriptor
class FileDevice final : public Device {
 public:
  FileDevice(folly::File file,
             uint64_t size,
             uint32_t ioAlignSize,
             std::shared_ptr<DeviceEncryptor> encryptor,
             uint32_t maxDeviceWriteSize)
      : Device{size, std::move(encryptor), ioAlignSize, maxDeviceWriteSize},
        file_{std::move(file)} {}
  FileDevice(const FileDevice&) = delete;
  FileDevice& operator=(const FileDevice&) = delete;

  ~FileDevice() override {}

 private:
  bool writeImpl(uint64_t offset, uint32_t size, const void* value) override {
    ssize_t bytesWritten = ::pwrite(file_.fd(), value, size, offset);
    if (bytesWritten != size) {
      reportIOError("write", offset, size, bytesWritten);
    }
    return bytesWritten == size;
  }

  bool readImpl(uint64_t offset, uint32_t size, void* value) override {
    ssize_t bytesRead = ::pread(file_.fd(), value, size, offset);
    if (bytesRead != size) {
      reportIOError("read", offset, size, bytesRead);
    }
    return bytesRead == size;
  }

  void flushImpl() override { ::fsync(file_.fd()); }

  void reportIOError(const char* opName,
                     uint64_t offset,
                     uint32_t size,
                     ssize_t ioRet) {
    XLOG_EVERY_N_THREAD(
        ERR, 1000,
        folly::sformat("IO error: {} offset={} size={} ret={} errno={} ({})",
                       opName, offset, size, ioRet, errno,
                       std::strerror(errno)));
  }

  uint64_t doZoneOpImpl(ZoneOpEnum optype,
    uint64_t arg1, uint64_t arg2) override {
    return 0;
  }

  const folly::File file_{};
};

// RAID0 device spanning multiple files
class RAID0Device final : public Device {
 public:
  RAID0Device(std::vector<folly::File> fvec,
              uint64_t fdSize,
              uint32_t ioAlignSize,
              uint32_t stripeSize,
              std::shared_ptr<DeviceEncryptor> encryptor,
              uint32_t maxDeviceWriteSize)
      : Device{fdSize * fvec.size(), std::move(encryptor), ioAlignSize,
               maxDeviceWriteSize},
        fvec_{std::move(fvec)},
        stripeSize_(stripeSize) {
    XDCHECK_GT(ioAlignSize, 0u);
    XDCHECK_GT(stripeSize_, 0u);
    XDCHECK_GE(stripeSize_, ioAlignSize);
    XDCHECK_EQ(0u, stripeSize_ % 2) << stripeSize_;
    XDCHECK_EQ(0u, stripeSize_ % ioAlignSize)
        << stripeSize_ << ", " << ioAlignSize;
    if (fdSize % stripeSize != 0) {
      throw std::invalid_argument(
          folly::sformat("Invalid size because individual device size: {} is "
                         "not aligned to stripe size: {}",
                         fdSize, stripeSize));
    }
  }
  RAID0Device(const RAID0Device&) = delete;
  RAID0Device& operator=(const RAID0Device&) = delete;

  ~RAID0Device() override {}

 private:
  bool writeImpl(uint64_t offset, uint32_t size, const void* value) override {
    IOOperation io = ::pwrite;
    return doIO(offset, size, const_cast<void*>(value), "RAID0 WRITE", io);
  }

  bool readImpl(uint64_t offset, uint32_t size, void* value) override {
    IOOperation io = ::pread;
    return doIO(offset, size, value, "RAID0 READ", io);
  }

  void flushImpl() override {
    for (const auto& f : fvec_) {
      ::fsync(f.fd());
    }
  }

  uint64_t doZoneOpImpl(ZoneOpEnum optype,
    uint64_t arg1, uint64_t arg2) override {
    return 0;
  }

  bool doIO(uint64_t offset,
            uint32_t size,
            void* value,
            const char* opName,
            IOOperation& io) {
    uint8_t* buf = reinterpret_cast<uint8_t*>(value);

    while (size > 0) {
      uint64_t stripe = offset / stripeSize_;
      uint32_t fdIdx = stripe % fvec_.size();
      uint64_t stripeStartOffset = (stripe / fvec_.size()) * stripeSize_;
      uint32_t ioOffsetInStripe = offset % stripeSize_;
      uint32_t allowedIOSize = std::min(size, stripeSize_ - ioOffsetInStripe);

      ssize_t retSize = io(fvec_[fdIdx].fd(),
                           buf,
                           allowedIOSize,
                           stripeStartOffset + ioOffsetInStripe);
      if (retSize != allowedIOSize) {
        XLOG_EVERY_N_THREAD(
            ERR, 1000,
            folly::sformat(
                "IO error: {} logicalOffset={} logicalIOSize={} stripeSize={} "
                "stripe={} offsetInStripe={} stripeIOSize={} ret={} errno={} "
                "({})",
                opName,
                offset,
                size,
                stripeSize_,
                stripe,
                ioOffsetInStripe,
                allowedIOSize,
                retSize,
                errno,
                std::strerror(errno)));

        return false;
      }

      size -= allowedIOSize;
      offset += allowedIOSize;
      buf += allowedIOSize;
    }
    return true;
  }

  const std::vector<folly::File> fvec_{};
  const uint32_t stripeSize_{};
};

// Device on memory buffer
class MemoryDevice final : public Device {
 public:
  explicit MemoryDevice(uint64_t size,
                        std::shared_ptr<DeviceEncryptor> encryptor,
                        uint32_t ioAlignSize)
      : Device{size, std::move(encryptor), ioAlignSize,
               0 /* max device write size */},
        buffer_{std::make_unique<uint8_t[]>(size)} {}
  MemoryDevice(const MemoryDevice&) = delete;
  MemoryDevice& operator=(const MemoryDevice&) = delete;
  ~MemoryDevice() override = default;

 private:
  bool writeImpl(uint64_t offset,
                 uint32_t size,
                 const void* value) noexcept override {
    XDCHECK_LE(offset + size, getSize());
    std::memcpy(buffer_.get() + offset, value, size);
    return true;
  }

  bool readImpl(uint64_t offset, uint32_t size, void* value) override {
    XDCHECK_LE(offset + size, getSize());
    std::memcpy(value, buffer_.get() + offset, size);
    return true;
  }

  void flushImpl() override {
    // Noop
  }

  uint64_t doZoneOpImpl(ZoneOpEnum optype,
    uint64_t arg1, uint64_t arg2) override {
    return 0;
  }

  std::unique_ptr<uint8_t[]> buffer_;
};

// ZNS Device
class ZNSDevice final : public Device {
public:

  //512B sector size shift.
  #define SECTOR_SHIFT 9
  #define MAX_NO_OF_ZONES 8192

  explicit ZNSDevice(int dev,
  uint64_t size,
  uint32_t ioAlignSize,
  uint64_t zoneSize,
  uint64_t  zoneCapacity,
  struct blk_zone *zoneLogPage,
  struct blk_zone_report *zoneReport,
  std::shared_ptr<DeviceEncryptor> encryptor,
  uint32_t maxDeviceWriteSize)
  : Device{size, std::move(encryptor), ioAlignSize,
  maxDeviceWriteSize},
  dev_{std::move(dev)},
  zoneSize_ {std::move(zoneSize)},
  zoneCapacity_ {std::move(zoneCapacity)},
  zoneLogPage_ {std::move(zoneLogPage)},
  zoneReport_ {std::move(zoneReport)}
  {
  }
  ZNSDevice(const ZNSDevice&) = delete;
  ZNSDevice& operator=(const ZNSDevice&) = delete;

  ~ZNSDevice() override = default;

private:
  const int dev_{};
  uint64_t  zoneSize_;
  uint64_t  zoneCapacity_;
  struct blk_zone *zoneLogPage_;
  struct blk_zone_report *zoneReport_;

  uint64_t  finish(uint64_t offset, uint64_t len) {
    struct blk_zone_range range;

    range.sector = offset >> SECTOR_SHIFT;
    range.nr_sectors = zoneSize_ >> SECTOR_SHIFT;
    if (::ioctl(dev_, BLKFINISHZONE, &range) < 0) {
      XLOG_EVERY_N_THREAD(ERR, 1000,
          folly::sformat(
              "Finish error: {} logicalOffset={} ret={} errno={} "
              "({})",
              BLKFINISHZONE,
              offset,
              errno,
              std::strerror(errno)));
      return (uint64_t)false;
   }
    return (uint64_t)true;
  }

  uint64_t reset(uint64_t offset, uint64_t len) {
    struct blk_zone_range range;

    range.sector = offset >> SECTOR_SHIFT;
    range.nr_sectors = zoneSize_ >> SECTOR_SHIFT;
    if (::ioctl(dev_, BLKRESETZONE, &range) < 0) {
      XLOG_EVERY_N_THREAD(  ERR, 1000,
          folly::sformat(
              "Rest error: {} logicalOffset={} ret={} errno={} "
              "({})",
              BLKRESETZONE,
              offset,
              errno,
              std::strerror(errno)));
      return (uint64_t)false;
    }
    return (uint64_t)true;
  }

  uint64_t len(uint64_t len) {
    uint32_t zoneNr;
    if (!len)
      return zoneSize_;

    zoneNr = (len/zoneCapacity_);
    if(len % zoneCapacity_)
      zoneNr++;
    return zoneNr * zoneSize_;
 }

  uint64_t doZoneOpImpl(ZoneOpEnum optype,
    uint64_t arg1, uint64_t arg2) override {
    switch(optype) {
      case ZONE_DEVICE:
        return (uint64_t)true;
      case ZONE_RESET:
        return (uint64_t)reset(arg1, len(arg2));
      case ZONE_FINISH:
        return (uint64_t)finish(arg1, len(arg2));
      case ZONE_SIZE:
        return zoneSize_;
      case ZONE_CAPACITY:
        return zoneCapacity_;
      case  ZONE_ADDR_FROM_OFFSET:
          return (zoneLogPage_[arg1/zoneCapacity_].start << SECTOR_SHIFT)
                  + (arg1 % zoneCapacity_);
    }
    return (uint64_t)false;
  }

  bool writeImpl(uint64_t offset, uint32_t size, const void* value) override {
    ssize_t bytesWritten;

    bytesWritten = ::pwrite(dev_, value, size, offset);
    return bytesWritten == size;
 }

  bool readImpl(uint64_t offset, uint32_t size, void* value) override {
    ssize_t bytesRead;
    bytesRead = ::pread(dev_, value, size, offset);
    return bytesRead == size;
  }
  void flushImpl() override { ::fsync(dev_); }
  };
}

bool Device::write(uint64_t offset, Buffer buffer) {
  const auto size = buffer.size();
  XDCHECK_LE(offset + buffer.size(), size_);
  uint8_t* data = reinterpret_cast<uint8_t*>(buffer.data());
  XDCHECK_EQ(reinterpret_cast<uint64_t>(data) % ioAlignmentSize_, 0ul);
  if (encryptor_) {
    XCHECK_EQ(offset % encryptor_->encryptionBlockSize(), 0ul);
    auto res = encryptor_->encrypt(folly::MutableByteRange{data, size}, offset);
    if (!res) {
      encryptionErrors_.inc();
      return false;
    }
  }

  auto remainingSize = size;
  auto maxWriteSize = (maxWriteSize_ == 0) ? remainingSize : maxWriteSize_;
  bool result = true;
  while (remainingSize > 0) {
    auto writeSize = std::min<size_t>(maxWriteSize, remainingSize);
    XDCHECK_EQ(offset % ioAlignmentSize_, 0ul);
    XDCHECK_EQ(writeSize % ioAlignmentSize_, 0ul);

    auto timeBegin = getSteadyClock();
    result = writeImpl(offset, writeSize, data);
    writeLatencyEstimator_.trackValue(
        toMicros((getSteadyClock() - timeBegin)).count());

    if (result) {
      bytesWritten_.add(writeSize);
    } else {
      // One part of the write failed so we abort the rest
      break;
    }
    offset += writeSize;
    data += writeSize;
    remainingSize -= writeSize;
  }
  if (!result) {
    writeIOErrors_.inc();
  }
  return result;
}

// reads size number of bytes from the device from the offset into value.
// Both offset and size are expected to be aligned for device IO operations.
// If successful and encryptor_ is defined, size bytes from
// validDataOffsetInValue offset in value are decrypted.
//
// returns true if successful, false otherwise.
bool Device::readInternal(uint64_t offset, uint32_t size, void* value) {
  XDCHECK_EQ(reinterpret_cast<uint64_t>(value) % ioAlignmentSize_, 0ul);
  XDCHECK_EQ(offset % ioAlignmentSize_, 0ul);
  XDCHECK_EQ(size % ioAlignmentSize_, 0ul);
  XDCHECK_LE(offset + size, size_);
  auto timeBegin = getSteadyClock();
  bool result = readImpl(offset, size, value);
  readLatencyEstimator_.trackValue(
      toMicros(getSteadyClock() - timeBegin).count());
  if (!result) {
    readIOErrors_.inc();
    return result;
  }
  bytesRead_.add(size);
  if (encryptor_) {
    XCHECK_EQ(offset % encryptor_->encryptionBlockSize(), 0ul);
    auto res = encryptor_->decrypt(
        folly::MutableByteRange{reinterpret_cast<uint8_t*>(value), size},
        offset);
    if (!res) {
      decryptionErrors_.inc();
      return false;
    }
  }
  return true;
}

// This API reads size bytes from the Device from offset into a Buffer and
// returns the Buffer. If offset and size are not aligned to device's
// ioAlignmentSize_, IO aligned offset and IO aligned size are determined
// and passed to device read. Upon successful read from the device, the
// buffer is adjusted to return the intended data by trimming the data in
// the front and back.
// An empty buffer is returned in case of error and the caller must check
// the buffer size returned with size passed in to check for errors.
Buffer Device::read(uint64_t offset, uint32_t size) {
  XDCHECK_LE(offset + size, size_);
  uint64_t readOffset =
      offset & ~(static_cast<uint64_t>(ioAlignmentSize_) - 1ul);
  uint64_t readPrefixSize =
      offset & (static_cast<uint64_t>(ioAlignmentSize_) - 1ul);
  auto readSize = getIOAlignedSize(readPrefixSize + size);
  auto buffer = makeIOBuffer(readSize);
  bool result = readInternal(readOffset, readSize, buffer.data());
  if (!result) {
    return Buffer{};
  }
  buffer.trimStart(readPrefixSize);
  buffer.shrink(size);
  return buffer;
}

// This API reads size bytes from the Device from the offset into value.
// Both offset and size are expected to be IO aligned.
bool Device::read(uint64_t offset, uint32_t size, void* value) {
  return readInternal(offset, size, value);
}

void Device::getCounters(const CounterVisitor& visitor) const {
  visitor("navy_device_bytes_written", getBytesWritten());
  visitor("navy_device_bytes_read", getBytesRead());
  readLatencyEstimator_.visitQuantileEstimator(visitor,
                                               "navy_device_read_latency_us");
  writeLatencyEstimator_.visitQuantileEstimator(visitor,
                                                "navy_device_write_latency_us");
  visitor("navy_device_read_errors", readIOErrors_.get());
  visitor("navy_device_write_errors", writeIOErrors_.get());
  visitor("navy_device_encryption_errors", encryptionErrors_.get());
  visitor("navy_device_decryption_errors", decryptionErrors_.get());
}

std::unique_ptr<Device> createFileDevice(
    folly::File file,
    uint64_t size,
    std::shared_ptr<DeviceEncryptor> encryptor) {
  return std::make_unique<FileDevice>(std::move(file), size, 0,
                                      std::move(encryptor),
                                      0 /* max device write size */);
}

std::unique_ptr<Device> createDirectIoFileDevice(
    folly::File file,
    uint64_t size,
    uint32_t ioAlignSize,
    std::shared_ptr<DeviceEncryptor> encryptor,
    uint32_t maxDeviceWriteSize) {
  XDCHECK(folly::isPowTwo(ioAlignSize));
  return std::make_unique<FileDevice>(std::move(file), size, ioAlignSize,
                                      std::move(encryptor), maxDeviceWriteSize);
}

std::unique_ptr<Device> createDirectIoZNSDevice(
  std::string fileName,
  uint64_t size,
  uint64_t regionSize,
  uint32_t ioAlignSize,
  std::shared_ptr<DeviceEncryptor> encryptor,
  uint32_t maxDeviceWriteSize) {

  int flags{O_RDWR | O_DIRECT};
  int fd, ret;
  uint32_t numZones = 0;
  uint64_t zoneSize = 0;
  uint64_t capSize, actDevSize;
  int count;
  struct blk_zone_report *rep;
  struct blk_zone *log;
  size_t rep_size;

  rep_size = sizeof(struct blk_zone_report) +
    (sizeof(struct blk_zone) * MAX_NO_OF_ZONES);
  rep = (struct blk_zone_report *) new char[rep_size];

  memset(rep, 0, rep_size);
  // Open the device, get number of zones,
  // get zone log information and zone size
  if ((fd = ::open(fileName.c_str(), flags, 0666)) < 0)
    throw std::invalid_argument(folly::sformat("Cannot open zoned device"));

  ret = ::ioctl(fd, BLKGETNRZONES, &numZones);
  if (ret < 0 || !numZones)
    throw std::invalid_argument(folly::sformat("Cannot get number of zones."
        "Not a zoned device?"));

  rep->sector = 0;
  rep->nr_zones = numZones;
  ret = ::ioctl(fd, BLKREPORTZONE, rep);
  if (ret < 0)
    throw std::invalid_argument(folly::sformat("Cannot get report of zones"));

  ret = ::ioctl(fd, BLKGETZONESZ, &zoneSize);
  if (ret < 0)
    throw std::invalid_argument(folly::sformat("Cannot get zone size"));

  // SECTOR SHIFT is for 512 bytes
  zoneSize <<= SECTOR_SHIFT;
  log = rep->zones;
  numZones = rep->nr_zones;

  // Zone has two length information
  // zone size - Size of the zone
  // zone capacity - Actual Capacity of zone
  // Capacity of the zone can be lesser than zone size
  // Here we add all the capapcities to get the actual
  // device size
  for (count =0, actDevSize = 0; count < numZones; count++) {
    uint64_t zone_capacity_size;

    if (*((uint32_t*)rep->reserved) & 0x01)
      zone_capacity_size = *((uint64_t*)&log[count].reserved[4])
                                            << SECTOR_SHIFT;
    else
      zone_capacity_size = log[count].len << SECTOR_SHIFT;
    actDevSize += zone_capacity_size;
  }

  // Get capacity to map region size
  for (count =0, capSize = 0; count < numZones; count++) {
    uint64_t zone_capacity_size;

    if (*((uint32_t*)rep->reserved) & 0x01)
      zone_capacity_size = *((uint64_t*)&log[count].reserved[4])
                                              << SECTOR_SHIFT;
    else
      zone_capacity_size = log[count].len << SECTOR_SHIFT;
    if (!capSize || zone_capacity_size)
          capSize = zone_capacity_size;
  }

  // Currently region size is equal to zone capacity
  // TODO: manage region size not equal to zone capacity
  if (regionSize != capSize)
    throw std::invalid_argument(
      folly::sformat("Region Size should be alligned to"
                          " ZNS capacity size {} MB: ", capSize/(1024 * 1024)));

  // If size is not given,
  // then use the device size.
  if (!size)
    size = actDevSize;

  if (size > actDevSize)
    throw std::invalid_argument(
      folly::sformat("Size should be alligned to ZNS drive:"
                  "drive size {} MB", actDevSize/(1024 * 1024)));

  // Size should align to zone capacity
  if (size % capSize)
    throw std::invalid_argument(
      folly::sformat("Size should be alligned to ZNS drive: capacity {} MB:"
                            "Needed Size: {} MB", capSize/(1024 * 1024),
                            (((size/ capSize) + 1) * capSize)/(1024 * 1024)));

  // We can use the full device or part of the device
  if (size < actDevSize)
    numZones = size/capSize;

  return std::make_unique<ZNSDevice>(std::move(fd),
                                    size, ioAlignSize,
                                    std::move(zoneSize),
                                    std::move(capSize),
                                    std::move(log),
                                    std::move(rep),
                                    std::move(encryptor),
                                    maxDeviceWriteSize );
}

std::unique_ptr<Device> createDirectIoRAID0Device(
    std::vector<folly::File> fvec,
    uint64_t size, // size of each device in the RAID
    uint32_t ioAlignSize,
    uint32_t stripeSize,
    std::shared_ptr<DeviceEncryptor> encryptor,
    uint32_t maxDeviceWriteSize) {
  XDCHECK(folly::isPowTwo(ioAlignSize));
  return std::make_unique<RAID0Device>(std::move(fvec), size, ioAlignSize,
                                       stripeSize, std::move(encryptor),
                                       maxDeviceWriteSize);
}

std::unique_ptr<Device> createMemoryDevice(
    uint64_t size,
    std::shared_ptr<DeviceEncryptor> encryptor,
    uint32_t ioAlignSize) {
  return std::make_unique<MemoryDevice>(size, std::move(encryptor),
                                        ioAlignSize);
}
} // namespace navy
} // namespace cachelib
} // namespace facebook
