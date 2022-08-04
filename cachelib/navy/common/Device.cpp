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
#include "libzbd/zbd.h"

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

  bool finishImpl(uint64_t offset, uint32_t len) {
    return true;
  }

  bool resetImpl(uint64_t offset, uint32_t size) override {
	return true;
  }

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

  bool finishImpl(uint64_t offset, uint32_t len) {
    return true;
  }

  bool resetImpl(uint64_t offset, uint32_t size) override {
	return true;
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

  bool finishImpl(uint64_t offset, uint32_t len) {
    return true;
  }

  void flushImpl() override {
    // Noop
  }

  bool resetImpl(uint64_t offset, uint32_t size) override {
	return true;
  }

  std::unique_ptr<uint8_t[]> buffer_;
};

// ZNS Device
class ZNSDevice : public Device {
  public:
    explicit ZNSDevice(int dev,
    struct zbd_info *info,
    struct zbd_zone *report,
    uint32_t nr_zones,
    uint64_t zoneMask,
    uint64_t size,
    uint32_t ioAlignSize,
    uint64_t ioZoneCapSize,
    uint64_t ioZoneSize,
    std::shared_ptr<DeviceEncryptor> encryptor,
    uint32_t maxDeviceWriteSize)
    : Device{size, std::move(encryptor), ioAlignSize,
    maxDeviceWriteSize, nr_zones,
           ioZoneSize, ioZoneCapSize},
    dev_{std::move(dev)},
    info_{info},
    report_{std::move(report)},
    nr_zones_{std::move(nr_zones)},
    zoneMask_ {std::move(zoneMask)},
    ioZoneCapSize_{std::move(ioZoneCapSize)}
    {
    }
    ZNSDevice(const ZNSDevice&) = delete;
    ZNSDevice& operator=(const ZNSDevice&) = delete;

    ~ZNSDevice() override = default;

  private:
    const int dev_{};
    struct zbd_info *info_;
    struct zbd_zone *report_;
    unsigned int nr_zones_;
    unsigned int zoneMask_;
    uint64_t ioZoneCapSize_;

    bool finishImpl(uint64_t offset, uint32_t len) override{
      if (zbd_finish_zones(dev_, offset, len) < 0)
        return false;
      return true;
    }

    bool resetImpl(uint64_t offset, uint32_t len) override{
      if (!finishImpl(offset, len))
        return false;
      if (zbd_reset_zones(dev_, offset, len) < 0)
        return false;
      return true;
    }

    bool writeImpl(uint64_t offset, uint32_t size, const void* value) override {
      ssize_t bytesWritten;

      bytesWritten = ::pwrite(dev_, value, size, offset);
      if (bytesWritten != size)
        XLOG(INFO) << "Error Writing to zone! offset" << offset
          << " size: " << size << " bytesWritten: " << bytesWritten;
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
    uint32_t ioAlignSize,
    std::shared_ptr<DeviceEncryptor> encryptor,
    uint32_t maxDeviceWriteSize) {

   struct zbd_zone *report;
   struct zbd_info *info;
    int flags{O_RDWR | O_DIRECT};
    int fd, ret;
    uint32_t nr_zones, zoneMask;
    uint64_t ioZoneCapSize, actDevSize;
     int count;

    info = new zbd_info();
    fd = zbd_open(fileName.c_str(), flags, info);
    if (fd <0) {
         XLOG(ERR) << "Exception in zns device: " << errno;
    }

    ret = zbd_list_zones(fd,
                     0, 0, ZBD_RO_ALL,
                     &report, &nr_zones);
    if (ret < 0 || !nr_zones) {
           XLOG(ERR) << "report zone " << nr_zones;
    }

    for (count =0, actDevSize = 0; count < nr_zones; count++)
        actDevSize += report[count].capacity;

    /* minimum zone capacity */
    /* TODO: Done for region size,
    we should be able to map each region to different size */
    for (count =0, ioZoneCapSize = 0; count < nr_zones; count++)
      if (!ioZoneCapSize || ioZoneCapSize > report[count].capacity)
            ioZoneCapSize = report[count].capacity;

   if (size > actDevSize)
    throw std::invalid_argument(
      folly::sformat("Size should be alligned to ZNS drive: drive size {} MB", actDevSize/(1024 * 1024)));

    if (size % ioZoneCapSize)
     throw std::invalid_argument(
       folly::sformat("Size should be alligned to ZNS drive: capacity {} MB: Needed Size: {} MB", ioZoneCapSize/(1024 * 1024),
         (((size/ ioZoneCapSize) + 1) * ioZoneCapSize)/(1024 * 1024)));

    if (size < actDevSize)
        nr_zones = size/ioZoneCapSize;
    zoneMask = info->zone_size - 1;

    return std::make_unique<ZNSDevice>(std::move(fd), std::move(info),
                                      std::move(report), std::move(nr_zones),
                                      zoneMask, size, ioAlignSize,
                                      ioZoneCapSize,zoneMask + 1,
                                      std::move(encryptor),
                                      maxDeviceWriteSize /* max device write size */);
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
