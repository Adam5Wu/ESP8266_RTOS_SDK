#!/usr/bin/env python3
# Copyright 2026 Adam5Wu (ESP8266_RTOS_SDK OSS contributors)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Stamp the current UTC date (YYYY-MM-DD) and time (HH:MM:SS UTC) into
esp_app_desc_t inside a linked ESP8266 ELF32 binary.

Designed to run as a post-link step on the application ELF (before elf2image):
  - No-op builds skip linking and therefore skip stamping (fully cached).
  - Incremental builds that relink the ELF stamp a fresh UTC timestamp right
    before elf2image generates the final .bin (and its SHA-256 / checksum).
  - Honors SOURCE_DATE_EPOCH when set for reproducible builds.
"""

from datetime import datetime, timezone
import os
import struct
import sys

ESP_APP_DESC_MAGIC_WORD = 0xABCD5432
ESP_APP_DESC_SIZE = 256
ESP_APP_DESC_TIME_OFFSET = 80
ESP_APP_DESC_TIME_SIZE = 16
ESP_APP_DESC_DATE_OFFSET = 96
ESP_APP_DESC_DATE_SIZE = 16

ELF_MAGIC = b"\x7fELF"
ELFCLASS32 = 1
ELFDATA2LSB = 1
SHT_SYMTAB = 2
FLASH_RODATA_DESC_OFFSET = 8


def _read_cstr(blob, offset):
    end = blob.find(b"\x00", offset)
    if end == -1:
        return blob[offset:]
    return blob[offset:end]


def _parse_elf32_sections(data):
    if len(data) < 52:
        raise ValueError("File too small to be an ELF32 binary")
    e_ident = data[:16]
    if e_ident[:4] != ELF_MAGIC or e_ident[4] != ELFCLASS32 or e_ident[5] != ELFDATA2LSB:
        raise ValueError("Unsupported ELF format (expected 32-bit little-endian ELF)")

    (
        _e_type,
        _e_machine,
        _e_version,
        _e_entry,
        _e_phoff,
        e_shoff,
        _e_flags,
        _e_ehsize,
        _e_phentsize,
        _e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)

    if e_shoff == 0 or e_shnum == 0 or e_shentsize < 40:
        raise ValueError("ELF contains no section headers")

    sections = []
    for idx in range(e_shnum):
        off = e_shoff + idx * e_shentsize
        fields = struct.unpack_from("<IIIIIIIIII", data, off)
        sections.append(
            {
                "sh_name": fields[0],
                "sh_type": fields[1],
                "sh_flags": fields[2],
                "sh_addr": fields[3],
                "sh_offset": fields[4],
                "sh_size": fields[5],
                "sh_link": fields[6],
                "sh_info": fields[7],
                "sh_addralign": fields[8],
                "sh_entsize": fields[9],
            }
        )

    shstr = sections[e_shstrndx]
    shstr_blob = data[shstr["sh_offset"] : shstr["sh_offset"] + shstr["sh_size"]]
    for sec in sections:
        sec["name"] = _read_cstr(shstr_blob, sec["sh_name"])

    return sections


def _find_esp_app_desc_offset(data):
    sections = _parse_elf32_sections(data)

    # Primary lookup: locate the global `esp_app_desc` symbol in .symtab.
    for sec in sections:
        if sec["sh_type"] != SHT_SYMTAB or sec["sh_entsize"] < 16:
            continue
        strtab_idx = sec["sh_link"]
        if strtab_idx >= len(sections):
            continue
        strtab = sections[strtab_idx]
        str_blob = data[strtab["sh_offset"] : strtab["sh_offset"] + strtab["sh_size"]]
        count = sec["sh_size"] // sec["sh_entsize"]
        for i in range(count):
            ent_off = sec["sh_offset"] + i * sec["sh_entsize"]
            st_name, st_value, st_size, _st_info, _st_other, st_shndx = struct.unpack_from(
                "<IIIBBH", data, ent_off
            )
            if _read_cstr(str_blob, st_name) != b"esp_app_desc":
                continue
            if st_size != ESP_APP_DESC_SIZE:
                raise ValueError(
                    "esp_app_desc symbol size mismatch: expected %d, got %d"
                    % (ESP_APP_DESC_SIZE, st_size)
                )
            if not (0 < st_shndx < len(sections)):
                raise ValueError("esp_app_desc has invalid section index %d" % st_shndx)
            target_sec = sections[st_shndx]
            if st_value < target_sec["sh_addr"]:
                raise ValueError("esp_app_desc address precedes its section")
            file_off = target_sec["sh_offset"] + (st_value - target_sec["sh_addr"])
            if file_off + ESP_APP_DESC_SIZE > len(data):
                raise ValueError("esp_app_desc extends past end of ELF")
            return file_off

    # Fallback for stripped ELFs: esp8266.project.ld places .rodata_desc at .flash.rodata + 0x8.
    for sec in sections:
        if sec["name"] == b".flash.rodata":
            file_off = sec["sh_offset"] + FLASH_RODATA_DESC_OFFSET
            if file_off + ESP_APP_DESC_SIZE <= len(data):
                magic = struct.unpack_from("<I", data, file_off)[0]
                if magic == ESP_APP_DESC_MAGIC_WORD:
                    return file_off

    raise ValueError("Could not locate esp_app_desc in ELF")


def _get_utc_datetime():
    source_date_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if source_date_epoch:
        return datetime.fromtimestamp(int(source_date_epoch), tz=timezone.utc)
    return datetime.now(timezone.utc)


def stamp_elf(elf_path):
    with open(elf_path, "rb") as fp:
        data = bytearray(fp.read())

    file_off = _find_esp_app_desc_offset(data)
    magic = struct.unpack_from("<I", data, file_off)[0]
    if magic != ESP_APP_DESC_MAGIC_WORD:
        raise ValueError(
            "Invalid esp_app_desc magic at 0x%x: expected 0x%08x, got 0x%08x"
            % (file_off, ESP_APP_DESC_MAGIC_WORD, magic)
        )

    dt = _get_utc_datetime()
    date_str = dt.strftime("%Y-%m-%d")
    time_str = dt.strftime("%H:%M:%S UTC")

    date_bytes = date_str.encode("ascii")
    time_bytes = time_str.encode("ascii")
    if len(date_bytes) >= ESP_APP_DESC_DATE_SIZE:
        raise ValueError("Formatted date too long for esp_app_desc_t.date[16]")
    if len(time_bytes) >= ESP_APP_DESC_TIME_SIZE:
        raise ValueError("Formatted time too long for esp_app_desc_t.time[16]")

    padded_time = time_bytes.ljust(ESP_APP_DESC_TIME_SIZE, b"\x00")
    padded_date = date_bytes.ljust(ESP_APP_DESC_DATE_SIZE, b"\x00")

    data[
        file_off + ESP_APP_DESC_TIME_OFFSET : file_off
        + ESP_APP_DESC_TIME_OFFSET
        + ESP_APP_DESC_TIME_SIZE
    ] = padded_time
    data[
        file_off + ESP_APP_DESC_DATE_OFFSET : file_off
        + ESP_APP_DESC_DATE_OFFSET
        + ESP_APP_DESC_DATE_SIZE
    ] = padded_date

    with open(elf_path, "wb") as fp:
        fp.write(data)

    return date_str, time_str


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("Usage: %s <app.elf>\n" % argv[0])
        return 2

    elf_path = argv[1]
    try:
        date_str, time_str = stamp_elf(elf_path)
    except Exception as exc:
        sys.stderr.write("stamp_app_desc.py: failed to stamp %s: %s\n" % (elf_path, exc))
        return 1

    print("Stamped esp_app_desc build time: %s %s" % (date_str, time_str))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
