#!/usr/bin/python
#
# created by Adam Laurie <adam@algroup.co.uk>
# based on Josh's work at:
# https://boredpentester.com/reversing-esp8266-firmware-part-4/
 
import sys
import struct
from struct import unpack_from

def main():

    li= open(sys.argv[1],"rb")
    li.seek(0)
 
    # load ROM segment
    (magic, segments, flash_mode, flash_size_freq, entrypoint) = struct.unpack(b'<BBBBI', li.read(8))
 
    print( "Reading ROM boot firmware @ 0x00")
    print( "Magic: %x" % magic)
    print( "Segments: %x" % segments)
    print( "Entry point: %x" % entrypoint)
    print( "\n")

    print( "Looping for bootloader")
       
    for k in range(segments):
 
        print( "\n")
        (seg_addr, seg_size) = unpack_from("<II",li.read(8))
        file_offset = li.tell()
 
        if(seg_addr == 0x40100000):
            seg_name = ".user_rom"
            seg_type = "CODE"
        elif(seg_addr == 0x3FFE8000):
            seg_name = ".user_rom_data"
            seg_type = "DATA"
        elif(seg_addr <= 0x3FFFFFFF):
            seg_name = ".data_seg_%d" % k
            seg_type = "DATA"
        elif(seg_addr > 0x40100000):
            seg_name = ".code_seg_%d" % k
            seg_type = "CODE"
        else:
            seg_name = ".unknown_seg_%d" % k
            seg_type = "CODE"
 
        print( "Seg name: %s" % seg_name)
        print( "Seg type: %s" % seg_type)
        print( "Seg address: %x" % seg_addr)
        print( "Seg size: %x" % seg_size)
        print( "File offset: %x" % file_offset)
        print( "Next segment: %x" % (file_offset + seg_size))

        dumpfile= '%s' % (sys.argv[1] + seg_name + ('-bl-0x%x' % seg_addr))
        print("saving %s" % dumpfile)
        lo= open(dumpfile, "wb")
        lo.write(li.read(seg_size))
        lo.close()
 
 
 
    #(rom_addr, rom_size) = struct.unpack("<II",li.read(8))
    #li.file2base(16, rom_addr, rom_addr+rom_size, True)
    #add_segm(0, rom_addr, rom_addr+rom_size, ".boot_rom", "CODE")
    #idaapi.add_entry(0, entrypoint, "rom_entry", 1)
 
    #print( "Reading 1st stage boot loader code @ 0x1000")
    #print( "ROM address: %x" % rom_addr)
    #print( "ROM size: %x" % rom_size)
    #print( "\n")
 
    # Go to user ROM code
    li.seek(0x1000, 0)
 
    # load ROM segment
    (magic, segments, flash_mode, flash_size_freq, entrypoint) = unpack_from('<BBBBI', li.read(8))
    print( "Magic: %x" % magic)
    print( "Segments: %x" % segments)
    print( "Entry point: %x" % entrypoint)
    print( "\n")
    #idaapi.add_entry(1, entrypoint, "user_entry", 1)

    print( "Looping for user code")
       
    for k in range(segments):
 
        print( "\n")
        (seg_addr, seg_size) = unpack_from("<II",li.read(8))
        file_offset = li.tell()
 
        if(seg_addr == 0x40100000):
            seg_name = ".user_rom"
            seg_type = "CODE"
        elif(seg_addr == 0x3FFE8000):
            seg_name = ".user_rom_data"
            seg_type = "DATA"
        elif(seg_addr <= 0x3FFFFFFF):
            seg_name = ".data_seg_%d" % k
            seg_type = "DATA"
        elif(seg_addr > 0x40100000):
            seg_name = ".code_seg_%d" % k
            seg_type = "CODE"
        else:
            seg_name = ".unknown_seg_%d" % k
            seg_type = "CODE"
 
        print( "Seg name: %s" % seg_name)
        print( "Seg type: %s" % seg_type)
        print( "Seg address: %x" % seg_addr)
        print( "Seg size: %x" % seg_size)
        print( "File offset: %x" % file_offset)
        print( "Next segment: %x" % (file_offset + seg_size))

        dumpfile= '%s' % (sys.argv[1] + seg_name + ('-0x%x' % seg_addr))
        print("saving %s" % dumpfile)
        lo= open(dumpfile, "wb")
        lo.write(li.read(seg_size))
        lo.close()
 
        #li.file2base(file_offset, seg_addr, seg_addr+seg_size, True)
        #add_segm(0, seg_addr, seg_addr+seg_size, seg_name, seg_type)
         
        li.seek(file_offset+seg_size, 0)
        print( "checking %x" % (file_offset+seg_size))
        magic = unpack_from('<B', li.read(1))
        if(magic[0] == 0xe9):
            (segments, flash_mode, flash_size_freq, entrypoint) = unpack_from('<BBBI', li.read(7))
            print( "Magic: %x" % magic)
            print( "Segments: %x" % segments)
            print( "Entry point: %x" % entrypoint)
            print( "\n")
        else:
            print( "no magic %x" % magic)
            li.seek(file_offset+seg_size, 0)
 
    return 1

if __name__ == "__main__":
    main()
