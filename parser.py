#part of Project2 for Digital Forensics Course
import pathlib
import argparse
import math

HEX_CHARS = "0123456789ABCDEF"
test = b"\x50\x4B\x03\x04\x14\x00\x06\x00"
signature_headers = {"MPEG Video File": "00 00 01 Bx",
    "DVD Video Movie File": "00 00 01 BA",
    "MPG":"FF F*",
    "PDF":"25 50 44 46",
    "BMP":"",
    "GIF":"47 49 46 38 3* 61",
    "ZIP":"50 4B 03 04",
    "JPG":"FF D8 FF E*",
    "DOCX":"50 4B 03 04 14 00 06 00",
    "AVI":"",
    "PNG":"89 50 4E 47 0D 0A 1A 0A",
    "EXE":"4D 5A"
} # need to figure out about wildcards - may have to do string representations as opposed to actual bytes
sigature_trailers = { 
    "JPG":"FF D9",
}


#gets the string representation of a byte or set of bytes
def convert_byte_to_str(b):
    byte_str = ""
    for by in b:
        byte_str += hex(by)[2:].zfill(2)
    return byte_str

#returns the sector of a given byte offset
def find_sector_of_byte_offset(offset):
    return math.ceil(offset/512)


#converts a set of bytes (little endian) to their integer equivalent 
def convert_bytes_to_int(bs):
    byte_str_to_convert = ""
    for b in bs:
        byte_str_to_convert = convert_byte_to_str(b) + byte_str_to_convert
    return int(byte_str_to_convert, 16)

# is_in_signature
# 
# Description:
#   checks if a given byte string is in a file signature
# Returns:
#   returns 0 if it is not in the file signature, 
#   returns 1 if the byte string is in the file signature
#   returns 2 if the byte string is the file signature
def is_in_signature(byte_str):
    for typ, sig in signature_headers.items():
        if sig.startswith(byte_str):
            if sig == byte_str:
                return 2
            return 1
    return 0

#
def parse(disk_image):
    print(f"Parsing {disk_image}")
    with open(disk_image, 'rb') as f: # if the image exists, start parsing.
        bytes_at_offset = ""
        test_bytes = f.read(1)
        start = end = 1
        while (test_bytes != ""):
            if bytes_at_offset != "":
                bytes_at_offset = bytes_at_offset + " " + convert_byte_to_str(test_bytes) 
            else:
                bytes_at_offset = convert_byte_to_str(test_bytes)
            end += 1 # increment the counter (offset)
            res =  is_in_signature(bytes_at_offset)
            if res == 0: # if the byte is not in the file signature, we set the start to end, and clear the byte string being observed
                start=end
                bytes_at_offset = ""
            elif res == 2:
                print(f"Found file signature at byte offset {start}")
                print(f"Sector: {find_sector_of_byte_offset(start)}")
                print("Signature: ", bytes_at_offset)
                start_of_file = True
            test_bytes=f.read(1)


def get_args():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('-d',
        "--diskimage", 
        help="The Disk Image you want to parse",
        required=True
    )
    return argparser.parse_args()

def main():
    args = get_args()
    MAX_SIG_LEN = 0
    for typ, sig in signature_headers.items():
        b_count = len(sig.split(" "))
        MAX_SIG_LEN = b_count if b_count > MAX_SIG_LEN else MAX_SIG_LEN
    disk_image = pathlib.Path(args.diskimage) 
    if not disk_image.exists(): # looks for the provided disk image 
        print("ERROR: could not find the provided file")
        return 1
    parse(disk_image)




if __name__ == "__main__":
    main()

