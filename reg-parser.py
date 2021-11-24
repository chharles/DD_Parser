#ddparser-reg
#uses regular expresion
#part of Project2 for Digital Forensics Course
import pathlib
import argparse
import re

filetype_signatures= {
    "MPG1":{
        "header":rb"\x00\x00\x01\xB3",
        "trailer":rb"\x00\x00\x01\xB7"},
    "MPEG-1 CD":{
        "header":rb"\x52\x49\x46\x46",
        "trailer":None},
    "MPEG-2 DVD":{
        "header":rb"\x00\x00\x01\xBA",
        "trailer":rb"\x00\x00\x01\xB9"},
    "MPEG-3 ID3":{
        "header":rb"\x49\x44\x33",
        "trailer":None},
    "MPEG-3 ftypM4A":{
        "header":rb"\x66\x74\x79\x70\x4D\x34\x41\x20",
        "trailer":None},
    "MPEG-4 MP4":{
        "header":rb"\x66\x74\x79\x70\x6D\x70\x34\x32",
        "trailer":None},
    "PDF1":{
        "header":rb"\x25\x50\x44\x46",
        "trailer":rb"\x0A\x25\x45\x4F\x46"}, # watch out for pdfs, there may be multiple eof marks within the file. GET THE LAST ONE 
    "PDF2":{
        "header":rb"\x25\x50\x44\x46",
        "trailer":rb"\x0A\x25\x45\x4F\x46\x0A"},
    "PDF3":{
        "header":rb"\x25\x50\x44\x46",
        "trailer":rb"\x0D\x0A\x25\x45\x4F\x46\x0D\x0A"},
    "PDF4":{
        "header":rb"\x25\x50\x44\x46",
        "trailer":rb"\x0D\x25\x25\x45\x4F\x0D"},
    "BMP":{
        "header":rb"\x42\x4D....",
        "trailer":None},
    "GIF87a":{
        "header":rb"\x47\x49\x46\x38\x37\x61",
        "trailer":rb"\x00\x3B"},
    "GIF89a":{
        "header":rb"\x47\x49\x46\x38\x39\x61",
        "trailer":rb"\x00\x3B"},
    "Standard JPEG":{
        "header":rb"\xFF\xD8\xFF\xE0",
        "trailer":rb"\xFF\xD9"},
    "JPEG with Exif metadata":{
        "header":rb"\xFF\xD8\xFF\xE1",
        "trailer":rb"\xFF\xD9"},
    "CIFF JPEG":{
        "header":rb"\xFF\xD8\xFF\xE2",
        "trailer":rb"\xFF\xD9"},
    "SPIFF JPEG":{
        "header":rb"\xFF\xD8\xFF\xE8",
        "trailer":rb"\xFF\xD9"},
    "DOCX":{
        "header":rb"\x50\x4B\x03\x04\x14\x00\x06\x00",
        "trailer":rb"\x50\x4B\x05\x06.{18}"},
    "AVI":{
        "header":rb"\x52\x49\x46....\x41\x56\x49\x20\x4C\x49\x53\x54",
        "trailer":None},
    "PNG":{
        "header":rb"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",
        "trailer":rb"\x49\x45\x4E\x44\xAE\x42\x60\x82"},
}

def compile_filetype_signatures(filetype_signatures):
    filetype_pattern = {}
    for filetype, signatures in filetype_signatures.items():
        header_pattern = re.compile(signatures["header"])
        trailer_pattern = None
        if signatures["trailer"]:
            trailer_pattern = re.compile(signatures["trailer"])
        filetype_pattern[filetype] = {"header":header_pattern, "trailer":trailer_pattern}
    return filetype_pattern

filetype_patterns = compile_filetype_signatures(filetype_signatures)

def create_matches_profile(filetype_patterns):
    matches_profile = {} #{"test":{"pattern":(header, trailer),"matches":[]}}
    for filetype, signatures in filetype_patterns.items():
        header = signatures["header"]
        trailer = signatures["trailer"]
        matches_profile[filetype] = {"pattern":(header, trailer), "matches":[]}
    return matches_profile

# find_signatures
def find_signatures(disk_image):
    global filetype_patterns
    image = ""

    if not disk_image.exists(): # looks for the provided disk image 
        print("ERROR: could not find the provided file")
        return None
    with open(disk_image, 'rb') as f:
        image = f.read()

    current_position = 0
    matches_profile = create_matches_profile(filetype_patterns)

    # while True:
    #     match = test.search(image[current_position:])
    #     if match is None:
    #         break
    #     matches["test"]["matches"].append(current_position+match.start())
    #     current_position += match.end()
    # print(matches)
    return None

def parse(disk_image):

    # find the signature
    ## for each signature in the signature list, we want to check for ALL matches of each signature type
    ## when we find a match, there's a good chance that that file exists within the disk image
    # find the starting point of the signature

    # find the end of the file
    # extract the file
    # take the hash of the file
    # analyze the file
    return None


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
    disk_image = pathlib.Path(args.diskimage) 
    find_signatures(disk_image)
    return 0




if __name__ == "__main__":
    main()

