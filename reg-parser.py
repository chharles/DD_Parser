#ddparser-reg
#uses regular expresion
#part of Project2 for Digital Forensics Course
import pathlib
import argparse
import re
import hashlib

filetype_signatures= {
    "MPG":{
        "extension":".mpg",
        "header":rb"\x00\x00\x01\xB3.\x00",
        "trailer":[rb"\x00\x00\x00\x01\xB7"]},
    "MPEG-2 DVD":{
        "extension":".mpg",
        "header":rb"\x00\x00\x01\xBA.\x00",
        "trailer":[rb"\x00\x00\x00\x01\xB9"]},
    "PDF":{
        "extension":".pdf",
        "header":rb"\x25\x50\x44\x46",
        "trailer":[rb"\x0A\x25\x25\x45\x4F\x46", rb"\x0A\x25\x25\x45\x4F\x46\x0A", rb"\x0D\x0A\x25\x25\x45\x4F\x46\x0D\x0A", rb"\x0D\x25\x25\x45\x4F\x0D"]}, # watch out for pdfs, there may be multiple eof marks within the file. GET THE LAST ONE 
    "BMP":{
        "extension":".bmp",
        "header":rb"\x42\x4D....\x00\x00\x00\x00",
        "trailer":None},
    "GIF87a":{
        "extension":".gif",
        "header":rb"\x47\x49\x46\x38\x37\x61",
        "trailer":[rb"\x00\x00\x3B"]},
    "GIF89a":{
        "extension":".gif",
        "header":rb"\x47\x49\x46\x38\x39\x61",
        "trailer":[rb"\x00\x00\x3B"]},
    "Standard JPEG":{
        "extension":".jpg",
        "header":rb"\xFF\xD8\xFF\xE0",
        "trailer":[rb"\xFF\xD9"]},
    "JPG":{
        "extension":".jpg",
        "header":rb"\xFF\xD8\xFF\xDB",
        "trailer":[rb"\xFF\xD9"]},
    "JPEG with Exif metadata":{
        "extension":".jpg",
        "header":rb"\xFF\xD8\xFF\xE1",
        "trailer":[rb"\xFF\xD9"]},
    "CIFF JPEG":{
        "extension":".jpg",
        "header":rb"\xFF\xD8\xFF\xE2",
        "trailer":[rb"\xFF\xD9"]},
    "SPIFF JPEG":{
        "extension":".jpg",
        "header":rb"\xFF\xD8\xFF\xE8",
        "trailer":[rb"\xFF\xD9"]},
    "DOCX":{
        "extension":".docx",
        "header":rb"\x50\x4B\x03\x04\x14\x00\x06\x00",
        "trailer":[rb"\x50\x4B\x05\x06.{18}"]},
    "AVI":{
        "extension":".avi",
        "header":rb"\x52\x49\x46\x46....\x41\x56\x49\x20\x4C\x49\x53\x54",
        "trailer":None},
    "PNG":{
        "extension":".png",
        "header":rb"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",
        "trailer":[rb"\x49\x45\x4E\x44\xAE\x42\x60\x82"]},
}

filetype_length_bytes = {
    "BMP":{
        "start":2, "end":5},
    "AVI":{
        "start":4, "end":7},
    }

def compile_filetype_signatures(filetype_signatures):
    filetype_pattern = {}
    for filetype, signatures in filetype_signatures.items():
        header_pattern = re.compile(signatures["header"])
        trailers = []
        if signatures["trailer"]:
            for trailer in signatures["trailer"]:
                trailers.append(re.compile(trailer))
        if len(trailers) <= 0:
            trailers = None
        filetype_pattern[filetype] = {
            "header":header_pattern, 
            "trailer":trailers, 
            "extension":signatures["extension"]} 
    return filetype_pattern

filetype_patterns = compile_filetype_signatures(filetype_signatures)

# find_signatures
def find_files(disk_image):
    global filetype_patterns
    image = ""

    if not disk_image.exists(): # looks for the provided disk image 
        print("ERROR: could not find the provided file")
        return None
    with open(disk_image, 'rb') as f:
        image = f.read()

    for filetype, patterns in filetype_patterns.items():
        header = patterns["header"]
        trailers = patterns["trailer"]
        patterns["matches"] = []
        current_position = 0
        match_found = False

        if "PDF" in filetype:
            pdf_header_locations = []
            header_match = header.search(image)
            current_position = 0
            while header_match != None:
                pdf_header_locations.append(current_position+header_match.start())
                current_position += header_match.end()
                header_match = header.search(image[current_position:])
            for i in range(len(pdf_header_locations)):
                end_position = len(image)
                if i + 1 < len(pdf_header_locations):
                    end_position = pdf_header_locations[i+1]
                current_position = pdf_header_locations[i]
                trailer_match_locations = []
                for trailer in trailers:
                    trailer_match = trailer.search(image[current_position:end_position])
                    while trailer_match != None:
                        trailer_match_locations.append(current_position+trailer_match.end())
                        current_position += trailer_match.end()
                        trailer_match = trailer.search(image[current_position:end_position])
                    current_position = pdf_header_locations[i]
                trailer_match_locations.sort()
                length = trailer_match_locations[-1] - pdf_header_locations[i]
                patterns["matches"].append({
                    "start":pdf_header_locations[i],
                    "end":trailer_match_locations[-1],
                    "length":length})                
                    
        else:

            while True:
                header_match = header.search(image[current_position:])
                if header_match is None: break # if we don't find the header in the image
                header_pos = current_position+header_match.start() # where the header is in the disk image
                trailer_match = None

                if trailers: # if there is a trailer for this filetype
                    length = 0
                    match_found = False
                    for trailer in trailers:
                        trailer_match = trailer.search(image[header_pos+length:]) # search for the first trailer
                        if trailer_match is None:
                            continue # if we reach the end of the file and a trailer match has not been found, no file exists
                        # we have found a potential match based off of the header and the footer
                        length = trailer_match.end() + length
                        match_found = True
                    if not match_found: # if no matches were found
                        break
                    patterns["matches"].append({
                        "start":header_pos,
                        "end":header_pos+length,
                        "length":length})
                    current_position += header_pos+length

                else: # if there is no trailer for the filetype
                    match = header_match.group(0)
                    length_info = filetype_length_bytes[filetype]
                    start = length_info["start"]
                    end = length_info["end"] 
                    length_bytes = match[start:end+1]
                    length = int.from_bytes(length_bytes, byteorder='little')
                    if "AVI" in filetype:
                        length += 8
                    patterns["matches"].append({
                        "start":header_pos, 
                        "end":header_pos+length, 
                        "length":length})
                    current_position += header_pos+length
        
        #print("matches:", patterns["matches"])
    return filetype_patterns

def extract_files(filetype_patterns, disk_image):
    files = []
    file_count = 0
    for filetype, pattern in filetype_patterns.items():
        matches = pattern["matches"]
        for match in matches:
            extracted_file = {}
            extracted_file["start"] = match["start"]
            extracted_file["end"] = match["end"]
            extracted_file["length"] = match["length"]
            file_data = ""
            with open(disk_image, "rb") as image:
                image.seek(match["start"])
                file_data = image.read(match["length"])
            extracted_file["name"] = f"file{file_count}{pattern['extension']}"
            extracted_file["filetype"] = filetype
            filename = "./extracted_files/" + extracted_file["name"]
            with open(filename, "wb") as out_file:
                out_file.write(file_data)
            extracted_file["sha256sum"] = get_sha256_sum(filename)
            files.append(extracted_file)
            file_count+=1
    return files

def get_sha256_sum(filename):
    data = ""
    with open(filename, "rb") as f:
        data = f.read()
    return hashlib.sha256(data).hexdigest()

def print_extracted_files(extracted_files):
    for f in extracted_files:
        print(f["name"])
        print("\tfiletype:", f["filetype"])
        print("\tstart offset:", hex(f["start"]))
        print("\tend offset:", hex(f["end"]))
        print("\tlength:", f["length"], "bytes")
        print("\tsha256 hexdigest:", f["sha256sum"])

def parse(disk_image):

    # find the signature
    ## for each signature in the signature list, we want to check for ALL matches of each signature type
    ## when we find a match, there's a good chance that that file exists within the disk image
    # find the starting point of the signature

    # find the end of the file
    filetype_patterns = find_files(disk_image)
    # extract the files
    files = extract_files(filetype_patterns, disk_image)
    # take the hash of the files
    print_extracted_files(files)
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
    parse(disk_image)
    return 0




if __name__ == "__main__":
    main()

