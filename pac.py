#!/usr/bin/python
import os,struct,glob,zlib

OUT_PATH = "output2/"
MODE = "<"

def dump_pac(f,basename,filename,filesize):
    if not os.path.isdir(OUT_PATH+basename+".extracted"):
        os.makedirs(OUT_PATH+basename+".extracted")
    else:
        pass
    outFilename = os.path.join(OUT_PATH+basename+".extracted",filename)
    if os.path.isfile(outFilename):
            return
    print filename
    out = open(outFilename,"wb")
    out.write(f.read(filesize))
    out.close()

# TODO take a file handle rather than a name
# TODO make sure file gets closed
def iterpac(filename,func):
    global MODE
    basename = os.path.split(filename)[1]

    f = open(filename,"rb")
    if f.read(4) != "FPAC":
        print "\t","Not a valid .pac file"
        return

    DATA_START,TOTAL_SIZE,FILE_COUNT = struct.unpack(MODE+ "3I",f.read(12))
    if FILE_COUNT == 0:
        return

    UNK01,STRING_SIZE,UNK03,UNK04 = struct.unpack(MODE+ "4I",f.read(16))
    ENTRY_SIZE = (DATA_START-0x20)/FILE_COUNT
    #STRING_SIZE = (STRING_SIZE + 15) & ~15

    for i in range(0,FILE_COUNT):
        f.seek(0x20+i*(ENTRY_SIZE))
        FILE_NAME,FILE_ID,FILE_OFFSET,FILE_SIZE,UNK = struct.unpack(MODE+str(STRING_SIZE)+"s4I",f.read(0x10+STRING_SIZE))
        FILE_NAME = FILE_NAME.split("\x00")[0]
        start = DATA_START + FILE_OFFSET
        end   = start + FILE_SIZE
        yield func(f, basename, FILE_NAME, start, end)

# create a parsing function for the pac iterator
def chunk_parser (parse_func):
    def parser (f, basename, chunkname, start, end):
        #print "CHUNK:", chunkname, "SIZE:", end - start
        return parse_func(f, chunkname, start, end)
    return parser

#for filename in glob.glob("disc/P4AU/char/char_kk_*.pac"):
if __name__ == "__main__":
    for filename in glob.glob("input/bbcpex/char_*_scr.pac"):
        print filename
        for thing in iterpac(filename,dump_pac):
            print thing
