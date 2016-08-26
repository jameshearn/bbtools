import struct

def rkt_sanitizer (signature):
    def sanitize (s):
        if isinstance(s, str):
            s = '"{0}"'.format(s.strip("\x00"))
        elif "hex" in signature:
            s = hex(s)
        return str(s).strip("\x00")
    return sanitize

# decode a bytecode stream into simple s-expressions
def sexp_raw_format (f, out, signatures, start, end):
    if end <= start:
        print "WARN: NO BYTES PROVIDED", start, end

    f.seek(start)
    pos = start
    open_blocks = 0
    initial_block = True

    while pos < end:
        instruction, = struct.unpack("<I", f.read(4))
        signature    = signatures[str(instruction)]
        parameters   = None
        operands     = None

        # Generate a name for unknown functions
        if "name" not in signature:
            signature["name"] = "<Func{0}>".format(instruction)

        if "format" not in signature:
            # parameters not yet determined, use hex-encoded raw bytes
            operands = [f.read(signature["size"] - 4).encode("hex")]
        else:
            parameters = signature["format"]
            operands = list(struct.unpack(parameters, f.read(struct.calcsize(parameters))))

        if instruction in [0, 8]:
            if not initial_block: out.write("\n")
            initial_block = False
            open_blocks += 1
            block_name = operands[0].strip("\x00")
            out.write('    ; {0}: {3} @ 0x{1}\n    ({2} "{0}")\n'.format(block_name, pos, signature["name"], signature["name"].capitalize()))
        else:
            arguments = " ".join(map(rkt_sanitizer(signature), operands))
            out.write("    ({0}{1})\n".format(
                signature["name"],
                (' ' + arguments) if arguments else ''))

        # newline after end-procedure, end-state
        if instruction in [1, 9]:
            open_blocks -= 1
            #out.write("\n")

        pos = f.tell()

    if pos != end:
        print "WARN: {0} leftover bytes".format(end - pos)

    # quick, overly simple sanity check
    if open_blocks > 0:
        print "WARN: {0} blocks left unclosed".format(open_blocks)
        out.write("; *****WARN: UNCLOSED BLOCK*****\n");
    elif open_blocks < 0:
        print "WARN: {0} extra blocks closed".format(-open_blocks)
        out.write("; *****WARN: OVERCLOSED BLOCK*****\n");

def parse_header (f, out, chunk_start):
    # first 4 bytes hold the number of records in the header of this bbscript chunk
    f.seek(chunk_start)
    num_records, = struct.unpack("<I", f.read(4))

    # HEADER:
    # sequence of fixed 0x24 byte records
    # 0x20 bytes for record name (z-filled)
    #    4 bytes for offset after the header
    table_start   = chunk_start + 4
    table_size    = num_records * 0x24
    table_end     = table_start + table_size

    # out.write("; HEADER: {0} entries SIZE: {1} bytes\n".format(num_records, table_size));

    # locate the beginning of the first record body
    f.seek(table_start + 0x20) # skip 0x20 bytes of name
    records_start = table_end + struct.unpack("<I", f.read(4))[0]

    return table_start, table_end, records_start, num_records

def parse_initializer (f, out, formatter, signatures, init_start, init_end):
    # optional initializer body is everything after the header table and before the record bodies
    if init_end > init_start:
        out.write("; INITIALIZER: SIZE: {0} bytes\n".format(init_end - init_start))
        out.write("(bbscript-initializer\n")
        formatter(f, out, signatures, init_start, init_end)
        out.write(") ; END-INITIALIZER\n\n")

def record_entry (f, header_start, header_end, i):
    f.seek(header_start + (i * 0x24))        # start of record entry
    name    = f.read(0x20).split("\x00")[0]  # 20 bytes of z-filled record name
    offset, = struct.unpack("<I", f.read(4)) #  4 bytes for record location
    start   = header_end + offset
    return (start, name)

def parse_records (f, out, formatter, signatures, num_records, header_start, header_end, records_end):
    if not num_records:
        return

    for i in range(0, num_records):
        record_start, record_name = record_entry(f, header_start, header_end, i)
        record_end = record_entry(f, header_start, header_end, i + 1)[0] if (i + 1 < num_records) else records_end
        out.write("; RECORD: {2} SIZE: {3} bytes [{0}/{1}]\n".format(i + 1, num_records, record_name, record_end - record_start))
        out.write("(bbscript-record \"{0}\"\n".format(record_name))
        formatter(f, out, signatures, record_start, record_end)
        out.write(") ; END-RECORD \"{0}\"\n\n".format(record_name))

def parse_chunk (f, out, chunkname, chunk_start, chunk_end, signatures, formatter):
    out.write("; CHUNK: {0} SIZE: {1} bytes\n".format(chunkname, chunk_end - chunk_start))
    out.write("(pac-chunk \"{0}\"\n".format(chunkname))

    header_start, header_end, records_start, num_records = parse_header(f, out, chunk_start)

    #print "INITIALIZER", header_end, records_start
    parse_initializer(f, out, formatter, signatures, header_end, records_start)
    #print "RECORDS"
    parse_records(f, out, formatter, signatures, num_records, header_start, header_end, chunk_end)
    out.write(") ; END-CHUNK: \"{0}\"\n\n".format(chunkname))
    # FIXME return something more useful

def chunk_parser (signatures, out, formatter):
    def bbscript_parser (f, chunkname, start, end):
        return parse_chunk(f, out, chunkname, start, end, signatures, formatter)
    return bbscript_parser
