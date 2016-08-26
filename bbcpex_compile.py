#!/usr/bin/python
import bbcpex_script_parser, pac
import os, json

signatures = json.loads(open("static_db/bb/commandDB.json").read())
characters = json.loads(open("static_db/bb/characters.json").read())

# TODO command-line arguments etc
if __name__ == "__main__":
    for abbrev, charname in characters.iteritems():
        # TODO: just pass a file handle to the parser
        pac_filename = "input/bbcpex/char_{0}_scr.pac".format(abbrev)

        if not os.path.isfile(pac_filename):
            print "WARN: could not locate file {0} for character {1}, skipping".format(pac_filename, charname)
            continue

        # TODO command-line option, parser type detection
        # TODO: name file with actual character name, not abbrev
        out_filename = "db/bbcpex/" + charname + ".rkt"
        out = open(out_filename, "wb")
        if not out:
            print "ERROR: could not open output file {0}, skipping.".format(out_filename)
            continue

        bbscript_parser = bbcpex_script_parser.chunk_parser(
            signatures,
            out,
            bbcpex_script_parser.sexp_raw_format)

        parser = pac.chunk_parser(bbscript_parser)

        print "FILE: {0}: {1} -> {2}".format(charname, pac_filename, out_filename)

        # FIXME HACK
        out.write("; FILE: {0}\n".format(pac_filename));
        out.write("(pac-file '{0}\n".format(charname))

        for filename in pac.iterpac(pac_filename, parser):
            # we get the chunks here
            # FIXME do something more sensible
            pass

        out.write(") ; END-FILE: {0}\n".format(charname));
        out.close()
