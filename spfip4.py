#! /usr/bin/python

import sys
import subprocess
import fileinput
from optparse import OptionParser

def n_to_ip (n, s = 32):
    ip4 = str((n >> 24) & 0xff) + '.' + str((n >> 16) & 0xff) + '.' + str((n >> 8) & 0xff) + '.' + str(n  & 0xff)
    if s != 32:
        ip4 += '/' + str(s)
    return ip4

def print_ip4 (addr, suffix):
    try:
        saddr = addr.split(".")
        if len(saddr) > 4:
            raise Exception("Too many dots")
        while len(saddr) < 4:
            saddr.append("0")

        naddr = (int(saddr[0]) << 24) | (int(saddr[1]) << 16) | (int(saddr[2]) << 8) | int(saddr[3])

        nsuffix = 32
        if suffix:
            nsuffix = int(suffix)
            if nsuffix > 32 or nsuffix < 1:
                raise Exception("Bad range")

        naddr &= 0xffffffff << (32 - nsuffix)

        if naddr >> 24 == 127 or naddr >> 24 == 0:
            raise Exception("Unexpected address")

        print n_to_ip(naddr, nsuffix)

    except:
        print "# Failed to parse '" + addr + "', '" + suffix + "'"


def rec_lookup (val, src_name, plen, record="A"):
    name = val if val != "" else src_name
    dig_out = subprocess.check_output(["dig", "+short", record, name])
    print "# Lookup", name, "(" + record + "):"
    for line in dig_out.splitlines():
        print_ip4(line, plen)

def mx_lookup (val, src_name, plen, record="MX"):
    name = val if val != "" else src_name
    dig_out = subprocess.check_output(["dig", "+short", record, name])
    print "# Lookup", name, "(" + record + "):"
    for mx_rec in dig_out.splitlines():
        pri, space, a = mx_rec.partition(' ')
        if a:
            rec_lookup(a, src_name, plen)

def strip_quote (txt):
    v = False
    r = ""
    for s in txt.split('"'):
        if v:
            r += s
        v = not v
    return r

lookups_done = set();

def spf_lookup (name, current_domain="", record="TXT"):
    global lookups_done;

    print "# Lookup", name, "(" + record + "):"

    lookup_key = name + "::" + record
    if lookup_key in lookups_done:
        print "# -- Already done"
        return

    # Isn't in fact done yet but if we find ourselves looking up the same
    # thing again then we want to avoid the loop
    lookups_done.add(lookup_key)

    if not current_domain:
        current_domain = name[:]
    dig_out = subprocess.check_output(["dig", "+short", record, name])
    for line in dig_out.splitlines():
        print "#", line
        args = strip_quote(line).split()
        if args and args[0] == 'v=spf1':
            for arg in args:
                if arg[0] == '+':
                    arg = arg[1:]

                arg, slash, plen = arg.partition('/')
                part, colon, val = arg.partition(":")

                if part == "ip4" :
                    print_ip4(val, plen)
                elif part == "include":
                    spf_lookup(val)
                elif part == "a":
                    rec_lookup(val, current_domain, plen)
                elif part == "mx":
                    mx_lookup(val, current_domain, plen)
                elif part.startswith("redirect="):
                    spf_lookup(part.partition("=")[2], current_domain)
                # PTR we probably can't do anything useful with
    print "# --"

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-f", "--file", action="store", type="string", dest="filename")
    (opts, args) = parser.parse_args(sys.argv[1:])

    print "#<<<", opts, args

    if opts.filename:
        for line in fileinput.input(opts.filename) :
            if line[0] != "#":
                args += line.split()

    for arg in args:

        arg, slash, plen = arg.partition('/')
        part, colon, val = arg.partition(":")

        if not val:
            spf_lookup(part)
        elif part == "ip4" :
            print_ip4(val, plen)
        elif part == "include":
            spf_lookup(val)


