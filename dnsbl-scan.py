#! /usr/bin/python

import sys
import subprocess
import fileinput
import time
import os
from optparse import OptionParser

cached_state = {}
new_state = {}
do_trap = True

class CacheRecord:
    expire_delta = 24 * 60 * 60

    def __init__ (self, state, now, blacktype):
        self.state = state
        self.time = now
        self.blacktype = int(blacktype)

    def file_str (self, ip):
        return self.state + "|" + ip + "|" + str(self.time) + "|" + str(self.blacktype)

    def expired (self):
        return now < self.time + self.expire_delta

def do_black (ip, cur_type, black_type):
    global do_trap

    if not do_trap:
        print "### BLACK (", black_type, ")", ip
    else:
        subprocess.check_call(["spamdb", "-a", "-t", ip])
    return

def spam_lookup (ip, cur_type, record="A"):
    global cached_state
    global new_state

    if cur_type != "WHITE" and cur_type != "GREY":
        return

    # If already in new_state then we have already done anything required
    if ip in new_state:
        print "### Got new state", new_state[ip]
        return

    now = int(time.time())

    if ip in cached_state:
        this_state = cached_state[ip]
        print "### Got cached state", this_state.file_str(ip)
    else:
        # Need new lookup
        saddr = ip.split(".")
        if len(saddr) != 4:
            print "### Bad IP4 ", ip
            return

        rip = saddr[3] + "." + saddr[2] + "." + saddr[1] + "." + saddr[0] + "." + "zen.spamhaus.org"

        print ">>> [", cur_type, "] ", rip

        dig_out = subprocess.check_output(["dig", "+short", record, rip])
        black_type = 256
        for a_rec in dig_out.splitlines():
            if a_rec[0:8] == "127.0.0.":
                this_black = int(a_rec[8:])
                if this_black != 0 and this_black < black_type:
                    black_type = this_black;

        if black_type != 256:
            this_state = CacheRecord("BLACK", now, black_type)
        else:
            this_state = CacheRecord("GREY", now, 0)

    if this_state.state == "BLACK":
        do_black(ip, cur_type, this_state.blacktype)

    new_state[ip] = this_state


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-f", "--file", action="store", type="string", dest="filename")
    parser.add_option("-n", "--no-trap", action="store_true", dest="no_trap")
    (opts, args) = parser.parse_args(sys.argv[1:])

    print "#<<<", opts, args
    do_trap = not opts.no_trap

    cache_name = "dnsbl-scan.cache"
    cache_temp = cache_name + ".$$$"

    now = int(time.time())

    fin = fileinput.input(cache_name)
    try:
        for line in fin :
            parts = line.split("|")
            cache_time = int(parts[2])
            if len(parts) >= 4 and now < cache_time + CacheRecord.expire_delta:
                cached_state[parts[1]] = CacheRecord(parts[0], cache_time, parts[3])
    except IOError:
        pass  # Probably doesn't exist

    fin.close()

    if opts.filename:
        dbsrc = fileinput.input(opts.filename)
    else:
        dbsrc = subprocess.check_output(["spamdb"])

    for line in dbsrc:
        parts = line.split("|")
        spam_lookup(parts[1], parts[0])

    fout = open(cache_temp, "w")
    for ip in new_state:
        fout.write(new_state[ip].file_str(ip) + "\n")
    fout.close()

    try:
        os.remove(cache_name)
    except OSError:
        pass

    os.rename(cache_temp, cache_name)


