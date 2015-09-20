#! /usr/bin/python

import sys
import subprocess
import fileinput
import time
import os
from optparse import OptionParser
import syslog

cached_state = {}
new_state = {}
black_req = set()
already_trapped = set()
do_trap = True
debug = False

class CacheRecord:
    expire_delta = 24 * 60 * 60

    def __init__ (self, state, now, blacktype):
        self.state = state
        self.time = now
        self.blacktype = int(blacktype)

    def __str__ (self):
        return self.state + "(" + str(self.blacktype) + ") @" + str(self.time)

    def file_str (self, ip):
        return self.state + "|" + ip + "|" + str(self.time) + "|" + str(self.blacktype)

    def expired (self):
        return now < self.time + self.expire_delta

def do_black (ip):
    global do_trap
    global debug

    if debug:
        print "Add TRAPPED:", ip

    if do_trap:
        subprocess.check_call(["spamdb", "-a", "-t", ip])

    syslog.syslog(syslog.LOG_NOTICE, "Add TRAPPED:" + ip)
    return

def spam_lookup (ip, cur_type, record="A"):
    global cached_state
    global new_state
    global black_req
    global already_trapped

    dbg_ip = ip + "[" + cur_type + "]"

    if cur_type == "TRAPPED":
        if debug:
            print "Already trapped", dbg_ip
        already_trapped.add(ip)
        return

    if cur_type != "WHITE" and cur_type != "GREY":
        return

    # If already in new_state then we have already done anything required
    if ip in new_state:
        if debug:
            print "Already got new state for", dbg_ip, ":", new_state[ip]
        return

    now = int(time.time())

    if ip in cached_state:
        this_state = cached_state[ip]
        if debug:
            print "Cached state for", dbg_ip, ":", this_state
    else:
        # Need new lookup
        saddr = ip.split(".")
        if len(saddr) != 4:
            print "Bad IP4 ", dbg_ip
            return

        rip = saddr[3] + "." + saddr[2] + "." + saddr[1] + "." + saddr[0] + "." + "zen.spamhaus.org"

        if debug:
            print ">>> [" + dbg_ip + "]", rip

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

        if debug:
            print "New state for", dbg_ip, ":", this_state


    if this_state.state == "BLACK":
        black_req.add(ip);

    new_state[ip] = this_state


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-f", "--file", action="store", type="string", dest="filename")
    parser.add_option("-n", "--no-trap", action="store_true", dest="no_trap")
    parser.add_option("-d", "--debug", action="store_true", dest="debug")
    parser.add_option("-c", "--cache-file", type="string",
                      dest="cache_file", default="/tmp/dnsbl-scan.cache")
    (opts, args) = parser.parse_args(sys.argv[1:])

    do_trap = not opts.no_trap
    debug = opts.debug

    # Use mail if not redirected (recommend adding to spamd)
    syslog.openlog("dnsbl-scan", 0, syslog.LOG_MAIL)

    syslog.syslog(syslog.LOG_DEBUG, "Started")

    if debug:
        print "#<<<", opts, args

    cache_name = opts.cache_file
    cache_temp = cache_name + ".$$$"

    now = int(time.time())

    fin = fileinput.input(cache_name)
    try:
        for line in fin :
            parts = line.split("|")
            if len(parts) >= 4:
                cache_time = int(parts[2])
                if now < cache_time + CacheRecord.expire_delta:
                    cached_state[parts[1]] = CacheRecord(parts[0], cache_time, parts[3])
    except IOError:
        pass  # Probably doesn't exist

    fin.close()

    if opts.filename:
        dbsrc = fileinput.input(opts.filename)
    else:
        dbsrc = subprocess.check_output(["spamdb"]).splitlines()

    for line in dbsrc:
        parts = line.split("|")
        spam_lookup(parts[1], parts[0])

    for ip in (black_req - already_trapped):
        do_black(ip)

    fout = open(cache_temp, "w")
    for ip in new_state:
        fout.write(new_state[ip].file_str(ip) + "\n")
    fout.close()

    try:
        os.remove(cache_name)
    except OSError:
        pass

    os.rename(cache_temp, cache_name)

    syslog.closelog()


