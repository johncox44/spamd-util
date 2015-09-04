./spfip4.py -f spfnospamd > spfnospamd.ip4 && cp spfnospamd.ip4 /etc/mail/nospamd
pfctl -t nospamd -T replace -f /etc/mail/nospamd

