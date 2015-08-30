/home/root/spfip4.py -f /home/root/spfnospamd > /home/root/spfnospamd.ip4 && cp /home/root/spfnospamd.ip4 /etc/mail/nospamd
pfctl -t nospamd -T replace -f /etc/mail/nospamd

