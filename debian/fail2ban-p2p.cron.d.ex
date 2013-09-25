#
# Regular cron jobs for the fail2ban-p2p package
#
0 4	* * *	root	[ -x /usr/bin/fail2ban-p2p_maintenance ] && /usr/bin/fail2ban-p2p_maintenance
