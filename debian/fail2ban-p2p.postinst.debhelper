# Automatically added by dh_pycentral
rm -f /var/lib/pycentral/fail2ban-p2p.pkgremove
if which pycentral >/dev/null 2>&1; then
	pycentral pkginstall fail2ban-p2p
	if grep -qs '^fail2ban-p2p$' /var/lib/pycentral/delayed-pkgs; then
		sed -i '/^fail2ban-p2p$/d' /var/lib/pycentral/delayed-pkgs
	fi
fi
# End automatically added section
# Automatically added by dh_installinit
if [ -x "/etc/init.d/fail2ban-p2p" ]; then
	update-rc.d fail2ban-p2p defaults 99 >/dev/null
	invoke-rc.d fail2ban-p2p start || exit $?
fi
# End automatically added section
