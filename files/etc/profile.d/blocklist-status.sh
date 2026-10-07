# /etc/profile.d/blocklist-status.sh - protection status at root login.
# For distributions without /etc/update-motd.d (RHEL, Fedora, openSUSE, Arch...).
if [ "$(id -u)" = 0 ] && [ -t 1 ] && [ -x /usr/local/sbin/blocklist ]; then
  /usr/local/sbin/blocklist motd 2>/dev/null
fi
