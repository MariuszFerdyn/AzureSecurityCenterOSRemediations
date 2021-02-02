#!/bin/bash

# 1.
if [ -f /etc/sysconfig/network ]; then
    if ! grep -q '^NOZEROCONF[[:blank:]]*=.*' /etc/sysconfig/network; then
        echo 'NOZEROCONF=yes' >> /etc/sysconfig/network
    else
	grep '^NOZEROCONF[[:blank:]]*=.*' /etc/sysconfig/network | grep -q -v 'yes' &&\
          sed -i 's/^\(NOZEROCONF[[:blank:]]*=[[:blank:]]*\).*/\1yes/' /etc/sysconfig/network
    fi
fi

# 2.
# 3.
[ -d /etc/sysctl.d ] || mkdir -p /etc/sysctl.d
[ -r /etc/sysctl.d/10-network-security.conf ] || touch /etc/sysctl.d/10-network-security.conf
for f in /etc/sysctl.conf /etc/sysctl.d/*; do
    if [ -f "$f" ] && grep -q '^net\.ipv4\.conf\.\(default\|all\)\.rp_filter[[:blank:]]*=' "$f"; then
        if [ "$f" == "/etc/sysctl.d/10-network-security.conf" ]; then
            grep '^net\.ipv4\.conf\.\(default\|all\)\.rp_filter[[:blank:]]*=[[:blank:]]*' "$f" |\
	      grep -q -v '=[[:blank:]]*1$' && \
              sed -i 's/^\(net\.ipv4\.conf\.\(default\|all\)\.rp_filter\)[[:blank:]]*=.*/\1=1/' "$f"
        else
            sed -i 's/^\(net\.ipv4\.conf\.\(default\|all\)\.rp_filter[[:blank:]]*=.*\)/#\1/' "$f"
        fi
    fi
done

if ! grep -q '^net\.ipv4\.conf\.\(default\|all\)\.rp_filter[[:blank:]]*=' /etc/sysctl.conf /etc/sysctl.d/*; then
        echo net.ipv4.conf.default.rp_filter=1 >> /etc/sysctl.d/10-network-security.conf
        echo net.ipv4.conf.all.rp_filter=1 >> /etc/sysctl.d/10-network-security.conf
fi

# 4.
if [ -f /etc/samba/smb.conf ]; then
    if grep '^[[:blank:]]*\(server \|\)min\ protocol[[:blank:]]*=' /etc/samba/smb.conf | grep -q -v 'SMB[23]'; then
        sed -i '/^\[global\]$/,/^\[/ s/^\([[:blank:]]*\(server \|\)min\ protocol[[:blank:]]*=\).*/\1 SMB2/' /etc/samba/smb.conf
    fi
    grep -q '^[[:blank:]]*\(server \|\)min\ protocol[[:blank:]]*=.*' /etc/samba/smb.conf || \
        sed -i '/^\[global\]$/a \\tmin protocol = SMB2' /etc/samba/smb.conf
fi

# 5.
for f in /etc/ssh/sshd_config /etc/ssh/ssh_config.d/*; do
    if [ -f "$f" ]; then
        grep '^[[:blank:]]*HostbasedAuthentication[[:blank:]]\+' "$f" | grep -q -v 'no' &&\
            sed -i 's/^\([[:blank:]]*HostbasedAuthentication[[:blank:]]\+\).*/\1no/' "$f"
    fi
done

grep -q '^[[:blank:]]*HostbasedAuthentication[[:blank:]]\+' /etc/ssh/sshd_config /etc/ssh/ssh_config.d/* ||\
    echo 'HostbasedAuthentication no' >> /etc/ssh/sshd_config

# 6.
for f in /etc/ssh/sshd_config /etc/ssh/ssh_config.d/*; do
    if [ -f "$f" ]; then
        grep '^[[:blank:]]*IgnoreRhosts[[:blank:]]\+' "$f" | grep -q -v 'yes' &&\
            sed -i 's/^\([[:blank:]]*IgnoreRhosts[[:blank:]]\+\).*/\1yes/' "$f"
    fi
done

grep -q '^[[:blank:]]*IgnoreRhosts[[:blank:]]\+' /etc/ssh/sshd_config /etc/ssh/ssh_config.d/* ||\
    echo 'IgnoreRhosts yes' >> /etc/ssh/sshd_config

# 7.
for f in /etc/rsyslog.conf /etc/rsyslog.d/*; do
    if [ -f "$f" ]; then
        grep '^$FileCreateMode[[:blank:]]*' "$f" | grep -q -v '06[04]0' &&\
	    sed -i 's/^\($FileCreateMode[[:blank:]]*\).*/\1 0640' "$f"
    fi
done

grep -q '^$FileCreateMode[[:blank:]]*' /etc/rsyslog.conf ||\
    echo '$FileCreateMode 0640' >> /etc/rsyslog.conf

# 8.
echo 'blacklist rds' > /etc/modprobe.d/rds.conf

# 9.
for f in /etc/ssh/sshd_config /etc/ssh/ssh_config.d/*; do
    if [ -f "$f" ]; then
        grep '^[[:blank:]]*Protocol[[:blank:]]\+' "$f" | grep -q -v '2' &&\
            sed -i 's/^\([[:blank:]]*Protocol[[:blank:]]\+\).*/\1 2/' "$f"
    fi
done

grep -q '^[[:blank:]]*Protocol[[:blank:]]\+' /etc/ssh/sshd_config /etc/ssh/ssh_config.d/* ||\
    echo 'Protocol 2' >> /etc/ssh/sshd_config

# 10.
if ! grep -q '^PASS_MIN_DAYS[[:blank:]]\+' /etc/login.defs; then
    echo 'PASS_MIN_DAYS 7' >> /etc/login.defs
else
    grep '^PASS_MIN_DAYS[[:blank:]]\+' /etc/login.defs | grep -q -v '\([7-9]\|[1-9][0-9]\)[[:blank:]]*$' && \
      sed -i 's/^\(PASS_MIN_DAYS[[:blank:]]\+\).*/\1 7/' /etc/login.defs
fi

# 11.
for f in /etc/ssh/sshd_config /etc/ssh/ssh_config.d/*; do
    if [ -f "$f" ]; then
        grep '^[[:blank:]]*PermitEmptyPasswords[[:blank:]]\+' "$f" | grep -q -v 'no' &&\
            sed -i 's/^\([[:blank:]]*PermitEmptyPasswords[[:blank:]]\+\).*/\1no/' "$f"
    fi
done

grep -q '^[[:blank:]]*PermitEmptyPasswords[[:blank:]]\+' /etc/ssh/sshd_config /etc/ssh/ssh_config.d/* ||\
    echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config

# 12.
if ! grep -q '^[[:blank:]]*\(AllowUsers\|AllowGroups\|DenyUsers\|DenyGroups\)[[:blank:]]\+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*; then
	echo Ensure SSH access is limited !
fi
