#!/bin/bash

function sysctl () {
  local file=$1
  local parameter=$2
  local value=$3
  local r1=$(echo "$parameter" | sed 's/\./\\./g')

  [ -d /etc/sysctl.d ] || mkdir -p /etc/sysctl.d
  [ -r /etc/sysctl.d/$file ] || touch /etc/sysctl.d/$file
  for f in /etc/sysctl.conf /etc/sysctl.d/*; do
    if [ -f "$f" ] && grep -q "^$r1[[:blank:]]*=" "$f"; then
        if [ "$f" == "/etc/sysctl.d/$file" ]; then
            grep "^$r1[[:blank:]]*=[[:blank:]]*" "$f" |\
              grep -q -v "=[[:blank:]]*$value$" && \
              sed -i "s/^\($r1\)[[:blank:]]*=.*/\1=$value/" "$f"
        else
            sed -i "s/^\($r1[[:blank:]]*=.*\)/#\1/" "$f"
        fi
    fi
  done

  if ! grep -q "^$r1[[:blank:]]*=" /etc/sysctl.conf /etc/sysctl.d/*; then
    echo $parameter=$value >> /etc/sysctl.d/$file
  fi

}

sysctl 10-network-security.conf net.ipv4.conf.default.rp_filter 1
sysctl 10-network-security.conf net.ipv4.conf.all.rp_filter 1
sysctl 10-network-security.conf net.ipv4.conf.default.secure_redirects 0
sysctl 10-network-security.conf net.ipv4.conf.default.accept_redirects 0
sysctl 10-network-security.conf net.ipv4.conf.all.log_martians 1

function modprobe_conf() {
  local file=$1
  local command=$2
  local modulename=$3
  local opts=$4
  local r1=$(echo "$command $modulename "|sed 's/[[:blank:]]\+/[[:blank:]]\\+/g')

  for f in /etc/modprobe.d/*; do
    if [ -f "$f" ] && grep -q "^$r1" "$f"; then
        if [ "$f" == "/etc/modprobe.d/$file" ]; then
            grep "^$r1" "$f" | grep -q -v "^$r1$opts" && \
              sed -i "s/^\($r1).*/\1 $opts/" "$f"
        else
            sed -i "s/^\($r1.*)/#\1/" "$f"
        fi
    fi
  done

  if ! grep -q "^$r1$opts" /etc/modprobe.d/*; then
    echo $command $modulename $opts >> /etc/modprobe.d/$file
  fi

}

modprobe_conf filesystems.conf install cramfs /bin/true
modprobe_conf filesystems.conf install hfs /bin/true
modprobe_conf filesystems.conf install jffs2 /bin/true
modprobe_conf filesystems.conf install hfsplus /bin/true
modprobe_conf filesystems.conf install freevxfs /bin/true
modprobe_conf filesystems.conf install rds /bin/true

# 1.
if [ -f /etc/sysconfig/network ]; then
    if ! grep -q '^NOZEROCONF[[:blank:]]*=.*' /etc/sysconfig/network; then
        echo 'NOZEROCONF=yes' >> /etc/sysconfig/network
    else
	grep '^NOZEROCONF[[:blank:]]*=.*' /etc/sysconfig/network | grep -q -v 'yes' &&\
          sed -i 's/^\(NOZEROCONF[[:blank:]]*=[[:blank:]]*\).*/\1yes/' /etc/sysconfig/network
    fi
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

grep -q -r '^[[:blank:]]*HostbasedAuthentication[[:blank:]]\+' /etc/ssh/sshd_config* ||\
    echo 'HostbasedAuthentication no' >> /etc/ssh/sshd_config

# 6.
for f in /etc/ssh/sshd_config /etc/ssh/ssh_config.d/*; do
    if [ -f "$f" ]; then
        grep '^[[:blank:]]*IgnoreRhosts[[:blank:]]\+' "$f" | grep -q -v 'yes' &&\
            sed -i 's/^\([[:blank:]]*IgnoreRhosts[[:blank:]]\+\).*/\1yes/' "$f"
    fi
done

grep -q -r '^[[:blank:]]*IgnoreRhosts[[:blank:]]\+' /etc/ssh/sshd_config* ||\
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

grep -q -r '^[[:blank:]]*Protocol[[:blank:]]\+' /etc/ssh/sshd_config* ||\
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

grep -q -r '^[[:blank:]]*PermitEmptyPasswords[[:blank:]]\+' /etc/ssh/sshd_config* ||\
    echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config

# 12.
if ! grep -q -r '^[[:blank:]]*\(AllowUsers\|AllowGroups\|DenyUsers\|DenyGroups\)[[:blank:]]\+' /etc/ssh/sshd_config*; then
    echo Ensure SSH access is limited !
    echo 'DenyUsers someUser' >> /etc/ssh/sshd_config
fi

# su
if ! grep -q "^[[:blank:]]*auth[[:blank:]]\+required[[:blank:]]\+pam_wheel.so[[:blank:]]\+use_uid" /etc/pam.d/su; then
    if grep -q "^#\+[[:blank:]]*auth[[:blank:]]\+required[[:blank:]]\+pam_wheel.so[[:blank:]]\+use_uid" /etc/pam.d/su; then
        sed -i "s/^.*\(auth[[:blank:]]\+required[[:blank:]]\+pam_wheel.so[[:blank:]]\+use_uid.*\)$/\1/" /etc/pam.d/su
    else
        echo 'auth required pam_wheel.so use_uid' >> /etc/pam.d/su
    fi
fi

# grub.cfg
[ -f /boot/grub2/grub.cfg ] && chmod 400 /boot/grub2/grub.cfg

# rsyslog.conf
for f in /etc/rsyslog.conf /etc/rsyslog.d/*; do
    if [ -f "$f" ]; then
        grep '^$FileOwner[[:blank:]]*' "$f" | grep -q -v ' syslog' &&\
	    sed -i 's/^\($FileOwner[[:blank:]]*\).*/\1 syslog' "$f"
    fi
done

grep -q '^$FileOwner[[:blank:]]*' /etc/rsyslog.conf ||\
    echo '$FileOwner syslog' >> /etc/rsyslog.conf

# postfix inet_interfaces
[ -r /etc/postfix/main.cf ] && echo "inet_interfaces localhost" >> /etc/postfix/main.cf

# /etc/passwd-
[ -f /etc/passwd- ] && chmod 600 /etc/passwd-

# no postfix
[ -x /usr/bin/apt-get ] && apt-get -y remove postfix
[ -x /usr/bin/yum ] && yum -y remove postfix

# portmap
systemctl stop rpcbind.service
systemctl disable rpcbind.service
systemctl mask rpcbind.service

# sshd banner
for f in /etc/ssh/sshd_config /etc/ssh/ssh_config.d/*; do
    if [ -f "$f" ]; then
        grep '^[[:blank:]]*Banner[[:blank:]]\+' "$f" | grep -q -v '/etc/issue.net' &&\
            sed -i 's/^\([[:blank:]]*Banner[[:blank:]]\+\).*/\= /etc/issue.net/' "$f"
    fi
done

grep -q '^[[:blank:]]*Banner[[:blank:]]\+' /etc/ssh/sshd_config /etc/ssh/ssh_config.d/* ||\
    echo 'Banner = /etc/issue.net' >> /etc/ssh/sshd_config

# end
echo Reboot suggested.
