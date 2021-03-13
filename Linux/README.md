# Azure Security Center Recommendations for Linux

This Scripts can be used to fix standard Linux installations to be compliant with Azure Security Center recommendations.

### Feel free to fork and contribute.

### Details:

| NAME | Zeroconf networking should be disabled. |
| --- | --- |
| CCEID | CCE-14054-1 |
| RULE SEVERITY | Critical |
| FULL DESCRIPTION | Zeroconf networking should be disabled. (disabled) |
| POTENTIAL IMPACT | An attacker could use abuse this to gain information on network systems, or spoof DNS requests due to flaws in its trust model |
| ACTUAL VALUE | File /etc/sysconfig/network should contain one or more lines matching [&#39;^NOZEROCONF=\w+\s\*$&#39;] |

| NAME | Performing source validation by reverse path should be enabled for all interfaces. (net.ipv4.conf.all.rp\_filter = 1) |
| --- | --- |
| CCEID | CCE-4080-8 |
| RULE SEVERITY | Critical |
| FULL DESCRIPTION | Performing source validation by reverse path should be enabled for all interfaces. (net.ipv4.conf.all.rp\_filter &amp;#61; 1) |
| POTENTIAL IMPACT | The system will accept traffic from addresses that are unroutable. |
| ACTUAL VALUE | File /proc/sys/net/ipv4/conf/all/rp\_filter should contain one or more lines matching [&#39;^1$&#39;] |

| NAME | Performing source validation by reverse path should be enabled for all interfaces. (net.ipv4.conf.default.rp\_filter = 1) |
| --- | --- |
| CCEID | CCE-3840-6 |
| RULE SEVERITY | Critical |
| FULL DESCRIPTION | Performing source validation by reverse path should be enabled for all interfaces. (net.ipv4.conf.default.rp\_filter &amp;#61; 1) |
| POTENTIAL IMPACT | The system will accept traffic from addresses that are unroutable. |
| ACTUAL VALUE | File /proc/sys/net/ipv4/conf/default/rp\_filter should contain one or more lines matching [&#39;^1$&#39;] |

| NAME | Disable SMB V1 with Samba |
| --- | --- |
| RULE SEVERITY | Critical |
| ACTUAL VALUE | No matching lines for expression: ^\s\*min protocol\s+=\s+SMB2 found in section: of file: /etc/samba/smb.conf |

| NAME | SSH host-based authentication should be disabled. - &#39;/etc/ssh/sshd\_config HostbasedAuthentication = no&#39; |
| --- | --- |
| CCEID | CCE-4370-3 |
| RULE SEVERITY | Critical |
| FULL DESCRIPTION | SSH host-based authentication should be disabled. - &#39;/etc/ssh/sshd\_config HostbasedAuthentication &amp;#61; no&#39; |
| POTENTIAL IMPACT | An attacker could use use host-based authentication to gain access from a compromised host |
| ACTUAL VALUE | File /etc/ssh/sshd\_config should contain one or more lines matching [&#39;^[\s\t]\*HostbasedAuthentication\s+no&#39;] |

| NAME | SSH must be configured and managed to meet best practices. - &#39;/etc/ssh/sshd\_config IgnoreRhosts = yes&#39; |
| --- | --- |
| CCEID | CCE-4030-3 |
| RULE SEVERITY | Critical |
| FULL DESCRIPTION | SSH must be configured and managed to meet best practices. - &#39;/etc/ssh/sshd\_config IgnoreRhosts &amp;#61; yes&#39; |
| POTENTIAL IMPACT | An attacker could use flaws in the Rhosts protocol to gain access |
| ACTUAL VALUE | File /etc/ssh/sshd\_config should contain one or more lines matching [&#39;^\s\*IgnoreRhosts\s+yes&#39;] |

| NAME | File permissions for all rsyslog log files should be set to 640 or 600. |
| --- | --- |
| CCEID | CCE-18095-0 |
| RULE SEVERITY | Critical |
| FULL DESCRIPTION | File permissions for all rsyslog log files should be set to 640. |
| POTENTIAL IMPACT | An attacker could cover up activity by manipulating logs |
| ACTUAL VALUE | File /etc/rsyslog.conf should contain one or more lines matching [&#39;^[\s]\*.FileCreateMode\s+06[04]0&#39;] |

| NAME | Disable support for RDS. |
| --- | --- |
| CCEID | CCE-14027-7 |
| RULE SEVERITY | Warning |
| FULL DESCRIPTION | Disable support for RDS. |
| POTENTIAL IMPACT | An attacker could use a vulnerability in RDS to compromise the system |
| ACTUAL VALUE | Found no files with lines matching &#39;^install\srds&#39; in /etc/modprobe.d/ |

| NAME | SSH must be configured and managed to meet best practices. - &#39;/etc/ssh/sshd\_config Protocol = 2&#39; |
| --- | --- |
| CCEID | CCE-4325-7 |
| RULE SEVERITY | Critical |
| FULL DESCRIPTION | SSH must be configured and managed to meet best practices. - &#39;/etc/ssh/sshd\_config Protocol &amp;#61; 2&#39; |
| POTENTIAL IMPACT | An attacker could use flaws in an earlier version of the SSH protocol to gain access |
| ACTUAL VALUE | File /etc/ssh/sshd\_config should contain one or more lines matching [&#39;^\s\*Protocol\s+2$&#39;] |

| NAME | Ensure minimum days between password changes is 7 or more. |
| --- | --- |
| RULE SEVERITY | Critical |
| ACTUAL VALUE | File /etc/login.defs should contain one or more lines matching [&#39;^\s\*PASS\_MIN\_DAYS\s+([7-9]|[1-9][0-9]+)\s\*$&#39;] |

| NAME | Remote connections from accounts with empty passwords should be disabled. - &#39;/etc/ssh/sshd\_config PermitEmptyPasswords = no&#39; |
| --- | --- |
| CCEID | CCE-3660-8 |
| RULE SEVERITY | Critical |
| FULL DESCRIPTION | Remote connections from accounts with empty passwords should be disabled. - &#39;/etc/ssh/sshd\_config PermitEmptyPasswords &amp;#61; no&#39; |
| POTENTIAL IMPACT | An attacker could gain access through password guessing |
| ACTUAL VALUE | File /etc/ssh/sshd\_config should contain one or more lines matching [&#39;^[\s\t]\*PermitEmptyPasswords\s+no&#39;] |

| NAME | Ensure SSH access is limited |
| --- | --- |
| RULE SEVERITY | Critical |
| ACTUAL VALUE | File /etc/ssh/sshd\_config should contain one or more lines matching [&#39;^\s\*(AllowUsers|AllowGroups|DenyUsers|DenyGroups)(\s+\S+)+&#39;] |


### In preparation:

| NAME | Sending ICMP redirects should be disabled for all interfaces. (net.ipv4.conf.default.secure\_redirects = 0) |
| --- | --- |
| CCEID | CCE-4151-7 |
| RULE SEVERITY | Critical |
| FULL DESCRIPTION | Sending ICMP redirects should be disabled for all interfaces. (net.ipv4.conf.default.secure\_redirects = 0) |
| POTENTIAL IMPACT | An attacker could alter this system&#39;s routing table, redirecting traffic to an alternate destination |
| ACTUAL VALUE | Expected output of &#39;sysctl -a&#39; to match &#39;^net\.ipv4\.conf\.default\.secure\_redirects\s\*=\s\*0\s\*$&#39; |

| NAME | Sending ICMP redirects should be disabled for all interfaces. (net.ipv4.conf.default.accept\_redirects = 0) |
| --- | --- |
| CCEID | CCE-4186-3 |
| RULE SEVERITY | Critical |
| FULL DESCRIPTION | Sending ICMP redirects should be disabled for all interfaces. (net.ipv4.conf.default.accept\_redirects = 0) |
| POTENTIAL IMPACT | An attacker could alter this system&#39;s routing table, redirecting traffic to an alternate destination |
| ACTUAL VALUE | Expected output of &#39;sysctl -a&#39; to match &#39;^net\.ipv6\.conf\.all\.accept\_redirects\s\*=\s\*0\s\*$&#39; |



| NAME | Disable the installation and use of file systems that are not required (cramfs) |
| --- | --- |
| RULE SEVERITY | Warning |
| FULL DESCRIPTION | Disable the installation and use of file systems that are not required (cramfs) |
| POTENTIAL IMPACT | An attacker could use a vulnerability in cramfs to elevate privileges |
| ACTUAL VALUE | Found no files with lines matching &#39;^install\s+cramfs\s+/bin/true&#39; in /etc/modprobe.d/ |

| NAME | Disable the installation and use of file systems that are not required (hfs) |
| --- | --- |
| RULE SEVERITY | Warning |
| FULL DESCRIPTION | Disable the installation and use of file systems that are not required (hfs) |
| POTENTIAL IMPACT | An attacker could use a vulnerability in hfs to elevate privileges |
| ACTUAL VALUE | Found no files with lines matching &#39;^install\s+hfs\s+/bin/true&#39; in /etc/modprobe.d/ |
| NAME | Disable the installation and use of file systems that are not required (jffs2) |
 |
 |
| RULE SEVERITY | Warning |
 |
 |
| FULL DESCRIPTION | Disable the installation and use of file systems that are not required (jffs2) |
 |
 |
| POTENTIAL IMPACT | An attacker could use a vulnerability in jffs2 to elevate privileges |
 |
 |
| ACTUAL VALUE | Found no files with lines matching &#39;^install\s+jffs2\s+/bin/true&#39; in /etc/modprobe.d/ |
 |
 |
|
 |
 |
 |
 |

| NAME | Disable the installation and use of file systems that are not required (hfsplus) |
| --- | --- |
| RULE SEVERITY | Warning |
| FULL DESCRIPTION | Disable the installation and use of file systems that are not required (hfsplus) |
| POTENTIAL IMPACT | An attacker could use a vulnerability in hfsplus to elevate privileges |
| ACTUAL VALUE | Found no files with lines matching &#39;^install\s+hfsplus\s+/bin/true&#39; in /etc/modprobe.d/ |

| NAME | Disable the installation and use of file systems that are not required (freevxfs) |
| --- | --- |
| RULE SEVERITY | Warning |
| FULL DESCRIPTION | Disable the installation and use of file systems that are not required (freevxfs) |
| POTENTIAL IMPACT | An attacker could use a vulnerability in freevxfs to elevate privileges |
| ACTUAL VALUE | Found no files with lines matching &#39;^install\s+freevxfs\s+/bin/true&#39; in /etc/modprobe.d/ |



| NAME | All bootloaders should have password protection enabled. |
| --- | --- |
| CCEID | CCE-3818-2 |
| RULE SEVERITY | Warning |
| FULL DESCRIPTION | All bootloaders should have password protection enabled. |
| POTENTIAL IMPACT | An attacker with physical access could modify bootloader options, yielding unrestricted system access |
| ACTUAL VALUE | File /boot/grub2/grub.cfg should contain one or more lines matching [&#39;^password\s+--encrypted\s+\S+&#39;] |

| NAME | Access to the root account via su should be restricted to the &#39;root&#39; group |
| --- | --- |
| CCEID | CCE-15047-4 |
| RULE SEVERITY | Critical |
| FULL DESCRIPTION | Access to the root account via su should be restricted to the &#39;root&#39; group |
| POTENTIAL IMPACT | An attacker could escalate permissions by password guessing if su is not restricted to users in the root group. |
| ACTUAL VALUE | File /etc/pam.d/su should contain one or more lines matching [&#39;^[\s\t]\*auth\s+required\s+pam\_wheel.so(\s+.\*)?\suse\_uid&#39;] |

| NAME | Ensure permissions on bootloader config are configured |
| --- | --- |
| RULE SEVERITY | Critical |
| FULL DESCRIPTION | Ensure permissions on bootloader config are configured |
| POTENTIAL IMPACT | Setting the permissions to read and write for root only prevents non-root users from seeing the boot parameters or changing them. Non-root users who read the boot parameters may be able to identify weaknesses in security upon boot and be able to exploit them. |
| ACTUAL VALUE | File &#39;/boot/grub2/grub.cfg&#39; has ownership/permissions errors: Mode is too permissive. Have 644, but want at least 400 |

| NAME | All rsyslog log files should be owned by the syslog user. |
| --- | --- |
| CCEID | CCE-17857-4 |
| RULE SEVERITY | Critical |
| FULL DESCRIPTION | All rsyslog log files should be owned by the syslog user. |
| POTENTIAL IMPACT | An attacker could cover up activity by manipulating logs |
| ACTUAL VALUE | File /etc/rsyslog.conf should contain one or more lines matching [&#39;^[\s]\*.FileOwner\s+syslog&#39;] |

| NAME | Disable support for RDS. |
| --- | --- |
| CCEID | CCE-14027-7 |
| RULE SEVERITY | Warning |
| FULL DESCRIPTION | Disable support for RDS. |
| POTENTIAL IMPACT | An attacker could use a vulnerability in RDS to compromise the system |
| ACTUAL VALUE | Found no files with lines matching &#39;^install\s+rds\s+/bin/true&#39; in /etc/modprobe.d/ |

| NAME | Postfix network listening should be disabled as appropriate. |
| --- | --- |
| CCEID | CCE-15018-5 |
| RULE SEVERITY | Critical |
| FULL DESCRIPTION | Postfix network listening should be disabled as appropriate. |
| POTENTIAL IMPACT | An attacker could use this system to send emails with malicious content to other users |
| ACTUAL VALUE | File /etc/postfix/main.cf should contain one or more lines matching [&#39;^[\s\t]\*inet\_interfaces\s+localhost\s\*$&#39;] |

| NAME | /etc/passwd- file permissions should be set to 0600 |
| --- | --- |
| CCEID | CCE-3932-1 |
| RULE SEVERITY | Critical |
| FULL DESCRIPTION | /etc/passwd- file permissions should be set to 0600 |
| POTENTIAL IMPACT | An attacker could join security groups if this file is not properly secured |
| ACTUAL VALUE | File &#39;/etc/passwd-&#39; has ownership/permissions errors: Mode is &#39;644&#39; but should be &#39;600&#39; |

| NAME | Logging of martian packets (those with impossible addresses) should be enabled for all interfaces. (net.ipv4.conf.all.log\_martians = 1) |
| --- | --- |
| CCEID | CCE-4320-8 |
| RULE SEVERITY | Critical |
| FULL DESCRIPTION | Logging of martian packets (those with impossible addresses) should be enabled for all interfaces. (net.ipv4.conf.all.log\_martians = 1) |
| POTENTIAL IMPACT | An attacker could send traffic from spoofed addresses without being detected |
| ACTUAL VALUE | Expected output of &#39;sysctl -a&#39; to match &#39;^net\.ipv4\.conf\.all\.log\_martians\s\*=\s\*1\s\*$&#39; |

| NAME | The postfix package should be uninstalled. |
| --- | --- |
| CCEID | CCE-14068-1 |
| RULE SEVERITY | Critical |
| FULL DESCRIPTION | The postfix package should be uninstalled. |
| POTENTIAL IMPACT | An attacker could use this system to send emails with malicious content to other users |
| ACTUAL VALUE | Package postfix should not be installed |

| NAME | The portmap service should be disabled. |
| --- | --- |
| CCEID | CCE-4550-0 |
| RULE SEVERITY | Critical |
| FULL DESCRIPTION | The portmap service should be disabled. |
| POTENTIAL IMPACT | An attacker could use a flaw in portmap to gain access |
| ACTUAL VALUE | Service &#39;rpcbind.service&#39; is not disabled |

| NAME | SSH warning banner should be enabled. - &#39;/etc/ssh/sshd\_config Banner = /etc/issue.net&#39; |
| --- | --- |
| CCEID | CCE-4431-3 |
| RULE SEVERITY | N/A |
