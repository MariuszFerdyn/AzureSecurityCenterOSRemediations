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
