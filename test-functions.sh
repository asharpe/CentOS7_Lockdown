#!/bin/bash

#This script will run through several checks and for each check output to the terminal 'OK' or 'ERROR
#The checks are designed to test whether or not the host conforms to the benchmarks in the
#following document
#https://benchmarks.cisecurity.org/tools2/linux/CIS_CentOS_Linux_7_Benchmark_v1.1.0.pdf

#This is aimed to be a starting point for a sysadmin to check or audit hosts he/she supports
#It's envisaged that it will need customising to suit a particular environment
#e.g. there are about 200 checks, someone may want to chop out X of them to suit their environment
#The script does not change anything on the host, mostly it runs a lot of greps & cuts
#on config files.
#To quickly get an idea of what this script does have a look at the 'main' and 'func_wrapper' functions
#Copyright (c) 2015, Ross Hamilton. All rights reserved.

#source $(dirname -- "$0")/test-utils.sh
#source $(dirname -- "$0")/test-functions.sh

FSTAB='/etc/fstab'
YUM_CONF='/etc/yum.conf'
GRUB_CFG='/boot/grub2/grub.cfg'
GRUB_DIR='/etc/grub.d'
SELINUX_CFG='/etc/selinux/config'
NTP_CONF='/etc/ntp.conf'
SYSCON_NTPD='/etc/sysconfig/ntpd'
LIMITS_CNF='/etc/security/limits.conf'
SYSCTL_CNF='/etc/sysctl.conf'
CENTOS_REL='/etc/centos-release'
LATEST_REL_STR='CentOS Linux release 7.1.1503 (Core)'
HOSTS_ALLOW='/etc/hosts.allow'
HOSTS_DENY='/etc/hosts.deny'
CIS_CNF='/etc/modprobe.d/CIS.conf'
RSYSLOG_CNF='/etc/rsyslog.conf'
AUDITD_CNF='/etc/audit/auditd.conf'
AUDIT_RULES='/etc/audit/audit.rules'
LOGR_SYSLOG='/etc/logrotate.d/syslog'
ANACRONTAB='/etc/anacrontab'
CRONTAB='/etc/crontab'
CRON_HOURLY='/etc/cron.hourly'
CRON_DAILY='/etc/cron.daily'
CRON_WEEKLY='/etc/cron.weekly'
CRON_MONTHLY='/etc/cron.monthly'
CRON_DIR='/etc/cron.d'
AT_ALLOW='/etc/at.allow'
AT_DENY='/etc/at.deny'
CRON_ALLOW='/etc/cron.allow'
CRON_DENY='/etc/cron.deny'
SSHD_CFG='/etc/ssh/sshd_config'
SYSTEM_AUTH='/etc/pam.d/system-auth'
PWQUAL_CNF='/etc/security/pwquality.conf'
PASS_AUTH='/etc/pam.d/password-auth'
PAM_SU='/etc/pam.d/su'
GROUP='/etc/group'
LOGIN_DEFS='/etc/login.defs'
PASSWD='/etc/passwd'
SHADOW='/etc/shadow'
GSHADOW='/etc/gshadow'
BASHRC='/etc/bashrc'
PROF_D='/etc/profile.d'
MOTD='/etc/motd'
ISSUE='/etc/issue'
ISSUE_NET='/etc/issue.net'
BANNER_MSG='/etc/dconf/db/gdm.d/01-banner-message'


function separate_partition {
	# Test that the supplied $1 is a separate partition

	local filesystem="${1}"
	grep -q "[[:space:]]${filesystem}[[:space:]]" "${FSTAB}" || return
}

function mount_option {
	# Test the the supplied mount option $2 is in use on the supplied filesystem $1

	local filesystem="${1}"
	local mnt_option="${2}"

	grep "[[:space:]]${filesystem}[[:space:]]" "${FSTAB}" | grep -q "${mnt_option}" || return

	mount | grep "[[:space:]]${filesystem}[[:space:]]" | grep -q "${mnt_option}" || return
}

function bind_mounted_to {
	# Test that a directory /foo/dir is bind mounted onto a particular filesystem

	local directory="${1}"
	local filesystem="${2}"
	local E_NO_MOUNT_OUTPUT=1

	grep "^${filesystem}[[:space:]]" "${FSTAB}" | grep -q "${directory}" || return

	local grep_mount
	grep_mount=$(mount | grep "^${filesystem}[[:space:]]" | grep "${directory}")
	#If $directory doesn't appear in the mount output as mounted on the $filesystem
	#it may appear in the output as being mounted on the same device as $filesystem, check for this
	local fs_dev
	local dir_dev
	fs_dev="$(mount | grep "[[:space:]]${filesystem}[[:space:]]" | cut -d" " -f1)"
	dir_dev="$(mount | grep "[[:space:]]${directory}[[:space:]]" | cut -d" " -f1)"
	if [[ -z "${grep_mount}" ]] && [[ "${fs_dev}" != "${dir_dev}" ]] ; then
		return "${E_NO_MOUNT_OUTPUT}"
	fi
}

function test_disable_mounting {
	# Test the the supplied filesystem type $1 is disabled
	test_module_disabled "$@"
}

function test_module_disabled {
	# Test that the install command for the supplied kernel module is /bin/true

	local module="${1}"
	modprobe -n -v ${module} | grep -q "install \+/bin/true" || return

	lsmod | grep -qv "${module}" || return
}

function centos_gpg_key_installed {
	# Test CentOS GPG Key is installed
	local centos_off_str='gpg(CentOS-7 Key (CentOS 7 Official Signing Key) <security@centos.org>)'
	rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey | grep -q "${centos_off_str}" || return
}

function yum_gpgcheck {
	# Check that gpgcheck is Globally Activated
	cut -d \# -f1 ${YUM_CONF} | grep 'gpgcheck' | grep -q 'gpgcheck=1' || return
}

function yum_update {
	# Check for outstanding pkg update with yum
	yum -q check-update >/dev/null || return
}

function pkg_integrity {
	# Verify the installed packages by comparing the installed files against file info stored in the pkg
	local rpm_out
	rpm_out="$(rpm -qVa | awk '$2 != "c" { print $0}')"
	[[ -z "${rpm_out}" ]] || return
}

function rpm_installed {
	# Test whether an rpm is installed

	local rpm="${1}"
	local rpm_out
	rpm_out="$(rpm -q --queryformat "%{NAME}\n" ${rpm})"
	[[ "${rpm}" = "${rpm_out}" ]] || return
}

function verify_aide_cron {
	# Verify there is a cron job scheduled to run the aide check
	crontab -u root -l | cut -d\# -f1 | grep -q "aide \+--check" || return
}

function verify_selinux_grubcfg {
	# Verify SELinux is not disabled in grub.cfg file

	local grep_out1
	grep_out1="$(grep selinux=0 ${GRUB_CFG})"
	[[ -z "${grep_out1}" ]] || return

	local grep_out2
	grep_out2="$(grep enforcing=0 ${GRUB_CFG})"
	[[ -z "${grep_out2}" ]] || return
}

function verify_selinux_state {
	# Verify SELinux configured state in /etc/selinux/config
	cut -d \# -f1 ${SELINUX_CFG} | grep 'SELINUX=' | tr -d '[[:space:]]' | grep -q 'SELINUX=enforcing' || return
}

function verify_selinux_policy {
	# Verify SELinux policy in /etc/selinux/config
	cut -d \# -f1 ${SELINUX_CFG} | grep 'SELINUXTYPE=' | tr -d '[[:space:]]' | grep -q 'SELINUXTYPE=targeted' || return
}

function rpm_not_installed {
  # Check that the supplied rpm(s) is not installed
	local package
	for package
	do
		rpm -q "$package" | grep -q "package ${package} is not installed" || return 1
	done
}

function unconfined_procs {
	# Test for unconfined daemons
	local ps_out
	ps_out="$(ps -eZ | egrep 'initrc|unconfined' | egrep -v 'bash|ps|grep')"
	[[ -n "${ps_out}" ]] || return
}

function check_grub_owns {
	# Check User/Group Owner on grub.cfg file
	stat -L -c "%u %g" ${GRUB_CFG} | grep -q '0 0' || return
}

function check_grub_perms {
	# Check Perms on grub.cfg file
	stat -L -c "%a" ${GRUB_CFG} | grep -q '.00' || return
}

function check_file_perms {
	# Check Perms on a supplied file match supplied pattern
	local file="${1}"
	local pattern="${2}"

	stat -L -c "%a" ${file} | grep -q "${pattern}" || return
}

function check_root_owns {
	# Check User/Group Owner on the specified file
	local file="${1}"
	stat -L -c "%u %g" ${file} | grep -q '0 0' || return
}

function check_boot_pass {
	grep -q 'set superusers=' "${GRUB_CFG}"
	if [[ "$?" -ne 0 ]]; then
		grep -q 'set superusers=' ${GRUB_DIR}/* || return
		file="$(grep 'set superusers' ${GRUB_DIR}/* | cut -d: -f1)"
		grep -q 'password' "${file}" || return
	else
		grep -q 'password' "${GRUB_CFG}" || return
	fi
}

function check_svc_not_enabled {
  # Verify that the service(s) is not enabled
	local service
	for service
	do
		systemctl list-unit-files | grep -q "${service}" || return 0
		systemctl is-enabled "${service}" 2>/dev/null | grep -q 'enabled' && return 1
	done
}

function check_svc_enabled {
  # Verify that the service(s) is enabled
  local service
  for service
  do
	 systemctl list-unit-files | grep -q "${service}.service" || return 1
	 systemctl is-enabled "${service}" 2>&1 | grep -q 'enabled' || return 1
  done
}

function ntp_cfg {
	cut -d\# -f1 ${NTP_CONF} | egrep "restrict{1}[[:space:]]+default{1}" ${NTP_CONF} | grep kod \
| grep nomodify | grep notrap | grep nopeer | grep -q noquery || return

	cut -d\# -f1 ${NTP_CONF} | egrep "restrict{1}[[:space:]]+\-6{1}[[:space:]]+default" | grep kod \
| grep nomodify | grep notrap | grep nopeer | grep -q noquery || return

	cut -d\# -f1 ${NTP_CONF} | egrep -q "^[[:space:]]*server" || return

	cut -d\# -f1 ${SYSCON_NTPD} | grep "OPTIONS=" | grep -q "ntp:ntp" || return
}

function restrict_core_dumps {
	# Verify that suid programs cannot dump their core
	egrep -q "\*{1}[[:space:]]+hard[[:space:]]+core[[:space:]]+0" "${LIMITS_CNF}" || return
	cut -d\# -f1 ${SYSCTL_CNF} | grep fs.suid_dumpable | cut -d= -f2 | tr -d '[[:space:]]' | grep -q '0' || return
}

function chk_sysctl_cnf {
	# Check the sysctl_conf file contains a particular flag, set to a particular value
	local flag="$1"
	local value="$2"
	local sysctl_cnf="$3"

	cut -d\# -f1 ${sysctl_cnf} | grep "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep -q "${value}" || return
}


function chk_sysctl {
	local flag="$1"
	local value="$2"

	sysctl "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep -q "${value}" || return
}

function chk_latest_rel {
	grep -q "${LATEST_REL_STR}" "${CENTOS_REL}" || return
}

function sticky_wrld_w_dirs {
	dirs="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \
\( -perm -0002 -a ! -perm -1000 \))"
	[[ -z "${dirs}" ]] || return
}

function check_umask {
	cut -d\# -f1 /etc/sysconfig/init | grep -q "umask[[:space:]]027" || return
}

function check_def_tgt {
	#Check that the default boot target is multi-user.target
	local default_tgt
	default_tgt="$(systemctl get-default)"
	[[ "${default_tgt}" = "multi-user.target" ]] || return
}

function mta_local_only {
	# If port 25 is being listened on, check it is on the loopback address
	netstat_out="$(netstat -an | grep "LIST" | grep ":25[[:space:]]")"
	if [[ "$?" -eq 0 ]] ; then
		ip=$(echo ${netstat_out} | cut -d: -f1 | cut -d" " -f4)
		[[ "${ip}" = "127.0.0.1" ]] || return
	fi
}

function ip6_router_advertisements_dis {
	# Check that IPv6 Router Advertisements are disabled
	# If ipv6 is disabled then we don't mind what IPv6 router advertisements are set to
	# If ipv6 is enabled then both settings should be set to zero
	chk_sysctl net.ipv6.conf.all.disable_ipv6 1 && return
	chk_sysctl net.ipv6.conf.all.accept_ra 0 || return
	chk_sysctl net.ipv6.conf.default.accept_ra 0 || return
}

function ip6_redirect_accept_dis {
	# Check that IPv6 Redirect Acceptance is disabled
	# If ipv6 is disabled then we don't mind what IPv6 redirect acceptance is set to
	# If ipv6 is enabled then both settings should be set to zero
	chk_sysctl net.ipv6.conf.all.disable_ipv6 1 && return
	chk_sysctl net.ipv6.conf.all.accept_redirects 0 || return
	chk_sysctl net.ipv6.conf.default.accept_redirects 0 || return
}

function chk_file_exists {
	local file="$1"
	[[ -f "${file}" ]] || return
}

function chk_hosts_deny_content {
	# Check the hosts.deny file resembles ALL: ALL
	cut -d\# -f1 ${HOSTS_DENY} | grep -q "ALL[[:space:]]*:[[:space:]]*ALL" || return
}

function chk_cis_cnf {
	local protocol="$1"
	local file="$2"
	grep -q "install[[:space:]]${protocol}[[:space:]]/bin/true" ${file} || return
}

function chk_rsyslog_content {
	# rsyslog should be configured to send logs to a remote host
	# grep output should resemble
	# *.* @@loghost.example.com
	grep -q "^*.*[^I][^I]*@" ${RSYSLOG_CNF} || return
}

function audit_log_storage_size {
	# Check the max size of the audit log file is configured
	cut -d\# -f1 ${AUDITD_CNF} | egrep -q "max_log_file[[:space:]]|max_log_file=" || return
}


function dis_on_audit_log_full {
	# Check auditd.conf is configured to notify the admin and halt the system when audit logs are full
	cut -d\# -f2 ${AUDITD_CNF} | grep 'space_left_action' | cut -d= -f2 | tr -d '[[:space:]]' | grep -q 'email' || return
	cut -d\# -f2 ${AUDITD_CNF} | grep 'action_mail_acct' | cut -d= -f2 | tr -d '[[:space:]]' | grep -q 'root' || return
	cut -d\# -f2 ${AUDITD_CNF} | grep 'admin_space_left_action' | cut -d= -f2 | tr -d '[[:space:]]' | grep -q 'halt' || return
}

function keep_all_audit_info {
	# Check auditd.conf is configured to retain audit logs
	cut -d\# -f2 ${AUDITD_CNF} | grep 'max_log_file_action' | cut -d= -f2 | tr -d '[[:space:]]' | grep -q 'keep_logs' || return
}

function audit_procs_prior_2_auditd {
	# Check lines that start with linux have the audit=1 parameter set
	grep_grub="$(grep "^[[:space:]]*linux" ${GRUB_CFG} | grep -v 'audit=1')"
	[[ -z "${grep_grub}" ]] || return
}

function audit_date_time {
	# Confirm that the time-change lines specified below do appear in the audit.rules file
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+time-change" | egrep "\-S[[:space:]]+settimeofday" \
	| egrep "\-S[[:space:]]+adjtimex" | egrep "\-F[[:space:]]+arch=b64" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+time-change" | egrep "\-S[[:space:]]+settimeofday" \
	| egrep "\-S[[:space:]]+adjtimex" | egrep "\-F[[:space:]]+arch=b32" | egrep "\-S[[:space:]]+stime" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+time-change" | egrep "\-F[[:space:]]+arch=b64" \
	| egrep "\-S[[:space:]]+clock_settime" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+time-change" | egrep "\-F[[:space:]]+arch=b32" \
	| egrep "\-S[[:space:]]+clock_settime" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+time-change" | egrep "\-p[[:space:]]+wa" \
	| egrep -q "\-w[[:space:]]+\/etc\/localtime" || return
}

function audit_user_group {
	# Confirm that the identity lines specified below do appear in the audit.rules file
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
	| egrep -q "\-w[[:space:]]+\/etc\/group" || return
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
	| egrep -q "\-w[[:space:]]+\/etc\/passwd" || return
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
	| egrep -q "\-w[[:space:]]+\/etc\/gshadow" || return
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
	| egrep -q "\-w[[:space:]]+\/etc\/shadow" || return
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
	| egrep -q "\-w[[:space:]]+\/etc\/security\/opasswd" || return
}

function audit_network_env {
	# Confirm that the system-locale lines specified below do appear in the audit.rules file
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-S[[:space:]]+sethostname" \
	| egrep "\-S[[:space:]]+setdomainname" | egrep "\-F[[:space:]]+arch=b64" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-S[[:space:]]+sethostname" \
	| egrep "\-S[[:space:]]+setdomainname" | egrep "\-F[[:space:]]+arch=b32" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-p[[:space:]]+wa" \
	| egrep -q "\-w[[:space:]]+\/etc\/issue" || return
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-p[[:space:]]+wa" \
	| egrep -q "\-w[[:space:]]+\/etc\/issue.net" || return
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-p[[:space:]]+wa" \
	| egrep -q "\-w[[:space:]]+\/etc\/hosts" || return
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-p[[:space:]]+wa" \
	| egrep -q "\-w[[:space:]]+\/etc\/sysconfig\/network" || return
}

function audit_logins_logouts {
	# Confirm that the logins lines specified below do appear in the audit.rules file
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+logins" | egrep "\-p[[:space:]]+wa" \
	| egrep -q "\-w[[:space:]]+\/var\/log\/faillog" || return
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+logins" | egrep "\-p[[:space:]]+wa" \
	| egrep -q "\-w[[:space:]]+\/var\/log\/lastlog" || return
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+logins" | egrep "\-p[[:space:]]+wa" \
	| egrep -q "\-w[[:space:]]+\/var\/log\/tallylog" || return
}

function audit_session_init {
	# Confirm that the logins lines specified below do appear in the audit.rules file
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+session" | egrep "\-p[[:space:]]+wa" \
	| egrep -q "\-w[[:space:]]+\/var\/run\/utmp" || return
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+session" | egrep "\-p[[:space:]]+wa" \
	| egrep -q "\-w[[:space:]]+\/var\/log\/wtmp" || return
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+session" | egrep "\-p[[:space:]]+wa" \
	| egrep -q "\-w[[:space:]]+\/var\/log\/btmp" || return
}

function audit_sys_mac {
	# Confirm that the logins lines specified below do appear in the audit.rules file
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+MAC-policy" | egrep "\-p[[:space:]]+wa" \
	| egrep -q "\-w[[:space:]]+\/etc\/selinux\/" || return
}

function audit_dac_perm_mod_events {
	# Confirm that perm_mod lines matching the patterns below do appear in the audit.rules file
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+chmod" \
	| egrep "\-S[[:space:]]+fchmod" | egrep "\-S[[:space:]]+fchmodat" | egrep "\-F[[:space:]]+arch=b64" \
	| egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
	| egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+chmod" \
	| egrep "\-S[[:space:]]+fchmod" | egrep "\-S[[:space:]]+fchmodat" | egrep "\-F[[:space:]]+arch=b32" \
	| egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
	| egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+chown" \
	| egrep "\-S[[:space:]]+fchown" | egrep "\-S[[:space:]]+fchownat" | egrep "\-S[[:space:]]+fchown" \
	| egrep "\-F[[:space:]]+arch=b64" | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
	| egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+chown" \
	| egrep "\-S[[:space:]]+fchown" | egrep "\-S[[:space:]]+fchownat" | egrep "\-S[[:space:]]+fchown" \
	| egrep "\-F[[:space:]]+arch=b32" | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
	| egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+setxattr" \
	| egrep "\-S[[:space:]]+lsetxattr" | egrep "\-S[[:space:]]+fsetxattr" | egrep "\-S[[:space:]]+removexattr" \
	| egrep "\-S[[:space:]]+lremovexattr" | egrep "\-S[[:space:]]+fremovexattr" | egrep "\-F[[:space:]]+arch=b64" \
	| egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
	| egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+setxattr" \
	| egrep "\-S[[:space:]]+lsetxattr" | egrep "\-S[[:space:]]+fsetxattr" | egrep "\-S[[:space:]]+removexattr" \
	| egrep "\-S[[:space:]]+lremovexattr" | egrep "\-S[[:space:]]+fremovexattr" | egrep "\-F[[:space:]]+arch=b32" \
	| egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
	| egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
}

function unsuc_unauth_acc_attempts {
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+access" | egrep "\-S[[:space:]]+creat" \
	| egrep "\-S[[:space:]]+open" | egrep "\-S[[:space:]]+openat" | egrep "\-S[[:space:]]+truncate" \
	| egrep "\-S[[:space:]]+ftruncate" | egrep "\-F[[:space:]]+arch=b64" | egrep "\-F[[:space:]]+auid>=1000" \
	| egrep "\-F[[:space:]]+auid\!=4294967295" | egrep "\-F[[:space:]]exit=\-EACCES" \
	| egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+access" | egrep "\-S[[:space:]]+creat" \
	| egrep "\-S[[:space:]]+open" | egrep "\-S[[:space:]]+openat" | egrep "\-S[[:space:]]+truncate" \
	| egrep "\-S[[:space:]]+ftruncate" | egrep "\-F[[:space:]]+arch=b32" | egrep "\-F[[:space:]]+auid>=1000" \
	| egrep "\-F[[:space:]]+auid\!=4294967295" | egrep "\-F[[:space:]]exit=\-EACCES" \
	| egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+access" | egrep "\-S[[:space:]]+creat" \
	| egrep "\-S[[:space:]]+open" | egrep "\-S[[:space:]]+openat" | egrep "\-S[[:space:]]+truncate" \
	| egrep "\-S[[:space:]]+ftruncate" | egrep "\-F[[:space:]]+arch=b64" | egrep "\-F[[:space:]]+auid>=1000" \
	| egrep "\-F[[:space:]]+auid\!=4294967295" | egrep "\-F[[:space:]]exit=\-EPERM" \
	| egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+access" | egrep "\-S[[:space:]]+creat" \
	| egrep "\-S[[:space:]]+open" | egrep "\-S[[:space:]]+openat" | egrep "\-S[[:space:]]+truncate" \
	| egrep "\-S[[:space:]]+ftruncate" | egrep "\-F[[:space:]]+arch=b32" | egrep "\-F[[:space:]]+auid>=1000" \
	| egrep "\-F[[:space:]]+auid\!=4294967295" | egrep "\-F[[:space:]]exit=\-EPERM" \
	| egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

}

function coll_priv_cmds {
	local priv_cmds
	priv_cmds="$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f)"
	for cmd in ${priv_cmds} ; do
		cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+privileged" | egrep "\-F[[:space:]]+path=${cmd}" \
		| egrep "\-F[[:space:]]+perm=x" | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
		| egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
	done
}

function coll_suc_fs_mnts {
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+mounts" | egrep "\-S[[:space:]]+mount" \
	| egrep "\-F[[:space:]]+arch=b64" | egrep "\-F[[:space:]]+auid>=1000" \
	| egrep "\-F[[:space:]]+auid\!=4294967295" \
	| egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+mounts" | egrep "\-S[[:space:]]+mount" \
	| egrep "\-F[[:space:]]+arch=b32" | egrep "\-F[[:space:]]+auid>=1000" \
	| egrep "\-F[[:space:]]+auid\!=4294967295" \
	| egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
}

function coll_file_del_events {
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+delete" | egrep "\-S[[:space:]]+unlink" \
	| egrep "\-F[[:space:]]+arch=b64" | egrep "\-S[[:space:]]+unlinkat" | egrep "\-S[[:space:]]+rename" \
	| egrep "\-S[[:space:]]+renameat" | egrep "\-F[[:space:]]+auid>=1000" \
	| egrep "\-F[[:space:]]+auid\!=4294967295" \
	| egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+delete" | egrep "\-S[[:space:]]+unlink" \
	| egrep "\-F[[:space:]]+arch=b32" | egrep "\-S[[:space:]]+unlinkat" | egrep "\-S[[:space:]]+rename" \
	| egrep "\-S[[:space:]]+renameat" | egrep "\-F[[:space:]]+auid>=1000" \
	| egrep "\-F[[:space:]]+auid\!=4294967295" \
	| egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

}

function coll_chg2_sysadm_scope {
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+scope" | egrep "\-p[[:space:]]+wa" \
	| egrep -q "\-w[[:space:]]+\/etc\/sudoers" || return

}

function coll_sysadm_actions {
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+actions" | egrep "\-p[[:space:]]+wa" \
	| egrep -q "\-w[[:space:]]+\/var\/log\/sudo.log" || return

}

function kmod_lod_unlod {
	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+modules" | egrep "\-p[[:space:]]+x" \
	| egrep -q "\-w[[:space:]]+\/sbin\/insmod" || return

	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+modules" | egrep "\-p[[:space:]]+x" \
	| egrep -q "\-w[[:space:]]+\/sbin\/rmmod" || return

	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+modules" | egrep "\-p[[:space:]]+x" \
	| egrep -q "\-w[[:space:]]+\/sbin\/modprobe" || return

	cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+modules" | egrep "\-S[[:space:]]+delete_module" \
	| egrep "\-F[[:space:]]+arch=b64" | egrep "\-S[[:space:]]+init_module" \
	| egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
}

function audit_cfg_immut {
	# There should be a "-e 2" at the end of the audit.rules file
	cut -d\# -f1 ${AUDIT_RULES} | egrep -q "^-e[[:space:]]+2" || return
}

function logrotate_cfg {
	[[ -f "${LOGR_SYSLOG}" ]] || return

	local timestamp
	timestamp=$(date '+%Y%m%d_%H%M%S')
	local tmp_data="/tmp/logrotate.tmp.${timestamp}"
	local file_list="/var/log/messages /var/log/secure /var/log/maillog /var/log/spooler /var/log/boot.log /var/log/cron"
	local line_num
	line_num=$(grep -n '{' "${LOGR_SYSLOG}" | cut -d: -f1)
	line_num=$((${line_num} - 1))
	head -${line_num} "${LOGR_SYSLOG}" > ${tmp_data}
	for file in ${file_list} ; do
		grep -q "${file}" ${tmp_data} || return
	done
	rm -f "${tmp_data}"
}

function atd_cfg {
 [[ ! -f ${AT_DENY} ]] || return
 [[ -f ${AT_ALLOW} ]] || return
 check_root_owns "${AT_ALLOW}"
 check_file_perms "${AT_ALLOW}" 600
}

function at_cron_auth_users {
 [[ ! -f ${AT_DENY} ]] || return
 [[ ! -f ${CRON_DENY} ]] || return
 check_root_owns "${CRON_ALLOW}"
 check_root_owns "${AT_ALLOW}"
 check_file_perms "${CRON_ALLOW}" 600
 check_file_perms "${AT_ALLOW}" 600
}

function chk_param {
	local file="${1}"
	local parameter="${2}"
	local value="${3}"
	cut -d\# -f1 ${file} | egrep -q "^${parameter}[[:space:]]+${value}" || return
}


function ssh_maxauthtries {
	local allowed_max="${1}"
	local actual_value
	actual_value=$(cut -d\# -f1 ${SSHD_CFG} | grep 'MaxAuthTries' | cut -d" " -f2)
	[[ ${actual_value} -le ${allowed_max} ]] || return
}

function ssh_access {
	local allow_users
	local allow_groups
	local deny_users
	local deny_users
	allow_users="$(cut -d\# -f1 ${SSHD_CFG} | grep "AllowUsers" | cut -d" " -f2)"
	allow_groups="$(cut -d\# -f1 ${SSHD_CFG} | grep "AllowGroups" | cut -d" " -f2)"
	deny_users="$(cut -d\# -f1 ${SSHD_CFG} | grep "DenyUsers" | cut -d" " -f2)"
	deny_groups="$(cut -d\# -f1 ${SSHD_CFG} | grep "DenyGroups" | cut -d" " -f2)"
	[[ -n "${allow_users}" ]] || return
	[[ -n "${allow_groups}" ]] || return
	[[ -n "${deny_users}" ]] || return
	[[ -n "${deny_groups}" ]] || return
}

function pass_hash_algo {
	local algo="${1}"
	authconfig --test | grep 'hashing' | grep -q "${algo}" || return
}

function pass_req_params {
	# verify the pam_pwquality.so params in /etc/pam.d/system-auth
	grep pam_pwquality.so ${SYSTEM_AUTH} | grep 'password' | grep 'requisite' | grep 'try_first_pass' | grep 'local_users_only' | grep 'retry=3' | grep -q 'authtok_type=' || return
	grep -q 'minlen=14' ${PWQUAL_CNF} || return
	grep -q 'dcredit=-1' ${PWQUAL_CNF} || return
	grep -q 'ucredit=-1' ${PWQUAL_CNF} || return
	grep -q 'ocredit=-1' ${PWQUAL_CNF} || return
	grep -q 'lcredit=-1' ${PWQUAL_CNF} || return
}

function failed_pass_lock {
 egrep "auth[[:space:]]+required" ${PASS_AUTH} | grep -q 'pam_deny.so' || return
 egrep "auth[[:space:]]+required" ${PASS_AUTH} | grep 'pam_faillock.so' | grep 'preauth' | grep 'audit' | grep 'silent' | grep 'deny=5' | grep -q 'unlock_time=900' || return
 grep 'auth' ${PASS_AUTH} | grep 'pam_unix.so' | egrep -q "\[success=1[[:space:]]+default=bad\]" || return
 grep 'auth' ${PASS_AUTH} | grep 'pam_faillock.so' | grep 'authfail' | grep 'audit' | grep 'deny=5' | grep 'unlock_time=900' | egrep -q "\[default=die\]" || return
 egrep "auth[[:space:]]+sufficient" ${PASS_AUTH} | grep 'pam_faillock.so' | grep 'authsucc' | grep 'audit' | grep 'deny=5' | grep -q 'unlock_time=900' || return
 egrep "auth[[:space:]]+required" ${PASS_AUTH} | grep -q 'pam_deny.so' || return

 egrep "auth[[:space:]]+required" ${SYSTEM_AUTH} | grep -q 'pam_env.so' || return
 egrep "auth[[:space:]]+required" ${SYSTEM_AUTH} | grep 'pam_faillock.so' | grep 'preauth' | grep 'audit' | grep 'silent' | grep 'deny=5' | grep -q 'unlock_time=900' || return
 grep 'auth' ${SYSTEM_AUTH} | grep 'pam_unix.so' | egrep -q "\[success=1[[:space:]]+default=bad\]" || return
 grep 'auth' ${SYSTEM_AUTH} | grep 'pam_faillock.so' | grep 'authfail' | grep 'audit' | grep 'deny=5' | grep 'unlock_time=900' | egrep -q "\[default=die\]" || return
 egrep "auth[[:space:]]+sufficient" ${SYSTEM_AUTH} | grep 'pam_faillock.so' | grep 'authsucc' | grep 'audit' | grep 'deny=5' | grep -q 'unlock_time=900' || return
 egrep "auth[[:space:]]+required" ${SYSTEM_AUTH} | grep -q 'pam_deny.so' || return
}

function lim_passwd_reuse {
 egrep "auth[[:space:]]+sufficient" ${SYSTEM_AUTH} | grep 'pam_unix.so' | grep -q 'remember=5' || return
}

function su_access {
	egrep "auth[[:space:]]+required" "${PAM_SU}" | grep 'pam_wheel.so' | grep -q 'use_uid' || return
	grep 'wheel' "${GROUP}" | cut -d: -f4 | grep -q 'root' || return
}

function dis_sys_accs {
	# Check that system accounts are disabled
	local accounts
	accounts="$(egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" \
&& $1!="halt" && $3<1000 && $7!="/sbin/nologin") {print}')"
	[[ -z "${accounts}" ]] || return
}

function root_def_grp {
	local gid1
	local gid2
	gid1="$(grep "^root:" "${PASSWD}" | cut -d: -f4)"
	[[ "${gid1}" -eq 0 ]] || return
	gid2="$(id -g root)"
	[[ "${gid2}" -eq 0 ]] || return
}

function def_umask_for_users {
	cut -d\#	-f1 "${BASHRC}" | egrep -q "umask[[:space:]]+077" || return
	egrep -q "umask[[:space:]]+077" ${PROF_D}/* || return
}

function inactive_usr_acs_locked {
	# After being inactive for a period of time the account should be disabled
	local days
	local inactive_threshold=35
	days="$(useradd -D | grep INACTIVE | cut -d= -f2)"
	[[ ${days} -ge ${inactive_threshold} ]] || return
}

function warning_banners {
	# Check that system login banners don't contain any OS information
	local motd
	local issue
	local issue_net
	motd="$(egrep '(\\v|\\r|\\m|\\s)' ${MOTD})"
	issue="$(egrep '(\\v|\\r|\\m|\\s)' ${ISSUE})"
	issue_net="$(egrep '(\\v|\\r|\\m|\\s)' ${ISSUE_NET})"
	[[ -z "${motd}" ]] || return
	[[ -z "${issue}" ]] || return
	[[ -z "${issue_net}" ]] || return
}

function gnome_banner {
	# On a host aiming to meet CIS requirements GNOME is unlikely to be installed
	# Thus the function says if the file exists then it should have these lines in it
	if [[ -f "${BANNER_MSG}" ]] ; then
		egrep '[org/gnome/login-screen]' ${BANNER_MSG} || return
		egrep 'banner-message-enable=true' ${BANNER_MSG} || return
		egrep 'banner-message-text=' ${BANNER_MSG} || return
	fi
}

function unowned_files {
	local uo_files
	uo_files="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser)"
	[[ -z "${uo_files}" ]] || return
}


function ungrouped_files {
	local ug_files
	ug_files="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup)"
	[[ -z "${ug_files}" ]] || return
}

function suid_exes {
  # For every suid exe on the host use the rpm cmd to verify that it should be suid executable
  # If the rpm cmd returns no output then the rpm is as it was when it was installed so no prob
  local suid_exes rpm rpm_out
  suid_exes="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print)"
  for suid_exe in ${suid_exes}
  do
	 rpm=$(rpm -qf $suid_exe)
	 rpm_out="$(rpm -V --noconfig $rpm | grep $suid_exe)"
	 [[ -z "${rpm_out}" ]] || return
  done
}

function sgid_exes {
  # For every sgid exe on the host use the rpm cmd to verify that it should be sgid executable
  # If the rpm cmd returns no output then the rpm is as it was when it was installed so no prob
  local sgid_exes rpm rpm_out
  sgid_exes="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print)"
  for sgid_exe in ${sgid_exes}
  do
	 rpm=$(rpm -qf $suid_exe)
	 rpm_out="$(rpm -V --noconfig $rpm | grep $suid_exe)"
	 [[ -z "${rpm_out}" ]] || return
  done
}

function passwd_field_chk {
	local shadow_out
	shadow_out="$(awk -F: '($2 == "" ) { print $1 }' ${SHADOW})"
	[[ -z "${shadow_out}" ]] || return
}

function nis_in_file {
	# Check for lines starting with + in the supplied file $1
	# In /etc/{passwd,shadow,group} it used to be a marker to insert data from NIS
	# There shouldn't be any entries like this
	local file="${1}"
	local grep_out
	grep_out="$(grep '^+:' ${file})"
	[[ -z "${grep_out}" ]] || return
}

function no_uid0_other_root {
	local grep_passwd
	grep_passwd="$(awk -F: '($3 == 0) { print $1 }' ${PASSWD})"
	[[ "${grep_passwd}" = "root" ]] || return
}

function world_w_dirs {
	dirs="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002)"
	[[ -z "${dirs}" ]] || return
}

function root_path {
	# There should not be an empty dir in $PATH
	local grep=/bin/grep
	local sed=/bin/sed
	path_grep="$(echo ${PATH} | ${grep} '::')"
	[[ -z "${path_grep}" ]] || return

	# There should not be a trailing : on $PATH
	path_grep="$(echo ${PATH} | ${grep} :$)"
	[[ -z "${path_grep}" ]] || return

	path_dirs="$(echo $PATH | ${sed} -e 's/::/:/' -e 's/:$//' -e 's/:/ /g')"
	for dir in ${path_dirs} ; do
		# PATH should not contain .
		[[ "${dir}" != "." ]] || return

		#$dir should be a directory
		[[ -d "${dir}" ]] || return

		local ls_out
		ls_out="$(ls -ldH ${dir})"
		if is_group_writable ${ls_out} ; then return 1 ; else return 0 ; fi
		if is_other_writable ${ls_out} ; then return 1 ; else return 0 ; fi


		# Directory should be owned by root
		dir_own="$(echo ${ls_out} | awk '{print $3}')"
		[[ "${dir_own}" = "root" ]] || return
	done
}

function is_group_readable {
	local ls_output="${1}"
	# 5th byte of ls output is the field for group readable
	[[ "${ls_output:4:1}" = "r" ]] || return
}

function is_group_writable {
	local ls_output="${1}"
	# 6th byte of ls output is the field for group writable
	[[ "${ls_output:5:1}" = "w" ]] || return
}

function is_group_executable {
	local ls_output="${1}"
	# 7th byte of ls output is the field for group readable
	[[ "${ls_output:6:1}" = "r" ]] || return
}

function is_other_readable {
	local ls_output="${1}"
	# 8th byte of ls output is the field for other readable
	[[ "${ls_output:7:1}" = "r" ]] || return
}

function is_other_writable {
	local ls_output="${1}"
	# 9th byte of ls output is the field for other writable
	[[ "${ls_output:8:1}" = "w" ]] || return
}

function is_other_executable {
	local ls_output="${1}"
	# 10th byte of ls output is the field for other executable
	[[ "${ls_output:9:1}" = "x" ]] || return
}

function home_dir_perms {
	dirs="$(grep -v 'root|halt|sync|shutdown' ${PASSWD} | awk -F: '($7 != "/sbin/nologin") { print $6 }')"
	[[ -z "${dirs}" ]] && return
	for dir in ${dirs} ; do
		[[ -d "${dir}" ]] || continue
		local ls_out
		ls_out="$(ls -ldH ${dir})"
		if is_group_writable ${ls_out} ; then return 1 ; else return 0 ; fi
		if is_other_readable ${ls_out} ; then return 1 ; else return 0 ; fi
		if is_other_writable ${ls_out} ; then return 1 ; else return 0 ; fi
		if is_other_executable ${ls_out} ; then return 1 ; else return 0 ; fi
	done
}

function dot_file_perms {
	dirs="$(grep -v 'root|halt|sync|shutdown' ${PASSWD} | awk -F: '($7 != "/sbin/nologin") { print $6 }')"
	for dir in ${dirs} ; do
		[[ -d "${dir}" ]] || continue
		for file in ${dir}/.[A-Za-z0-9]* ; do
			if [[ ! -h "${file}" && -f "${file}" ]] ; then
				local ls_out
				ls_out="$(ls -ldH ${dir})"
				if is_group_writable ${ls_out} ; then return 1 ; else return 0 ; fi
				if is_other_writable ${ls_out} ; then return 1 ; else return 0 ; fi
			fi
		done
	done
}

function dot_rhosts_files {
	dirs="$(grep -v 'root|halt|sync|shutdown' ${PASSWD} | awk -F: '($7 != "/sbin/nologin") { print $6 }')"
	for dir in ${dirs} ; do
		[[ -d "${dir}" ]] || continue
		local file="${dir}/.rhosts"
		if [[ ! -h "${file}" && -f "${file}" ]] ; then
			return 1
		else
			return 0
		fi
	done
}

function chk_groups_passwd {
	# We don't want to see any groups in /etc/passwd that aren't in /etc/group
	group_ids="$(cut -s -d: -f4 ${PASSWD} | sort -u)"
	for group_id in ${group_ids} ; do
		grep -q -P "^.*?:x:${group_id}:" ${GROUP} || return
	done
}

function chk_home_dirs_exist {
	#Check that users home directory do all exist
	while read user uid dir ; do
		if [[ "${uid}" -ge 1000 && ! -d "${dir}" && "${user}" != "nfsnobody" ]] ; then
			return 1
		fi
	done < <(awk -F: '{ print $1 " " $3 " " $6 }' ${PASSWD})
}

function chk_home_dirs_owns {
	#Check that users home directory do all exist
	while read user uid dir ; do
		if [[ "${uid}" -ge 1000 && ! -d "${dir}" && "${user}" != "nfsnobody" ]] ; then
			local owner
			owner="$(stat -L -c "%U" "${dir}")"
			[[ "${owner}" = "${user}" ]] || return
		fi
	done < <(awk -F: '{ print $1 " " $3 " " $6 }' ${PASSWD})
}

function dot_netrc_perms {
	dirs="$(grep -v 'root|halt|sync|shutdown' ${PASSWD} | awk -F: '($7 != "/sbin/nologin") { print $6 }')"
	for dir in ${dirs} ; do
		[[ -d "${dir}" ]] || continue
		for file in ${dir}/.netrc ; do
			if [[ ! -h "${file}" && -f "${file}" ]] ; then
				local ls_out
				ls_out="$(ls -ldH ${dir})"
				if is_group_readable ${ls_out} ; then return 1 ; else return 0 ; fi
				if is_group_writable ${ls_out} ; then return 1 ; else return 0 ; fi
				if is_group_executable ${ls_out} ; then return 1 ; else return 0 ; fi
				if is_other_readable ${ls_out} ; then return 1 ; else return 0 ; fi
				if is_other_writable ${ls_out} ; then return 1 ; else return 0 ; fi
				if is_other_executable ${ls_out} ; then return 1 ; else return 0 ; fi
			fi
		done
	done
}

function user_dot_netrc {
	# We don't want to see any ~/.netrc files
	local dirs
	dirs="$(cut -d: -f6 ${PASSWD})"
	for dir in ${dirs} ; do
		[[ -d "${dir}" ]] || continue
		if [[ ! -h "${dir}/.netrc" && -f "${dir}/.netrc" ]] ; then
			return 1
		fi
	done
}

function user_dot_forward {
	# We don't want to see any ~/.forward files
	local dirs
	dirs="$(cut -d: -f6 ${PASSWD})"
	for dir in ${dirs} ; do
		[[ -d "${dir}" ]] || continue
		if [[ ! -h "${dir}/.forward" && -f "${dir}/.forward" ]] ; then
			return 1
		fi
	done
}

function duplicate_uids {
	local num_of_uids
	local uniq_num_of_uids
	num_of_uids="$(cut -f3 -d":" ${PASSWD} | wc -l)"
	uniq_num_of_uids="$(cut -f3 -d":" ${PASSWD} | sort -n | uniq | wc -l)"
	[[ "${num_of_uids}" -eq "${uniq_num_of_uids}" ]] || return
}

function duplicate_gids {
	local num_of_gids
	local uniq_num_of_gids
	num_of_gids="$(cut -f3 -d":" ${GROUP} | wc -l)"
	uniq_num_of_gids="$(cut -f3 -d":" ${GROUP} | sort -n | uniq | wc -l)"
	[[ "${num_of_gids}" -eq "${uniq_num_of_gids}" ]] || return
}

function chk_uids_4_res {
  local default_users='root bin daemon adm lp sync shutdown halt mail news uucp operator games \
gopher ftp nobody nscd vcsa rpc mailnull smmsp pcap ntp dbus avahi sshd rpcuser systemd-network \
nfsnobody haldaemon avahi-autoipd distcache apache oprofile webalizer dovecot squid \
named xfs gdm sabayon usbmuxd rtkit abrt saslauth pulse postfix tcpdump polkitd tss chrony'
  while read user uid; do
	 local found=0
	 for duser in ${default_users} ${custom_system_users}; do
		if [[ "${user}" = "${duser}" ]] ; then
		  found=1
		fi
	 done
	 [[ "${found}" -eq 1 ]] || return
  done < <(awk -F: '($3 < 1000) {print $1" "$3 }' ${PASSWD})
}

function duplicate_usernames {
	local num_of_usernames
	local num_of_uniq_usernames
	num_of_usernames="$(cut -f1 -d":" ${PASSWD} | wc -l)"
	num_of_uniq_usernames="$(cut -f1 -d":" ${PASSWD} | sort | uniq | wc -l)"
	[[ "${num_of_usernames}" -eq "${num_of_uniq_usernames}" ]] || return
}

function duplicate_groupnames {
	local num_of_groupnames
	local num_of_uniq_groupnames
	num_of_groupnames="$(cut -f1 -d":" ${GROUP} | wc -l)"
	num_of_uniq_groupnames="$(cut -f1 -d":" ${GROUP} | sort | uniq | wc -l)"
	[[ "${num_of_groupnames}" -eq "${num_of_uniq_groupnames}" ]] || return
}

function check_disallowed_expansions {
	local file="$1"

	egrep -q '(\\v|\\r|\\m|\\s)' "$file"
}

function check_owner_group_perms {
	local target="$1"
	local owner="$2"
	local group="$3"
	local perms="$4"

	stat -L -c "%u %g" "$target" | grep -q "$owner $group" || return 1
	stat -L -c "%a" "$target" | grep -q "$perms" || return 1
}

function gdm_login_banner {
	if rpm -q gdm >/dev/null
	then
		local count=$(egrep -c 'user-db:user|system-db:gdm|file-db:/usr/share/gdm/greeter-dconf-defaults' /etc/dconf/profile/gdm)
		((count == 3)) || return 1

		count=$(egrep -c "banner-message-enable=true|banner-message-text='.+'" /etc/dconf/db/gdm.d/01-banner-message)
		((count == 2)) || return 1
	fi

	return 0
}

function time_sync_in_use {
	rpm -q ntp >/dev/null || rpm -q chrony >/dev/null
}

function ntp_is_configured {
	rpm -q ntp >/dev/null || return 0

	local restrict_count=$(egrep -c -- "^restrict -(4|6)" /etc/ntp.conf)
	local server_count=$(egrep -c -- "^server" /etc/ntp.conf)
	local user_count=0
	while read count
	do
		let "user_count+=$count"
	done < <(egrep -c "(OPTIONS|ExecStart).*ntp:ntp" /etc/sysconfig/ntpd /usr/lib/systemd/system/ntpd.service)
	ge 1 $restrict_count $server_count $user_count
}

function chrony_is_configured {
	rpm -q chrony >/dev/null || return 0

	local server_count=$(egrep -c -- "^server" /etc/chrony.conf)
	local user_count=$(egrep -c -- "-u chrony" /etc/sysconfig/chronyd)
	ge 1 $server_count $user_count
}

function x_not_installed {
	local package_count=$(rpm -qa 'xorg-x11*' | wc -l)
	eq 0 $package_count
}

function check_mta {
	#local service_count=$(netstat -an | grep LIST | grep ":25[[:space:]] | grep -v 127.0.0.1" | wc -l)
	#eq 0 $service_count
	ss -an | awk 'BEGIN { fail=0 } /LISTEN/ && $5 ~ /:25$/ { fail=1 } END { exit(fail) }'
}

function check_ip_forwarding {
	[[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" == 0 ]]
}

function disable_send_redirects {
	local all=$(sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null)
	local default=$(sysctl -n net.ipv4.conf.default.send_redirects 2>/dev/null)
	alleq 0 $all $default
}

function reject_source_routed_packets {
	local all=$(sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null)
	local default=$(sysctl -n net.ipv4.conf.default.accept_source_route 2>/dev/null)
	alleq 0 $all $default
}

function reject_icmp_redirects {
	local all=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)
	local default=$(sysctl -n net.ipv4.conf.default.accept_redirects 2>/dev/null)
	alleq 0 $all $default
}

function reject_secure_icmp_redirects {
	local all=$(sysctl -n net.ipv4.conf.all.secure_redirects 2>/dev/null)
	local default=$(sysctl -n net.ipv4.conf.default.secure_redirects 2>/dev/null)
	alleq 0 $all $default
}

function log_suspicious_packets {
	local all=$(sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null)
	local default=$(sysctl -n net.ipv4.conf.default.log_martians 2>/dev/null)
	alleq 1 $all $default
}

function ignore_icmp_broadcast {
	[[ "$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null)" == 1 ]]
}

function ignore_bogus_icmp {
	[[ "$(sysctl -n net.ipv4.icmp_ignore_bogus_error_responses 2>/dev/null)" == 1 ]]
}

function enable_reverse_path_filtering {
	local all=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null)
	local default=$(sysctl -n net.ipv4.conf.default.rp_filter 2>/dev/null)
	alleq 1 $all $default
}

function enable_tcp_syn_cookies {
	[[ "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)" == 1 ]]
}

function reject_ipv6_router_advertisements {
	local all=$(sysctl -n net.ipv6.conf.all.accept_ra 2>/dev/null)
	local default=$(sysctl -n net.ipv4.conf.default.accept_ra 2>/dev/null)
	alleq 0 $all $default
}

function reject_ipv6_redirects {
	local all=$(sysctl -n net.ipv6.conf.all.accept_redirects 2>/dev/null)
	local default=$(sysctl -n net.ipv4.conf.default.accept_redirects 2>/dev/null)
	alleq 0 $all $default
}

function ipv6_disabled {
	modprobe -c | awk '/options/ && /ipv6/ {print $NF}' | grep -q disable=1
}

function check_hosts_allow {
	line_count=$(egrep -v '^\s*(#|$)' /etc/hosts.allow | wc -l)
	ge 1 $line_count
}

function check_hosts_deny {
	deny_line=$(egrep -v '^\s*(#|$)' /etc/hosts.deny | head -n1)
	[[ "$deny_line" == "ALL: ALL" ]]
}

function check_firewall_policy {
	# if any policy is ACCEPT, we've failed
	iptables -nL | awk '$1 == "Chain" && $3 ~ /policy/ && $4 ~ /ACCEPT/ {exit 1}'
}

function check_firewall_loopback {
	local input="$(iptables -L INPUT -v -n)"
	local input_accept_line input_drop_line
	
	input_accept_line=$(awk '
		BEGIN { found=0 }
		$3 == "ACCEPT" && $6 == "lo" && $(NF-1) == "0.0.0.0/0" && $NF == "0.0.0.0/0" {
			print NR
			found=1
			exit
		}
		END { if(!found) exit(1)}' <<<"$input") || return 1
	input_drop_line=$(awk '
		$3 == "DROP" && $(NF-1) == "127.0.0.0/8" && $NF == "0.0.0.0/0" {
			print NR
			found=1
			exit
		}
		END { if(!found) exit(1)}' <<<"$input") || return 1

	((input_accept_line < input_drop_line)) || return 1

	iptables -L OUTPUT -v -n | awk '
		BEGIN { found=0 }
		$3 == "ACCEPT" && $7 == "lo" && $(NF-1) == "0.0.0.0/0" && $NF == "0.0.0.0/0" {
			found=1
			exit
		}
		END { if(!found) exit(1) }
	'
}

function check_firewall_outbound {
	# Audit:
	# Run the following command and verify all rules for new outbound, and established connections match site policy:
	#	iptables -L -v -n
	true

	# this is actually done via our nagios checks which look for local changes
}

function check_firewall_services {
	# TODO this only does world-listening ports, not non-local address listening
	local listening_ports=($(ss -lnut | awk '$5 ~ /^(\*|::):/ {n=split($5, a, ":"); print $1 ":" a[n]}' | uniq))
	local firewall_rules="$(iptables -L INPUT -v -n)"

	while IFS=: read proto port
	do
		# the options could be in a different order depending on the rule
		grep "dpt:$port" <<<"$firewall_rules" | grep -q $proto || return 1
	done < <(IFS=$'\n'; echo "${listening_ports[*]}")
}

function check_wireless_interfaces {
	local interfaces

	interfaces=$(iwconfig 2>/dev/null) || return 1

	# TODO learn the iwconfig output to check if any are active in
	#	ip link show up
}

function check_audit_log_size {
	# TODO verify some value
	awk '
		BEGIN { remaining=1 }
		$1 == "max_log_file" { --remaining }
		END { exit(remaining) }
	' /etc/audit/auditd.conf
}

function check_audit_log_full_action {
	awk '
		BEGIN { remaining=3 }
		$1 == "space_left_action" && $NF == "email" { --remaining }
		$1 == "action_mail_acct" && $NF == "root" { --remaining }
		$1 == "admin_space_left_action" && $NF == "halt" { --remaining }
		END { exit(remaining) }
	' /etc/audit/auditd.conf
}

function check_audit_log_deletion {
	awk '
		BEGIN { remaining=1 }
		$1 == "max_log_file_action" && $NF == "keep_logs" { --remaining }
		END { exit(remaining) }
	' /etc/audit/auditd.conf
}

function check_boot_audit {
	! (grep "^\s*linux" /boot/grub2/grub.cfg | grep -qv audit=1)
}

function check_audit_time_changes {
	local expected="$(cat <<-EOF
		-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
		-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
		-a always,exit -F arch=b64 -S clock_settime -k time-change
		-a always,exit -F arch=b32 -S clock_settime -k time-change
		-w /etc/localtime -p wa -k time-change
	EOF
	)"

	diff -q <(grep time-change /etc/audit/audit.rules) <(echo "$expected") >/dev/null 2>&1
}

function check_audit_user_group_changes {
	local expected="$(cat <<-EOF
		-w /etc/group -p wa -k identity
		-w /etc/passwd -p wa -k identity
		-w /etc/gshadow -p wa -k identity
		-w /etc/shadow -p wa -k identity
		-w /etc/security/opasswd -p wa -k identity
	EOF
	)"

	diff -q <(grep identity /etc/audit/audit.rules) <(echo "$expected") >/dev/null 2>&1
}

function check_audit_net_changes {
	local expected="$(cat <<-EOF
		-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
		-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
		-w /etc/issue -p wa -k system-locale
		-w /etc/issue.net -p wa -k system-locale
		-w /etc/hosts -p wa -k system-locale
		-w /etc/sysconfig/network -p wa -k system-locale
	EOF
	)"

	diff -q <(grep system-locale /etc/audit/audit.rules) <(echo "$expected") >/dev/null 2>&1
}

function check_audit_mac_policy_changes {
	local expected="$(cat <<-EOF
		-w /etc/selinux/ -p wa -k MAC-policy
	EOF
	)"

	diff -q <(grep MAC-policy /etc/audit/audit.rules) <(echo "$expected") >/dev/null 2>&1
}

function check_audit_login {
	local expected="$(cat <<-EOF
		-w /var/log/lastlog -p wa -k logins
		-w /var/run/faillock/ -p wa -k logins
	EOF
	)"

	diff -q <(grep logins /etc/audit/audit.rules) <(echo "$expected") >/dev/null 2>&1
}

function check_audit_session {
	local expected="$(cat <<-EOF
		-w /var/run/utmp -p wa -k session
		-w /var/log/wtmp -p wa -k session
		-w /var/log/btmp -p wa -k session
	EOF
	)"

	diff -q <(grep session /etc/audit/audit.rules) <(echo "$expected") >/dev/null 2>&1
}

function check_audit_perm_changes {
	local expected="$(cat <<-EOF
		-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
		-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
		-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
		-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
		-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
		-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
	EOF
	)"

	diff -q <(grep perm_mod /etc/audit/audit.rules) <(echo "$expected") >/dev/null 2>&1
}

function check_audit_login_failure {
	local expected="$(cat <<-EOF
		-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
		-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
		-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
		-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
	EOF
	)"

	diff -q <(grep access /etc/audit/audit.rules) <(echo "$expected") >/dev/null 2>&1
}

function check_audit_privileged_commands {
	local executable_partitions=(
		/
	)

	for partition in "${executable_partitions[@]}"
	do
		while read line
		do
			grep -q -- "$line" /etc/audit/audit.rules || return 1
		done < <(find "$partition" -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '
			{ print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }
		')
	done
}

function check_audit_mounts {
	local expected="$(cat <<-EOF
		-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
		-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
	EOF
	)"

	diff -q <(grep mounts /etc/audit/audit.rules) <(echo "$expected") >/dev/null 2>&1
}

function check_audit_deletes {
	local expected="$(cat <<-EOF
		-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
		-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
	EOF
	)"

	diff -q <(grep delete /etc/audit/audit.rules) <(echo "$expected") >/dev/null 2>&1
}

function check_audit_sudoers {
	local expected="$(cat <<-EOF
		-w /etc/sudoers -p wa -k scope
		-w /etc/sudoers.d -p wa -k scope
	EOF
	)"

	diff -q <(grep scope /etc/audit/audit.rules) <(echo "$expected") >/dev/null 2>&1
}

function check_audit_sudo_log {
	local expected="$(cat <<-EOF
		-w /var/log/sudo.log -p wa -k actions
	EOF
	)"

	diff -q <(grep actions /etc/audit/audit.rules) <(echo "$expected") >/dev/null 2>&1
}

function check_audit_modules {
	local expected="$(cat <<-EOF
		-w /sbin/insmod -p x -k modules
		-w /sbin/rmmod -p x -k modules
		-w /sbin/modprobe -p x -k modules
		-a always,exit arch=b64 -S init_module -S delete_module -k modules
	EOF
	)"

	diff -q <(grep modules /etc/audit/audit.rules) <(echo "$expected") >/dev/null 2>&1
}

function check_audit_immutable {
	local expected="$(cat <<-EOF
		-e 2
	EOF
	)"

	diff -q <(grep "^\s*[^#]" /etc/audit/audit.rules | tail -1) <(echo "$expected") >/dev/null 2>&1
}

function check_rsyslog_configured {
	# Review the contents of the /etc/rsyslog.conf file to ensure appropriate logging is set. In addition, run the following command and verify that the log files are logging information:
	#	ls -l /var/log/
	true
}

function check_rsyslog_permissions {
	local perm=$(awk '$1 == "$FileCreateMode" {print $NF}' /etc/rsyslog.conf)

	# verify that $FileCreateMode is 0640 or more restrictive
	[[ $perm == 0640 ]]
}

function check_rsyslog_remote {
	# Review the /etc/rsyslog.conf file and verify that logs are sent to a central host

	# this just checks for ANY remote logging, not a specific target
	local remote_lines=$(egrep -c "^\*.\*[^I]+@" /etc/rsyslog.conf)
	(( remote_lines ))
}

function check_rsyslog_remote_accepted {
	# Run the following commands and verify the resulting lines are uncommented on designated log hosts and commented or removed on all others

	# most servers want these commented
	# TODO an option to toggle this
	local regex='^[[:space:]]*#(\$InputTCPServerRun|\$ModLoad imtcp)'
	#local regex='^[[:space:]]*(\$InputTCPServerRun|\$ModLoad imtcp)'

	local lines=$(egrep -c "$regex" /etc/rsyslog.conf)
	(( lines == 2 ))
}

function check_syslog_ng_configured {
	# Review the contents of the /etc/rsyslog.conf file to ensure appropriate logging is set. In addition, run the following command and verify that the log files are logging information:
	#	ls -l /var/log/
	true
}

function check_syslog_ng_permissions {
	# verify the perm option is 0640 or more restrictive

	local perms=$(grep -c 'perm(0640)' /etc/syslog-ng/syslog-ng.conf)
	# anything non-zero is success
	(( perms ))
}

function check_syslog_ng_remote {
	# Review the /etc/syslog-ng/syslog-ng.conf file and verify that logs are sent to a central host

	# TODO this check is bogus, it doesn't distinguish between source and destination

	# this just checks for ANY remote logging, not a specific target
	local remote_lines=$(egrep -c "tcp" /etc/syslog-ng/syslog-ng.conf)
	(( remote_lines ))
}

function check_syslog_ng_remote_accepted {
	# TODO this check is bogus, it doesn't distinguish between source and destination

	local remote_lines=$(egrep -c "tcp" /etc/syslog-ng/syslog-ng.conf)
	(( remote_lines ))
}

function check_logging_installed {
	rpm_installed rsyslog || rpm_installed syslog-ng
}

function check_logfile_permissions {
	local bogus_logs=$(find /var/log -type f -perm /007 -ls | wc -l)
	(( bogus_logs == 0 ))
}

function check_logrotate {
	# Review /etc/logrotate.conf and /etc/logrotate.d/* and verify logs are rotated according to site policy.
	true
}

function check_cron_restrictions {
	(
		! [[ -f /etc/cron.deny ]] && ! [[ -f /etc/at.deny ]]
	) || return 1

	check_owner_group_perms /etc/cron.allow 0 0 600 \
		&& check_owner_group_perms /etc/at.allow 0 0 600
}

function check_ssh_protocol {
	awk '
		tolower($1) == "protocol" && $2 == 2 { found=1 }
		BEGIN { found=0 }
		END { exit(!found) }
	' /etc/ssh/sshd_config
}

function check_ssh_log_level {
	awk '
		tolower($1) == "loglevel" && $2 == "INFO" { found=1 }
		BEGIN { found=0 }
		END { exit(!found) }
	' /etc/ssh/sshd_config
}

function check_ssh_X_forwarding {
	# TODO other acceptable values for "no"
	awk '
		tolower($1) == "x11forwarding" && $2 == "no" { found=1 }
		BEGIN { found=0 }
		END { exit(!found) }
	' /etc/ssh/sshd_config
}

function check_ssh_max_auth_tries {
	awk '
		tolower($1) == "maxauthtries" && $2 <= 4 { found=1 }
		BEGIN { found=0 }
		END { exit(!found) }
	' /etc/ssh/sshd_config
}

function check_ssh_ignore_rhosts {
	# TODO other acceptable values for "yes"
	awk '
		tolower($1) == "ignorerhosts" && $2 == "yes" { found=1 }
		BEGIN { found=0 }
		END { exit(!found) }
	' /etc/ssh/sshd_config
}

function check_ssh_host_based_auth {
	awk '
		tolower($1) == "hostbasedauthentication" && $2 == "no" { found=1 }
		BEGIN { found=0 }
		END { exit(!found) }
	' /etc/ssh/sshd_config
}

function check_ssh_root_login {
	awk '
		tolower($1) == "permitrootlogin" && $2 == "no" { found=1 }
		BEGIN { found=0 }
		END { exit(!found) }
	' /etc/ssh/sshd_config
}

function check_ssh_empty_passwords {
	awk '
		tolower($1) == "permitemptypasswords" && $2 == "no" { found=1 }
		BEGIN { found=0 }
		END { exit(!found) }
	' /etc/ssh/sshd_config
}

function check_ssh_user_environment {
	awk '
		tolower($1) == "permituserenvironment" && $2 == "no" { found=1 }
		BEGIN { found=0 }
		END { exit(!found) }
	' /etc/ssh/sshd_config
}

function check_ssh_ciphers {
	local bad_cipers=$(awk 'tolower($1) == "ciphers" {print $NF}' /etc/ssh/sshd_config | sed -e 's/,/\n/g' | grep -c -- -cbc)

	(( !bad_ciphers ))
}

function check_ssh_MACs {
	# Run the following command and verify that output does not contain any unlisted MAC algorithms:
	#	grep "MACs" /etc/ssh/sshd_config

	# WAT?

	true
}

function check_ssh_idle_timeout {
	awk '
		tolower($1) == "clientaliveinterval" && $2 <= 300 { --required }
		tolower($1) == "clientalivecountmax" && $2 <= 3 { --required }
		BEGIN { required=2 }
		END { exit(required) }
	' /etc/ssh/sshd_config
}

function check_ssh_login_grace {
	awk '
		tolower($1) == "logingracetime" && $2 <= 60 { found=1 }
		BEGIN { found=0 }
		END { exit(!found) }
	' /etc/ssh/sshd_config
}

function check_ssh_access {
	local restrictions=$(egrep -ic "(Allow|Deny)(Users|Groups)" /etc/ssh/sshd_config)
	(( restrictions ))
}

function check_ssh_banner {
	awk '
		tolower($1) == "banner" && $2 == "/etc/issue.net" { found=1 }
		BEGIN { found=0 }
		END { exit(!found) }
	' /etc/ssh/sshd_config
}

function check_umask {
	local bad_umasks=$(grep -h '^\s*umask' /etc/bashrc /etc/profile | grep -v 027 | wc -l)
	(( ! bad_umasks ))
}

function check_root_login_console {
	local allowed_consoles=(
		console
		tty1
	)

	local bad_consoles=$(egrep -v "$(IFS='|'; echo "${allowed_consoles[*]}")" /etc/securetty)
	(( ! bad_consoles ))
}

function check_su_restrictions {
	local using_pam_wheel=$(grep pam_wheel.so /etc/pam.d/su | grep -vc '^\s*#')	

	(( using_pam_wheel )) || return 1

	# the list of wheel users should match site policy which is managed by puppet
	#local wheel_users=($(getent group wheel | awk -F: '{print $4}' | sed -e "s^,^ ^g"))
}

