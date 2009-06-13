#!/usr/local/bin/gawk -f
#
# ssh brutforce attack detector for FreeBSD
#
# Usage:
#
# 1) add to /etc/syslog.conf
# auth.* |exec /path/sshblock.awk
#
# 2) add to /etc/hosts.allow (at the begin of the file)
# # sshblock.allow
# # sshblock.deny
# # sshblock.end
#
# 3) restart syslogd
# /etc/rc.d/syslogd restart
#

# Initialization
BEGIN {
	HOSTSALLOW = "/etc/hosts.allow"; # hosts.allow full path
	CMD_TOUCH = "/usr/bin/touch"; # touch command
	CMD_CP = "/bin/cp";           # cp command
	COUNTER = "####"; # Counter, max attempts - 1
	# hosts.allow blocks
	block_header = "";
	block_allow = "";
	block_deny = "";
	block_footer = "";
}

# Trim string
function trim(s)
{
	sub("^[[:space:]]+", "", s);
	sub("[[:space:]]+$", "", s);
	return s;
}

# Turn constant string into regexp
function str2regexp(s)
{
	gsub("\\.", "\\.", s); # Currently process only '.'
	return s;
}

# Remove IP record from list
function remove_ip(list, ip)
{
	gsub("[^\\n]*" str2regexp(ip) "[^\\n]*\\n", "", list);
	return list;
}

# Touch and backup hosts.allow before modification
function touch_and_backup()
{
	system(CMD_TOUCH " " HOSTSALLOW);
	system(CMD_CP" " HOSTSALLOW " " HOSTSALLOW ".bak");
}

# Read hosts.allow
function read_hosts_allow(curr_block, raw_str, trim_str)
{
	# Reset blocks
	block_header = "";
	block_allow = "";
	block_deny = "";
	block_footer = "";
	curr_block = "header"; # Current block, header first
	while (getline raw_str < HOSTSALLOW) # Read lines
	{
		trim_str = trim(raw_str); #Trimmed string for allow/deny blocks and block detection
		# Detect and switch block
		if (match(trim_str, "#[[:space:]]*" str2regexp("sshblock.allow")))
		{
			curr_block = "allow";
			continue;
		}
		if (match(trim_str, "#[[:space:]]*" str2regexp("sshblock.deny")))
		{
			curr_block = "deny";
			continue;
		}
		if (match(trim_str, "#[[:space:]]*" str2regexp("sshblock.end")))
		{
			curr_block = "footer";
			continue;
		}
		# Current data string procession
		if (curr_block == "header"){
			block_header = block_header raw_str "\n";
			continue;
		}
		if (curr_block == "footer"){
			block_footer = block_footer raw_str "\n";
			continue;
		}
		if (trim_str=="") continue; # Skip empty strings in allow/deny blocks
		if (curr_block == "allow"){
			block_allow = block_allow trim_str "\n";
			continue;
		}
		if (curr_block == "deny"){
			block_deny = block_deny trim_str "\n";
			continue;
		}
	}
	close(HOSTSALLOW);
}

# Write hosts.allow
function write_hosts_allow(file_str)
{
	# Concatenate blocks
	file_str = block_header "# sshblock.allow\n" block_allow "\n# sshblock.deny\n" block_deny "\n# sshblock.end\n" block_footer;
	# Save to file
	printf("%s", file_str) > HOSTSALLOW;
	close(HOSTSALLOW);
}

# Add IP record
function ip_allow(ip, flag_allow, re_ip, old_str)
{
	touch_and_backup();
	read_hosts_allow();
	if (flag_allow){
		block_deny = remove_ip(block_deny, ip); # Delete deny record
		block_allow = "sshd: " ip ": allow\n" remove_ip(block_allow, ip); # Move allow record to the beginning
	}
	else
	{
		re_ip = str2regexp(ip);
		if (!match(block_allow, re_ip)){ # Skip, if allow record exists
			if (match(block_deny, "([^\\n]*" re_ip "[^\\n]*)", old_str)) # Search old IP records
			{
				sub("^#", "", old_str[1]); # Decrement counter
				block_deny = old_str[1] "\n" remove_ip(block_deny, ip); # Move deny record to the beginning
			}
			else
			{
				block_deny = COUNTER "sshd: " ip ": deny\n" block_deny; # Add new record with counter to the beginning
			}
		}
	}
	write_hosts_allow();
}

# Input strings processing
{
	# Process only accepted/failed login log messages
	if (match($0, "^.* sshd\\[[[:digit:]]+\\]: (Accepted|Failed) .* for .* from ([[:digit:].]+) port [[:digit:]]+ ssh2$", params))
		ip_allow(params[2], (params[1]=="Accepted") ? 1 : 0); # Modify hosts.allow
	# Process "invalid user" messages
	if (match($0, "^.* sshd\\[[[:digit:]]+\\]: Invalid user .* from ([[:digit:].]+)$", params))
		ip_allow(params[1], 0); # Modify hosts.allow
}
