# CMDmap custom payload directory
# ────────────────────────────────────────────────────────────────
# Drop any .txt files here. They are loaded unconditionally as
# Tier 5 extensions and are NEVER overwritten by updates.
#
# File format — same as core/ files:
#   # @label:  My payload label
#   # @signal: system:linux_id
#   # @blind:  false
#   # @os:     linux
#   ;my_payload_here
#
# Valid @signal values:
#   echo            — token echo confirmation
#   system:linux_id — uid=N(user) gid=N pattern
#   system:linux_user — bare username output
#   system:linux_uname — kernel version string
#   system:win_user — domain\user pattern
#   system:win_ver  — Microsoft Windows [Version ...] 
#   linux_passwd    — /etc/passwd content
#   win_ini         — win.ini [fonts] section
#   time            — timing-based blind (set @blind: true)
#   oob             — OOB callback (needs --collab)
#   oob_data        — OOB with data exfil
#   redirect:PATH   — file redirect confirmation
