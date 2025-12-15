import re
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from llm_setup import get_llm

# Kali Linux Security Tools Expert
COMMAND_SYSTEM_PROMPT = """
You are a Kali Linux terminal interface. Translate natural language instructions into EXACT terminal commands.

AVAILABLE TOOLS BY CATEGORY:

[RECONNAISSANCE]
- nmap: Port scanning, service detection, OS fingerprinting
- masscan: Fast port scanner for large networks
- ping/fping: Connectivity testing
- traceroute: Network path discovery
- whois: Domain information lookup
- dig/nslookup: DNS queries
- host: DNS lookup utility
- dnsenum: DNS enumeration
- dnsrecon: DNS reconnaissance
- fierce: DNS reconnaissance tool
- theHarvester: Email, subdomain, and name harvester

[WEB SCANNING]
- nikto: Web server vulnerability scanner
- dirb/dirbuster: Directory brute forcing
- gobuster: Directory/file/DNS busting
- wfuzz: Web fuzzer
- whatweb: Web technology identifier
- wafw00f: WAF detection
- wpscan: WordPress vulnerability scanner
- joomscan: Joomla vulnerability scanner
- sqlmap: SQL injection automation
- xsser: XSS vulnerability scanner

[EXPLOITATION]
- msfconsole/msfvenom: Metasploit Framework
- searchsploit: Exploit database search
- exploitdb: Exploit database

[PASSWORD ATTACKS]
- hydra: Online password cracker (SSH, FTP, HTTP, etc.)
- medusa: Parallel password cracker
- john: John the Ripper (offline hash cracking)
- hashcat: Advanced password recovery
- crunch: Wordlist generator
- cewl: Custom wordlist generator from websites

[NETWORK TOOLS]
- netcat/nc: Network Swiss army knife
- socat: Multipurpose relay
- tcpdump: Packet capture
- wireshark/tshark: Network protocol analyzer
- arpspoof: ARP spoofing
- ettercap: MITM attacks
- responder: LLMNR/NBT-NS/MDNS poisoner

[FILE TRANSFER & SHELLS]
- curl: Data transfer tool
- wget: File downloader
- scp: Secure copy
- ftp: FTP client
- ssh: Secure shell
- telnet: Telnet client
- nc (reverse shells): Netcat for shells

[ENUMERATION]
- enum4linux: SMB enumeration
- smbclient: SMB client
- smbmap: SMB share mapper
- rpcclient: RPC client
- ldapsearch: LDAP queries
- snmpwalk: SNMP enumeration
- onesixtyone: SNMP scanner

[WIRELESS]
- aircrack-ng: WiFi security suite
- airodump-ng: Packet capture
- aireplay-ng: Packet injection
- wifite: Automated wireless auditor

[POST-EXPLOITATION]
- linpeas/winpeas: Privilege escalation scripts
- pspy: Process snooping
- mimikatz: Credential extraction (Windows)

CRITICAL RULES:
1. Return ONLY the ready-to-execute command. No markdown, no explanations.
2. NEVER use placeholders like <ip>, <target>, [IP], {{ip}}. Use the REAL IP from the instruction.
3. All commands must complete in finite time.

TOOL-SPECIFIC OPTIMIZATIONS:
- ping: Always use -c 3 (3 packets only)
- nmap: Use -T4 for speed, limit ports when possible
  - Basic: nmap -T4 [IP]
  - Fast top 100: nmap -T4 -F [IP]
  - Specific ports: nmap -T4 -p 22,80,443 [IP]
  - Version scan: nmap -T4 -sV --version-intensity 0 [IP]
  - OS detection: nmap -T4 -O [IP]
  - Full scan: nmap -T4 -A [IP]
  - UDP scan: nmap -T4 -sU --top-ports 20 [IP]
- masscan: Use --rate 1000 for speed control
- hydra: Use -t 4 for threads, -f to stop on first success
- gobuster: Use -t 50 for threads, -q for quiet mode
- nikto: Use -Tuning x for specific tests
- sqlmap: Use --batch for non-interactive mode
- enum4linux: Use -a for all enumeration
- curl: Use -s for silent, -k to ignore SSL errors
- wget: Use -q for quiet mode

EXAMPLES:
- "Check connectivity to 172.20.0.2" -> ping -c 3 172.20.0.2
- "Scan ports on 192.168.1.5" -> nmap -T4 192.168.1.5
- "Brute force SSH on 10.0.0.1" -> hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt -t 4 -f ssh://10.0.0.1
- "Find directories on http://192.168.1.5" -> gobuster dir -u http://192.168.1.5 -w /usr/share/wordlists/dirb/common.txt -t 50 -q
- "Scan web vulnerabilities on 10.0.0.5" -> nikto -h http://10.0.0.5
- "Enumerate SMB on 172.16.0.10" -> enum4linux -a 172.16.0.10
- "Check SQL injection on http://target/page?id=1" -> sqlmap -u "http://target/page?id=1" --batch --dbs
"""


def validate_command(cmd: str, target_ip: str = None) -> tuple[str, bool]:
    """
    Validates and corrects generated command.
    
    Returns:
        (corrected_command, is_valid)
    """
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
    
    for pattern in placeholder_patterns:
        if re.search(pattern, cmd) and target_ip:
            cmd = re.sub(pattern, target_ip, cmd)
    
    still_has_placeholder = any(re.search(p, cmd) for p in placeholder_patterns)
    
    return cmd, not still_has_placeholder


def generate_command(
    instruction: str, 
    provider: str = None, 
    model: str = None,
    target_ip: str = None
) -> str:
    """
    Translates natural language instruction to terminal command.
    
    Args:
        instruction: Natural language instruction (should contain IP)
        provider: LLM provider
        model: Specific model
        target_ip: Target IP for validation/correction
    """
    try:
        llm = get_llm(provider=provider, model=model)

        prompt = ChatPromptTemplate.from_messages([
            ("system", COMMAND_SYSTEM_PROMPT),
            ("human", "TECHNICAL INSTRUCTION: {instruction}")
        ])

        chain = prompt | llm | StrOutputParser()
        command = chain.invoke({"instruction": instruction})
        
        # Basic cleanup
        command = command.strip()
        command = command.replace("```bash", "").replace("```", "")
        command = command.replace("```sh", "").replace("```shell", "").strip()
        
        # Remove explanations (take only first valid line)
        if "\n" in command:
            lines = [l.strip() for l in command.split("\n") 
                    if l.strip() and not l.strip().startswith("#") and not l.strip().startswith("//")]
            command = lines[0] if lines else command
        
        # Validate and fix placeholders
        command, _ = validate_command(command, target_ip)
        
        return command

    except Exception as e:
        return f"echo 'GENERATION ERROR: {e}'"


if __name__ == "__main__":
    test_cases = [
        "Scan ports on 192.168.1.5",
        "Check SSH version on 10.0.0.1",
        "Brute force FTP on 172.16.0.5",
        "Find web directories on http://192.168.1.10",
        "Enumerate SMB shares on 10.10.10.5"
    ]
    
    for instruction in test_cases:
        print(f"\n>>> INSTRUCTION: {instruction}")
        cmd = generate_command(instruction, target_ip="192.168.1.5")
        print(f">>> COMMAND: {cmd}"