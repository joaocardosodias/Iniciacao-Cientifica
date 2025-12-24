"""
Tools API endpoints.

Requirements:
- 4.1: Display all available tools grouped by category
- 8.5: Return tool definitions with parameter schemas
"""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends

from fragmentum.web.backend.models.schemas import (
    ErrorResponse,
)
from fragmentum.tools.registry import get_tool_registry, Tool as RegistryTool

router = APIRouter(prefix="/tools", tags=["tools"])


# Tool grouping configuration - maps base tool name to its variants
TOOL_GROUPS = {
    "nmap": {
        "name": "Nmap",
        "description": "Network exploration and security auditing",
        "variants": {
            "basic": {"tool": "nmap", "label": "Basic Scan", "description": "Service version and script scan (-sV -sC)"},
            "full": {"tool": "nmap_full", "label": "Full Scan", "description": "All ports with aggressive detection (-p- -A)"},
            "vuln": {"tool": "nmap_vuln", "label": "Vulnerability Scan", "description": "Run vulnerability scripts (--script=vuln)"},
            "udp": {"tool": "nmap_udp", "label": "UDP Scan", "description": "Top 100 UDP ports (-sU)"},
            "stealth": {"tool": "nmap_stealth", "label": "Stealth Scan", "description": "SYN scan with fragmentation (-sS -f)"},
            "os": {"tool": "nmap_os", "label": "OS Detection", "description": "Operating system detection (-O)"},
        }
    },
    "hydra": {
        "name": "Hydra",
        "description": "Network logon cracker - brute force attacks",
        "variants": {
            "ssh": {"tool": "hydra_ssh", "label": "SSH", "description": "Brute force SSH login"},
            "ftp": {"tool": "hydra_ftp", "label": "FTP", "description": "Brute force FTP login"},
            "http": {"tool": "hydra_http", "label": "HTTP Form", "description": "Brute force HTTP POST form"},
            "smb": {"tool": "hydra_smb", "label": "SMB", "description": "Brute force SMB/Windows login"},
            "rdp": {"tool": "hydra_rdp", "label": "RDP", "description": "Brute force Remote Desktop"},
            "mysql": {"tool": "hydra_mysql", "label": "MySQL", "description": "Brute force MySQL login"},
            "postgres": {"tool": "hydra_postgres", "label": "PostgreSQL", "description": "Brute force PostgreSQL login"},
        }
    },
    "impacket": {
        "name": "Impacket",
        "description": "Python classes for network protocols - Windows/AD attacks",
        "variants": {
            "secretsdump": {"tool": "impacket_secretsdump", "label": "Secrets Dump", "description": "Dump hashes from DC"},
            "psexec": {"tool": "impacket_psexec", "label": "PSExec", "description": "Remote command execution via PSExec"},
            "wmiexec": {"tool": "impacket_wmiexec", "label": "WMIExec", "description": "Remote command execution via WMI"},
            "smbexec": {"tool": "impacket_smbexec", "label": "SMBExec", "description": "Remote command execution via SMB"},
            "dcomexec": {"tool": "impacket_dcomexec", "label": "DCOMExec", "description": "Remote command execution via DCOM"},
            "atexec": {"tool": "impacket_atexec", "label": "ATExec", "description": "Remote command via Task Scheduler"},
        }
    },
    "msfvenom": {
        "name": "MSFVenom",
        "description": "Payload generator for Metasploit",
        "variants": {
            "linux": {"tool": "msfvenom_linux", "label": "Linux ELF", "description": "Linux reverse shell (ELF)"},
            "windows": {"tool": "msfvenom_windows", "label": "Windows EXE", "description": "Windows reverse shell (EXE)"},
            "php": {"tool": "msfvenom_php", "label": "PHP", "description": "PHP reverse shell"},
        }
    },
    "crackmapexec": {
        "name": "CrackMapExec",
        "description": "Swiss army knife for pentesting Windows/AD",
        "variants": {
            "smb": {"tool": "crackmapexec_smb", "label": "SMB", "description": "SMB password spray"},
            "winrm": {"tool": "crackmapexec_winrm", "label": "WinRM", "description": "WinRM password spray"},
        }
    },
    "dirbuster": {
        "name": "Directory Bruteforce",
        "description": "Web directory and file discovery",
        "variants": {
            "gobuster": {"tool": "gobuster", "label": "Gobuster", "description": "Fast Go-based scanner"},
            "ffuf": {"tool": "ffuf", "label": "FFUF", "description": "Fast web fuzzer"},
            "dirb": {"tool": "dirb", "label": "Dirb", "description": "Classic directory scanner"},
            "feroxbuster": {"tool": "feroxbuster", "label": "Feroxbuster", "description": "Recursive content discovery"},
            "wfuzz": {"tool": "wfuzz", "label": "WFuzz", "description": "Web application fuzzer"},
        }
    },
    "smb": {
        "name": "SMB Enumeration",
        "description": "SMB/Samba enumeration tools",
        "variants": {
            "enum4linux": {"tool": "enum4linux", "label": "Enum4Linux", "description": "Full SMB enumeration"},
            "smbclient": {"tool": "smbclient", "label": "SMBClient", "description": "List SMB shares"},
            "smbmap": {"tool": "smbmap", "label": "SMBMap", "description": "Map SMB shares and permissions"},
        }
    },
    "dns": {
        "name": "DNS Enumeration",
        "description": "DNS reconnaissance and enumeration",
        "variants": {
            "dnsrecon": {"tool": "dnsrecon", "label": "DNSRecon", "description": "DNS reconnaissance"},
            "dnsenum": {"tool": "dnsenum", "label": "DNSEnum", "description": "DNS enumeration"},
            "zone": {"tool": "dns_zone", "label": "Zone Transfer", "description": "Attempt DNS zone transfer"},
        }
    },
    "osint": {
        "name": "OSINT",
        "description": "Open Source Intelligence gathering",
        "variants": {
            "theharvester": {"tool": "theharvester", "label": "theHarvester", "description": "Email and subdomain harvester"},
            "subfinder": {"tool": "subfinder", "label": "Subfinder", "description": "Subdomain discovery"},
            "amass": {"tool": "amass", "label": "Amass", "description": "Attack surface mapping"},
            "whois": {"tool": "whois", "label": "WHOIS", "description": "Domain/IP WHOIS lookup"},
        }
    },
    "cms": {
        "name": "CMS Scanners",
        "description": "Content Management System vulnerability scanners",
        "variants": {
            "wpscan": {"tool": "wpscan", "label": "WPScan", "description": "WordPress scanner"},
            "joomscan": {"tool": "joomscan", "label": "JoomScan", "description": "Joomla scanner"},
            "droopescan": {"tool": "droopescan", "label": "Droopescan", "description": "Drupal/WordPress scanner"},
        }
    },
    "password": {
        "name": "Password Cracking",
        "description": "Offline password cracking tools",
        "variants": {
            "john": {"tool": "john", "label": "John the Ripper", "description": "CPU password cracker"},
            "hashcat": {"tool": "hashcat", "label": "Hashcat", "description": "GPU password cracker"},
        }
    },
}

# Tools that should NOT be grouped (shown individually)
STANDALONE_TOOLS = {
    "masscan", "rustscan", "nikto", "sqlmap", "whatweb", "wafw00f",
    "ldapsearch", "snmpwalk", "nbtscan", "rpcclient", "showmount", "finger",
    "smtp_vrfy", "netcat", "curl", "wget", "searchsploit", "nuclei",
    "cewl", "davtest", "xsstrike", "commix", "evil_winrm",
    "bloodhound_python", "ldapdomaindump", "kerbrute",
    "arp_scan", "netdiscover", "tcpdump", "responder", "bettercap",
    "airmon", "airodump", "wifite", "linpeas", "linenum", "pspy",
    "rubeus", "mimikatz", "aws_cli", "pacu", "prowler", "scoutsuite",
}


def convert_registry_tool_to_response(tool: RegistryTool) -> dict:
    """Convert a registry Tool to API response format."""
    properties = {}
    required = []
    
    for param_name, default_value in tool.default_options.items():
        param_type = "string"
        if isinstance(default_value, bool):
            param_type = "boolean"
        elif isinstance(default_value, int):
            param_type = "integer"
        elif isinstance(default_value, dict):
            param_type = "object"
        
        properties[param_name] = {
            "type": param_type,
            "description": f"Parameter: {param_name}",
            "default": default_value
        }
    
    if "{target}" in tool.command or "{TARGET}" in tool.command:
        properties["target"] = {
            "type": "string",
            "description": "Target IP, domain, or URL",
        }
        required.append("target")
    
    return {
        "name": tool.name,
        "description": tool.description,
        "category": tool.category.value,
        "command": tool.command,  # Include command template for preview
        "parameters": {
            "type": "object",
            "properties": properties,
            "required": required
        }
    }


def get_grouped_tools(registry) -> list:
    """Get tools organized into groups with variants."""
    all_tools = registry.list_all()
    tool_map = {t.name: t for t in all_tools}
    
    result = []
    used_tools = set()
    
    # Process grouped tools
    for group_id, group_config in TOOL_GROUPS.items():
        variants = []
        for variant_id, variant_config in group_config["variants"].items():
            tool_name = variant_config["tool"]
            if tool_name in tool_map:
                tool = tool_map[tool_name]
                tool_response = convert_registry_tool_to_response(tool)
                variants.append({
                    "id": variant_id,
                    "label": variant_config["label"],
                    "description": variant_config["description"],
                    "tool": tool_response
                })
                used_tools.add(tool_name)
        
        if variants:
            # Use first variant's category
            first_tool = tool_map.get(group_config["variants"][list(group_config["variants"].keys())[0]]["tool"])
            result.append({
                "id": group_id,
                "name": group_config["name"],
                "description": group_config["description"],
                "category": first_tool.category.value if first_tool else "scanning",
                "isGroup": True,
                "variants": variants,
                "defaultVariant": list(group_config["variants"].keys())[0]
            })
    
    # Add standalone tools
    for tool in all_tools:
        if tool.name not in used_tools:
            tool_response = convert_registry_tool_to_response(tool)
            result.append({
                "id": tool.name,
                "name": tool.name,
                "description": tool.description,
                "category": tool.category.value,
                "isGroup": False,
                "tool": tool_response
            })
    
    return result


@router.get(
    "",
    responses={500: {"model": ErrorResponse}},
    summary="List all tools",
    description="Returns all available tools grouped by category - Requirements 4.1, 8.5"
)
async def list_tools(
    category: Optional[str] = None,
    search: Optional[str] = None,
    grouped: bool = True
) -> dict:
    """List all available tools from the registry."""
    registry = get_tool_registry()
    
    if grouped:
        tools = get_grouped_tools(registry)
        
        # Filter by category
        if category:
            tools = [t for t in tools if t["category"] == category]
        
        # Filter by search
        if search:
            search_lower = search.lower()
            filtered = []
            for t in tools:
                if search_lower in t["name"].lower() or search_lower in t["description"].lower():
                    filtered.append(t)
                elif t.get("isGroup") and t.get("variants"):
                    # Search in variants
                    for v in t["variants"]:
                        if search_lower in v["label"].lower() or search_lower in v["description"].lower():
                            filtered.append(t)
                            break
            tools = filtered
        
        categories = list(set(t["category"] for t in tools))
        
        return {
            "tools": tools,
            "total": len(tools),
            "categories": categories,
            "grouped": True
        }
    else:
        # Legacy ungrouped response
        if search:
            tools = registry.search(search)
        else:
            tools = registry.list_all()
        
        if category:
            tools = [t for t in tools if t.category.value == category]
        
        tool_responses = [convert_registry_tool_to_response(t) for t in tools]
        categories = list(set(t["category"] for t in tool_responses))
        
        return {
            "tools": tool_responses,
            "total": len(tool_responses),
            "categories": categories,
            "grouped": False
        }


@router.get(
    "/{name}",
    responses={404: {"model": ErrorResponse}},
    summary="Get tool details",
    description="Returns details for a specific tool - Requirements 4.3, 8.5"
)
async def get_tool(name: str) -> dict:
    """Get details for a specific tool.
    
    Requirements:
    - 4.3: Display tool description, parameters, and usage examples
    - 8.5: Return tool definitions with parameter schemas
    """
    registry = get_tool_registry()
    tool = registry.get(name)
    
    if not tool:
        raise HTTPException(
            status_code=404,
            detail=f"Tool not found: {name}"
        )
    
    return convert_registry_tool_to_response(tool)


@router.get(
    "/categories/list",
    response_model=List[str],
    summary="List tool categories",
    description="Returns all available tool categories - Requirements 4.1"
)
async def list_categories() -> List[str]:
    """List all available tool categories.
    
    Requirements 4.1: Display tools grouped by category.
    """
    registry = get_tool_registry()
    tools = registry.list_all()
    categories = list(set(t.category.value for t in tools))
    return sorted(categories)
