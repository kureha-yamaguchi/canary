// MITRE ATT&CK tactics and techniques extracted from vulnerabilities data
export interface TechniqueData {
  id: string;
  name: string;
  vulnerabilities: string[];
}

export const TACTICS_TECHNIQUES: Record<string, TechniqueData[]> = {
  'Reconnaissance': [
    {
      id: 'T1592',
      name: 'Gather Victim Host Information',
      vulnerabilities: ['Information Disclosure in Errors', 'Missing Referrer Policy']
    },
    {
      id: 'T1592.002',
      name: 'Gather Victim Host Information: Software',
      vulnerabilities: ['Server Information Disclosure']
    }
  ],
  'Initial Access': [
    {
      id: 'T1190',
      name: 'Exploit Public-Facing Application',
      vulnerabilities: ['SQL Injection', 'XML External Entity (XXE)', 'Server-Side Request Forgery (SSRF)', 'LDAP Injection', 'NoSQL Injection']
    },
    {
      id: 'T1189',
      name: 'Drive-by Compromise',
      vulnerabilities: ['Cross-Site Scripting (XSS) - Reflected', 'Cross-Site Scripting (XSS) - Stored', 'Clickjacking', 'Missing Content Security Policy (CSP)', 'Missing X-Frame-Options Header', 'Missing X-Content-Type-Options Header', 'Missing Content-Type Header', 'Lack of Trusted Types Readiness', 'Deprecated X-XSS-Protection Header']
    },
    {
      id: 'T1566.002',
      name: 'Phishing: Spearphishing Link',
      vulnerabilities: ['Open Redirect', 'Unvalidated Redirects in Authentication']
    }
  ],
  'Execution': [
    {
      id: 'T1203',
      name: 'Exploitation for Client Execution',
      vulnerabilities: ['Insecure Deserialization']
    },
    {
      id: 'T1059',
      name: 'Command and Scripting Interpreter',
      vulnerabilities: ['Command Injection']
    },
    {
      id: 'T1204.002',
      name: 'User Execution: Malicious File',
      vulnerabilities: ['Insecure File Upload']
    }
  ],
  'Persistence': [
    {
      id: 'T1098',
      name: 'Account Manipulation',
      vulnerabilities: ['Insecure Direct Object References (IDOR)', 'Mass Assignment']
    },
    {
      id: 'T1078',
      name: 'Valid Accounts',
      vulnerabilities: ['Missing Access Control']
    }
  ],
  'Privilege Escalation': [
    {
      id: 'T1078',
      name: 'Valid Accounts',
      vulnerabilities: ['Missing Access Control']
    }
  ],
  'Defense Evasion': [
    {
      id: 'T1550',
      name: 'Use Alternate Authentication Material',
      vulnerabilities: ['Broken Authentication']
    },
    {
      id: 'T1078',
      name: 'Valid Accounts',
      vulnerabilities: ['Missing Access Control']
    }
  ],
  'Credential Access': [
    {
      id: 'T1539',
      name: 'Steal Web Session Cookie',
      vulnerabilities: ['Cross-Site Request Forgery (CSRF)', 'Cookie Security Issues', 'Insecure Set-Cookie Headers']
    },
    {
      id: 'T1552.001',
      name: 'Unsecured Credentials: Credentials In Files',
      vulnerabilities: ['Sensitive Data Exposure - Client Side', 'API Key in URL Parameters']
    },
    {
      id: 'T1110',
      name: 'Brute Force',
      vulnerabilities: ['Insufficient Rate Limiting']
    },
    {
      id: 'T1110.001',
      name: 'Brute Force: Password Guessing',
      vulnerabilities: ['Weak Password Policy']
    },
    {
      id: 'T1557',
      name: 'Adversary-in-the-Middle',
      vulnerabilities: ['Missing Security Headers', 'Mixed Content', 'Outdated TLS Version', 'Deprecated TLS Support', 'Weak Cipher Suite', 'Missing HSTS Header']
    },
    {
      id: 'T1557.002',
      name: 'Adversary-in-the-Middle: ARP Cache Poisoning',
      vulnerabilities: ['Certificate Expiry']
    },
    {
      id: 'T1040',
      name: 'Network Sniffing',
      vulnerabilities: ['HTTPS Not Enabled']
    }
  ],
  'Discovery': [
    {
      id: 'T1083',
      name: 'File and Directory Discovery',
      vulnerabilities: ['Path Traversal', 'Directory Listing Enabled']
    }
  ],
  'Lateral Movement': [
    {
      id: 'T1550',
      name: 'Use Alternate Authentication Material',
      vulnerabilities: ['Broken Authentication']
    }
  ],
  'Collection': [
    {
      id: 'T1005',
      name: 'Data from Local System',
      vulnerabilities: ['Local File Inclusion (LFI)', 'Missing Cross-Origin Resource Isolation']
    },
    {
      id: 'T1530',
      name: 'Data from Cloud Storage',
      vulnerabilities: ['Row Level Security Bypass']
    },
    {
      id: 'T1557',
      name: 'Adversary-in-the-Middle',
      vulnerabilities: ['Missing Security Headers', 'Mixed Content', 'Outdated TLS Version', 'Deprecated TLS Support', 'Weak Cipher Suite', 'Missing HSTS Header']
    },
    {
      id: 'T1557.002',
      name: 'Adversary-in-the-Middle: ARP Cache Poisoning',
      vulnerabilities: ['Certificate Expiry']
    },
    {
      id: 'T1123',
      name: 'Audio Capture',
      vulnerabilities: ['Missing Permissions-Policy Header']
    },
    {
      id: 'T1040',
      name: 'Network Sniffing',
      vulnerabilities: ['HTTPS Not Enabled']
    }
  ],
  'Command and Control': [
    {
      id: 'T1105',
      name: 'Ingress Tool Transfer',
      vulnerabilities: ['Remote File Inclusion (RFI)']
    }
  ]
};
