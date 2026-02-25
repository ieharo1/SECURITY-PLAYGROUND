import { Injectable } from '@angular/core';

export interface Vulnerability {
  type: 'SQL Injection' | 'XSS' | 'Command Injection';
  risk: 'Low' | 'Medium' | 'High';
  pattern: string;
  explanation: string;
  remediation: string;
}

@Injectable({
  providedIn: 'root'
})
export class InputDetectorService {
  private patterns = {
    sqlInjection: [
      { pattern: /(\b|--|;)(select|insert|update|delete|drop|create|alter|exec|execute|union)\b/i, risk: 'High' as const },
      { pattern: /'(\s*or\s*|\s*and\s*)['"=]/i, risk: 'High' as const },
      { pattern: /(\bor\b|\band\b).*=.*['"]/i, risk: 'Medium' as const },
      { pattern: /['"](?:\s*(?:or|and)\s*['"]?\d|\s*=\s*['"]?\d)/i, risk: 'High' as const },
      { pattern: /--$/m, risk: 'High' as const },
      { pattern: /;\s*(drop|delete|truncate)/i, risk: 'High' as const },
      { pattern: /union\s+select/i, risk: 'High' as const },
      { pattern: /'\s*or\s+'1'\s*=\s*'1/i, risk: 'High' as const },
      { pattern: /1\s*=\s*1/i, risk: 'High' as const },
    ],
    xss: [
      { pattern: /<script\b/i, risk: 'High' as const },
      { pattern: /javascript:/i, risk: 'High' as const },
      { pattern: /on\w+\s*=/i, risk: 'High' as const },
      { pattern: /<img[^>]+onerror/i, risk: 'High' as const },
      { pattern: /<svg[^>]+onload/i, risk: 'High' as const },
      { pattern: /<iframe/i, risk: 'Medium' as const },
      { pattern: /<object/i, risk: 'Medium' as const },
      { pattern: /<embed/i, risk: 'Medium' as const },
      { pattern: /eval\s*\(/i, risk: 'High' as const },
      { pattern: /innerHTML\s*=/i, risk: 'Medium' as const },
    ],
    commandInjection: [
      { pattern: /;\s*(ls|dir|cat|rm|mkdir|chmod|chown)/i, risk: 'High' as const },
      { pattern: /\|\s*(cat|ls|grep|awk|head)/i, risk: 'High' as const },
      { pattern: /\$\([^)]+\)/i, risk: 'High' as const },
      { pattern: /`[^`]+`/i, risk: 'High' as const },
      { pattern: /\b(whoami|id|uname|hostname)\b/i, risk: 'Medium' as const },
      { pattern: /\b(nc|netcat|wget|curl)\b/i, risk: 'High' as const },
      { pattern: /&\s*&\s*/i, risk: 'Medium' as const },
      { pattern: /\|\s*/i, risk: 'Low' as const },
    ]
  };

  detect(input: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const lowerInput = input.toLowerCase();

    for (const rule of this.patterns.sqlInjection) {
      if (rule.pattern.test(input)) {
        vulnerabilities.push({
          type: 'SQL Injection',
          risk: rule.risk,
          pattern: rule.pattern.source,
          explanation: 'SQL Injection allows attackers to interfere with database queries.',
          remediation: 'Use parameterized queries or prepared statements instead of concatenating user input.'
        });
        break;
      }
    }

    for (const rule of this.patterns.xss) {
      if (rule.pattern.test(input)) {
        vulnerabilities.push({
          type: 'XSS',
          risk: rule.risk,
          pattern: rule.pattern.source,
          explanation: 'Cross-Site Scripting (XSS) allows attackers to inject malicious scripts.',
          remediation: 'Escape output and use Content Security Policy (CSP) headers.'
        });
        break;
      }
    }

    for (const rule of this.patterns.commandInjection) {
      if (rule.pattern.test(input)) {
        vulnerabilities.push({
          type: 'Command Injection',
          risk: rule.risk,
          pattern: rule.pattern.source,
          explanation: 'Command Injection allows execution of arbitrary system commands.',
          remediation: 'Never use user input in system calls. Use allowlists and input validation.'
        });
        break;
      }
    }

    return vulnerabilities;
  }
}
