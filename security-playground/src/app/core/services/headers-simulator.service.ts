import { Injectable } from '@angular/core';

export interface HeaderAnalysis {
  headers: { [key: string]: string };
  present: { name: string; value: string; recommendation: string }[];
  missing: { name: string; recommendation: string }[];
  score: number;
}

@Injectable({
  providedIn: 'root'
})
export class HeadersSimulatorService {
  private securityHeaders = {
    'content-security-policy': {
      name: 'Content-Security-Policy',
      recommendation: 'Implement CSP to prevent XSS and data injection attacks. Example: "default-src \'self\'; script-src \'self\'"'
    },
    'x-frame-options': {
      name: 'X-Frame-Options',
      recommendation: 'Add X-Frame-Options to prevent clickjacking. Use DENY or SAMEORIGIN.'
    },
    'strict-transport-security': {
      name: 'Strict-Transport-Security',
      recommendation: 'Enable HSTS to enforce HTTPS. Example: "max-age=31536000; includeSubDomains"'
    },
    'x-content-type-options': {
      name: 'X-Content-Type-Options',
      recommendation: 'Set to "nosniff" to prevent MIME type sniffing.'
    },
    'referrer-policy': {
      name: 'Referrer-Policy',
      recommendation: 'Set a referrer policy to control information leakage. Use "strict-origin-when-cross-origin".'
    },
    'permissions-policy': {
      name: 'Permissions-Policy',
      recommendation: 'Restrict browser features like geolocation, camera, microphone.'
    },
    'x-xss-protection': {
      name: 'X-XSS-Protection',
      recommendation: 'Enable XSS filter (note: deprecated, CSP is preferred). Use "1; mode=block".'
    }
  };

  analyze(rawHeaders: string): HeaderAnalysis {
    const headers: { [key: string]: string } = {};
    const present: { name: string; value: string; recommendation: string }[] = [];
    const missing: { name: string; recommendation: string }[] = [];

    const lines = rawHeaders.split('\n');
    for (const line of lines) {
      const colonIndex = line.indexOf(':');
      if (colonIndex > 0) {
        const key = line.substring(0, colonIndex).trim().toLowerCase();
        const value = line.substring(colonIndex + 1).trim();
        if (key && value) {
          headers[key] = value;
        }
      }
    }

    for (const [key, config] of Object.entries(this.securityHeaders)) {
      if (headers[key]) {
        present.push({
          name: config.name,
          value: headers[key],
          recommendation: ''
        });
      } else {
        missing.push({
          name: config.name,
          recommendation: config.recommendation
        });
      }
    }

    const score = Math.round((present.length / Object.keys(this.securityHeaders).length) * 100);

    return { headers, present, missing, score };
  }
}
