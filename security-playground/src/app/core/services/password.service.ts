import { Injectable, signal, computed } from '@angular/core';

export interface PasswordAnalysis {
  length: number;
  poolSize: number;
  entropy: number;
  score: number;
  crackTimeCpu: string;
  crackTimeGpu: string;
  crackTimeDistributed: string;
  vulnerabilities: string[];
  suggestions: string[];
}

@Injectable({
  providedIn: 'root'
})
export class PasswordService {
  private commonPatterns = [
    'password', '123456', 'qwerty', 'abc123', 'letmein', 'welcome',
    'admin', 'login', 'master', 'dragon', 'monkey', 'shadow',
    'sunshine', 'princess', 'football', 'baseball', 'superman',
    'batman', 'trustno1', 'iloveyou'
  ];

  private keyboardPatterns = [
    'qwerty', 'asdfgh', 'zxcvbn', 'qazwsx', '123456', '098765',
    'abcdef', 'aaaaaa', 'bbbbbb', '111111', 'aaaaaa'
  ];

  analyze(password: string): PasswordAnalysis {
    const length = password.length;
    const poolSize = this.calculatePoolSize(password);
    const entropy = Math.log2(Math.pow(poolSize, length));
    const score = this.calculateScore(password, entropy);
    const vulnerabilities = this.detectVulnerabilities(password);
    const suggestions = this.generateSuggestions(password, poolSize, length);

    return {
      length,
      poolSize,
      entropy: Math.round(entropy * 100) / 100,
      score,
      crackTimeCpu: this.estimateCrackTime(entropy, 1e7),
      crackTimeGpu: this.estimateCrackTime(entropy, 1e11),
      crackTimeDistributed: this.estimateCrackTime(entropy, 1e13),
      vulnerabilities,
      suggestions
    };
  }

  private calculatePoolSize(password: string): number {
    let pool = 0;
    if (/[a-z]/.test(password)) pool += 26;
    if (/[A-Z]/.test(password)) pool += 26;
    if (/[0-9]/.test(password)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(password)) pool += 32;
    return pool || 1;
  }

  private calculateScore(password: string, entropy: number): number {
    let score = 0;
    
    if (password.length >= 8) score += 10;
    if (password.length >= 12) score += 15;
    if (password.length >= 16) score += 15;
    
    if (/[a-z]/.test(password)) score += 10;
    if (/[A-Z]/.test(password)) score += 10;
    if (/[0-9]/.test(password)) score += 10;
    if (/[^a-zA-Z0-9]/.test(password)) score += 15;
    
    score += Math.min(20, entropy / 3);
    
    const lower = password.toLowerCase();
    if (this.commonPatterns.some(p => lower.includes(p))) score -= 30;
    if (this.keyboardPatterns.some(p => lower.includes(p))) score -= 20;
    if (/(.)\1{2,}/.test(password)) score -= 15;
    if (/^(123|abc|qwe)/i.test(password)) score -= 15;

    return Math.max(0, Math.min(100, Math.round(score)));
  }

  private detectVulnerabilities(password: string): string[] {
    const vulns: string[] = [];
    const lower = password.toLowerCase();
    
    if (this.commonPatterns.some(p => lower === p || lower.includes(p))) {
      vulns.push('Contains common password pattern');
    }
    if (this.keyboardPatterns.some(p => lower.includes(p))) {
      vulns.push('Contains keyboard pattern');
    }
    if (/(.)\1{2,}/.test(password)) {
      vulns.push('Contains repeated characters');
    }
    if (/^(123|abc|qwe|000|111)/i.test(password)) {
      vulns.push('Contains sequential characters');
    }
    if (password.length < 8) {
      vulns.push('Too short (less than 8 characters)');
    }
    if (!/[A-Z]/.test(password)) {
      vulns.push('Missing uppercase letters');
    }
    if (!/[0-9]/.test(password)) {
      vulns.push('Missing numbers');
    }
    if (!/[^a-zA-Z0-9]/.test(password)) {
      vulns.push('Missing special characters');
    }
    
    return vulns;
  }

  private generateSuggestions(password: string, poolSize: number, length: number): string[] {
    const suggestions: string[] = [];
    
    if (length < 16) suggestions.push('Use at least 16 characters');
    if (!/[A-Z]/.test(password)) suggestions.push('Add uppercase letters');
    if (!/[0-9]/.test(password)) suggestions.push('Add numbers');
    if (!/[^a-zA-Z0-9]/.test(password)) suggestions.push('Add special characters');
    if (poolSize < 60) suggestions.push('Use a larger character set');
    
    return suggestions;
  }

  private estimateCrackTime(entropy: number, guessesPerSecond: number): string {
    const combinations = Math.pow(2, entropy);
    const seconds = combinations / guessesPerSecond / 2;
    
    if (seconds < 1) return 'Instant';
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
    if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
    if (seconds < 31536000 * 100) return `${Math.round(seconds / 31536000)} years`;
    if (seconds < 31536000 * 1000000) return `${Math.round(seconds / 31536000 / 1000)} thousand years`;
    return 'Millions of years';
  }

  generatePassword(length: number, options: {
    uppercase: boolean;
    numbers: boolean;
    symbols: boolean;
    excludeAmbiguous: boolean;
  }): string {
    let charset = 'abcdefghijklmnopqrstuvwxyz';
    const ambiguous = 'lIO0';
    
    if (options.uppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (options.numbers) charset += '0123456789';
    if (options.symbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    if (options.excludeAmbiguous) {
      charset = charset.split('').filter(c => !ambiguous.includes(c)).join('');
    }
    
    const array = new Uint32Array(length);
    crypto.getRandomValues(array);
    
    let password = '';
    for (let i = 0; i < length; i++) {
      password += charset[array[i] % charset.length];
    }
    
    return password;
  }
}
