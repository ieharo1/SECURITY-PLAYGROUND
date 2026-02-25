import { Injectable } from '@angular/core';

export interface JWTResult {
  valid: boolean;
  header: any;
  payload: any;
  algorithm: string;
  expiration: 'valid' | 'expired' | 'none';
  expirationTime?: string;
  warnings: string[];
  errors: string[];
}

@Injectable({
  providedIn: 'root'
})
export class JwtService {
  
  decode(token: string): JWTResult {
    const result: JWTResult = {
      valid: false,
      header: null,
      payload: null,
      algorithm: 'unknown',
      expiration: 'none',
      warnings: [],
      errors: []
    };

    if (!token || typeof token !== 'string') {
      result.errors.push('Token is empty or invalid');
      return result;
    }

    const parts = token.trim().split('.');
    if (parts.length !== 3) {
      result.errors.push('Invalid JWT format (must have 3 parts)');
      return result;
    }

    try {
      result.header = this.decodeBase64Url(parts[0]);
      result.algorithm = result.header?.alg || 'unknown';
      
      if (result.algorithm.toLowerCase() === 'none') {
        result.warnings.push('INSECURE: Algorithm "none" detected - token is not signed!');
      }
    } catch (e) {
      result.errors.push('Failed to decode header');
    }

    try {
      result.payload = this.decodeBase64Url(parts[1]);
    } catch (e) {
      result.errors.push('Failed to decode payload');
    }

    if (result.payload) {
      if (result.payload.exp !== undefined) {
        const expDate = new Date(result.payload.exp * 1000);
        const now = new Date();
        
        if (expDate < now) {
          result.expiration = 'expired';
          result.expirationTime = `Expired ${this.formatTimeDifference(now, expDate)}`;
        } else {
          result.expiration = 'valid';
          result.expirationTime = `Expires in ${this.formatTimeDifference(now, expDate)}`;
        }
        
        if (result.payload.exp - (result.payload.iat || Math.floor(Date.now() / 1000)) > 86400) {
          result.warnings.push('Token has long expiration (more than 24 hours)');
        }
      } else {
        result.warnings.push('No expiration claim (exp) - token never expires');
      }
    }

    result.valid = result.errors.length === 0;

    return result;
  }

  private decodeBase64Url(str: string): any {
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4;
    if (pad) {
      base64 += '='.repeat(4 - pad);
    }
    
    try {
      const decoded = atob(base64);
      return JSON.parse(decoded);
    } catch (e) {
      return null;
    }
  }

  private formatTimeDifference(now: Date, target: Date): string {
    const diffMs = Math.abs(target.getTime() - now.getTime());
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHour = Math.floor(diffMin / 60);
    const diffDay = Math.floor(diffHour / 24);

    if (diffDay > 0) return `${diffDay} day${diffDay > 1 ? 's' : ''}`;
    if (diffHour > 0) return `${diffHour} hour${diffHour > 1 ? 's' : ''}`;
    if (diffMin > 0) return `${diffMin} minute${diffMin > 1 ? 's' : ''}`;
    return `${diffSec} second${diffSec > 1 ? 's' : ''}`;
  }
}
