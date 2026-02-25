import { Component, signal, computed, effect } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { CryptoService } from './core/services/crypto.service';
import { PasswordService, PasswordAnalysis } from './core/services/password.service';
import { JwtService, JWTResult } from './core/services/jwt.service';
import { InputDetectorService, Vulnerability } from './core/services/input-detector.service';
import { HeadersSimulatorService, HeaderAnalysis } from './core/services/headers-simulator.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App {
  activeModule = signal('password');
  
  // Password Analyzer
  passwordInput = signal('');
  passwordVisible = signal(false);
  passwordAnalysis = signal<PasswordAnalysis | null>(null);
  generatedPassword = signal('');
  genOptions = signal({
    length: 16,
    uppercase: true,
    numbers: true,
    symbols: true,
    excludeAmbiguous: false
  });

  // Hash Generator
  hashInput = signal('');
  hashAlgorithm = signal<'sha256' | 'sha512'>('sha256');
  hashOutput = signal('');
  hashCompare1 = signal('');
  hashCompare2 = signal('');

  // JWT Validator
  jwtInput = signal('');
  jwtResult = signal<JWTResult | null>(null);

  // Input Detector
  detectorInput = signal('');
  vulnerabilities = signal<Vulnerability[]>([]);

  // Headers Simulator
  headersInput = signal('');
  headerAnalysis = signal<HeaderAnalysis | null>(null);

  navItems = [
    { id: 'password', label: 'Analizador de Contraseñas', icon: '🔐' },
    { id: 'hash', label: 'Generador de Hash', icon: '#️⃣' },
    { id: 'jwt', label: 'Validador JWT', icon: '🎫' },
    { id: 'detector', label: 'Seguridad de Inputs', icon: '🔍' },
    { id: 'headers', label: 'Headers de Seguridad', icon: '📋' }
  ];

  constructor(
    private cryptoService: CryptoService,
    private passwordService: PasswordService,
    private jwtService: JwtService,
    private inputDetector: InputDetectorService,
    private headersSimulator: HeadersSimulatorService
  ) {
    effect(() => {
      const pwd = this.passwordInput();
      if (pwd) {
        this.passwordAnalysis.set(this.passwordService.analyze(pwd));
      } else {
        this.passwordAnalysis.set(null);
      }
    });

    effect(() => {
      const input = this.hashInput();
      if (input) {
        this.generateHash(input);
      }
    });

    effect(() => {
      const input = this.jwtInput();
      if (input) {
        this.jwtResult.set(this.jwtService.decode(input));
      } else {
        this.jwtResult.set(null);
      }
    });

    effect(() => {
      const input = this.detectorInput();
      if (input) {
        this.vulnerabilities.set(this.inputDetector.detect(input));
      } else {
        this.vulnerabilities.set([]);
      }
    });

    effect(() => {
      const input = this.headersInput();
      if (input) {
        this.headerAnalysis.set(this.headersSimulator.analyze(input));
      } else {
        this.headerAnalysis.set(null);
      }
    });
  }

  setActiveModule(module: string) {
    this.activeModule.set(module);
  }

  togglePasswordVisibility() {
    this.passwordVisible.set(!this.passwordVisible());
  }

  getStrengthClass(): string {
    const analysis = this.passwordAnalysis();
    if (!analysis) return '';
    if (analysis.score < 30) return 'weak';
    if (analysis.score < 50) return 'medium';
    if (analysis.score < 75) return 'strong';
    return 'very-strong';
  }

  getScoreColor(): string {
    const analysis = this.passwordAnalysis();
    if (!analysis) return '';
    if (analysis.score < 30) return 'danger';
    if (analysis.score < 50) return 'warning';
    if (analysis.score < 75) return 'success';
    return 'success';
  }

  generatePassword() {
    const opts = this.genOptions();
    this.generatedPassword.set(
      this.passwordService.generatePassword(opts.length, opts)
    );
  }

  copyToClipboard(text: string) {
    navigator.clipboard.writeText(text);
  }

  async generateHash(input: string) {
    const algo = this.hashAlgorithm();
    if (algo === 'sha256') {
      this.hashOutput.set(await this.cryptoService.sha256(input));
    } else {
      this.hashOutput.set(await this.cryptoService.sha512(input));
    }
  }

  setHashAlgorithm(algo: 'sha256' | 'sha512') {
    this.hashAlgorithm.set(algo);
    const input = this.hashInput();
    if (input) {
      this.generateHash(input);
    }
  }

  getExpirationStatus(): { class: string; text: string } {
    const result = this.jwtResult();
    if (!result) return { class: '', text: '' };
    
    if (result.expiration === 'expired') {
      return { class: 'danger', text: 'Expirado' };
    } else if (result.expiration === 'valid') {
      return { class: 'success', text: 'Válido' };
    }
    return { class: 'info', text: 'Sin Expiración' };
  }

  getHeaderScoreClass(): string {
    const analysis = this.headerAnalysis();
    if (!analysis) return '';
    if (analysis.score < 40) return 'low';
    if (analysis.score < 70) return 'medium';
    return 'high';
  }

  formatJson(obj: any): string {
    return JSON.stringify(obj, null, 2);
  }
}
