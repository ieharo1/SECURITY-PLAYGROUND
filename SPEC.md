# Web Security Playground - Specification

## 1. Project Overview

**Project Name:** Web Security Playground  
**Type:** Single Page Application (Angular 17+)  
**Core Functionality:** Interactive educational platform for analyzing passwords, generating hashes, validating JWTs, detecting input vulnerabilities, and simulating security header analysis.  
**Target Users:** Developers, security enthusiasts, students learning cybersecurity fundamentals.

---

## 2. UI/UX Specification

### Layout Structure

- **Navigation:** Fixed left sidebar (280px) with module navigation
- **Main Content:** Fluid content area with max-width 1400px
- **Header:** Top bar with app title and theme toggle
- **Responsive:** Collapsible sidebar on mobile (<768px)

### Visual Design

**Color Palette (Dark Theme - Primary):**
- Background Primary: `#0a0a0f` (deep black)
- Background Secondary: `#12121a` (card backgrounds)
- Background Tertiary: `#1a1a25` (input fields)
- Accent Primary: `#00ff88` (neon green - success/strong)
- Accent Warning: `#ffaa00` (amber - medium)
- Accent Danger: `#ff3366` (red - weak/vulnerable)
- Accent Info: `#00ccff` (cyan - info/links)
- Text Primary: `#e8e8e8`
- Text Secondary: `#8888aa`
- Border: `#2a2a3a`

**Typography:**
- Font Family: `"JetBrains Mono", "Fira Code", monospace` (technical feel)
- Headings: `"Space Grotesk"` -> Changed to `"Outfit", sans-serif`
- Body: 14px base
- Headings: H1 32px, H2 24px, H3 18px

**Spacing:**
- Base unit: 8px
- Card padding: 24px
- Section gap: 32px
- Input padding: 12px 16px

**Visual Effects:**
- Cards: subtle glow on hover (`box-shadow: 0 0 20px rgba(0, 255, 136, 0.1)`)
- Inputs: focus ring with accent color
- Buttons: gradient backgrounds with hover lift
- Transitions: 200ms ease-out

### Components

1. **Sidebar Navigation**
   - Logo/App title
   - Module icons with labels
   - Active state: accent background
   - Hover: subtle glow

2. **Module Cards**
   - Dark background with border
   - Header with icon and title
   - Content area with inputs/outputs
   - Action buttons

3. **Input Fields**
   - Dark background (#1a1a25)
   - Monospace font for code inputs
   - Show/hide toggle for passwords
   - Copy button for outputs

4. **Strength Meter**
   - Visual bar with gradient
   - Percentage label
   - Color changes based on strength

5. **Results Panel**
   - Grid of metrics
   - Animated counters
   - Color-coded indicators

---

## 3. Functionality Specification

### Module 1: Password Analyzer

**Inputs:**
- Password field (with show/hide toggle)
- Optional: username/context for personal data detection

**Calculations:**
- Length (characters)
- Character pool size (lowercase, uppercase, digits, symbols)
- Entropy: `Math.log2(poolSize ** length)` bits
- Pattern detection: sequences, repeats, keyboard patterns

**Outputs:**
- Strength score: 0-100
- Entropy in bits
- Crack time estimates:
  - Basic CPU (10^7 guesses/sec)
  - GPU cluster (10^11 guesses/sec)
  - Distributed (10^13 guesses/sec)
- Vulnerabilities list (pattern-based warnings)
- Improvement suggestions

**Visual:**
- Animated strength bar
- Color: red (<30) / amber (30-60) / green (>60)
- Icon indicators for each detected issue

### Module 2: Hash Generator

**Algorithms:**
- SHA-256
- SHA-512

**Features:**
- Text input for hashing
- File input (text file) for hashing
- Hash comparison tool (paste two hashes)
- Copy to clipboard button

**Implementation:**
- Use Web Crypto API (`crypto.subtle.digest`)
- Display hex output in monospace

### Module 3: JWT Validator

**Inputs:**
- JWT token textarea

**Features:**
- Decode and display header (JSON formatted)
- Decode and display payload (JSON formatted)
- Show algorithm (HS256, RS256, none, etc.)
- Verify expiration:
  - Extract `exp` claim
  - Show "Expired" or "Valid" with time remaining/since
- Detect insecure patterns:
  - Algorithm "none"
  - Missing expiration
  - Very long expiration (>24h warning)

**Outputs:**
- Parsed header object
- Parsed payload object
- Status indicators (valid/expired/malformed)
- Security warnings list

### Module 4: Input Vulnerability Detector

**Inputs:**
- Textarea for user input simulation

**Detection Patterns:**
- SQL Injection: `' OR 1=1 --`, `'; DROP TABLE`, `UNION SELECT`
- XSS: `<script>`, `javascript:`, `onerror=`, `<img onerror>`
- Command Injection: `; ls`, `| cat`, `$(whoami)`, `` `id` ``

**Features:**
- Real-time analysis as user types
- Highlight detected threats
- Provide educational explanation of each vulnerability
- Suggest safe alternatives

**Outputs:**
- Vulnerability type detected
- Risk level (Low/Medium/High)
- Explanation
- Remediation suggestion

### Module 5: Security Headers Simulator

**Inputs:**
- Textarea to paste HTTP headers (raw format)

**Analysis:**
- Parse header key-value pairs
- Check for:
  - Content-Security-Policy (CSP)
  - X-Frame-Options
  - Strict-Transport-Security (HSTS)
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy

**Outputs:**
- Present headers with values
- Missing security headers (warnings)
- Basic recommendation for each missing header
- Security score (0-100)

---

## 4. Technical Architecture

### Angular Structure
```
src/
├── app/
│   ├── core/
│   │   └── services/
│   │       ├── crypto.service.ts
│   │       ├── password.service.ts
│   │       └── jwt.service.ts
│   ├── features/
│   │   ├── password-analyzer/
│   │   ├── hash-generator/
│   │   ├── jwt-validator/
│   │   ├── input-detector/
│   │   └── headers-simulator/
│   ├── shared/
│   │   └── components/
│   └── app.component.ts
```

### Key Technologies
- Angular 17+ with standalone components
- Signals for reactive state
- Web Crypto API for hashing
- CSS custom properties for theming
- No external UI libraries (custom components)

---

## 5. Acceptance Criteria

1. ✅ All 5 modules accessible via sidebar navigation
2. ✅ Password analyzer calculates real entropy and estimates crack times
3. ✅ Hash generator produces correct SHA-256/SHA-512 outputs
4. ✅ JWT decoder parses valid tokens and detects expiration
5. ✅ Input detector identifies SQLi, XSS, command injection patterns
6. ✅ Headers simulator analyzes pasted headers and reports missing ones
7. ✅ Dark theme with neon accent colors applied consistently
8. ✅ Responsive layout works on mobile
9. ✅ All interactions have smooth animations
10. ✅ No console errors during normal operation
