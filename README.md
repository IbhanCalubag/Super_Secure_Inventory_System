SS Inventory Management System is a hardened web-based inventory platform designed with multiple defensive layers, detailed monitoring, and strong access control.

## Overview  
This application provides secure product inventory tracking with integrated security controls such as brute-force protection, two-factor authentication, rate limiting, and centralized logging, making it suitable as a teaching and testing environment for web security best practices.

## Core Security Features  

### Web Application Firewall (WAF)  
- .htaccess rules to filter common malicious patterns and block high‑risk requests.  
- Protection against typical injection and XSS payloads, reducing exposure to automated attacks.

### Security Information & Event Management (SIEM)  
- Centralized logging of authentication events, configuration changes, and security‑relevant actions.  
- Detection of brute‑force attempts and suspicious activity with an auditable trail for investigations.

### Access Control & Sessions  
- Role-based access control (RBAC) separating regular users and administrators.  
- Secure session handling with timeouts, regeneration, and CSRF protection on sensitive forms.

### Authentication & Account Security  
- Brute-force protection with a maximum of five failed login attempts before temporary lockout.  
- Strong password policy enforcement and full logging of login successes and failures.

### Data Protection  
- Server-side validation and sanitization of user input to prevent malformed data and injection.  
- Output encoding and strict file upload validation to minimize XSS and file-based attacks.

## Project Documentation  
- PHASE 1 
- PHASE 2  
- PHASE 3

## Installation & Setup  

1. Create a project directory and change into it:  
   ```bash
   mkdir secured-inventory-system
   cd secured-inventory-system
   ```
