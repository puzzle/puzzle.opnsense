# Security Policy

## Supported Versions

We provide security updates for the following versions of the puzzle.opnsense Ansible Collection:

| Version | Supported          |
| ------- | ------------------ |
| 1.5.x   | :white_check_mark: |
| < 1.5.0 | :x:                |

## Reporting a Vulnerability

### Security Issues

If you discover a security vulnerability within this project, please report it responsibly. **Do not create a public GitHub issue** for security vulnerabilities.

Instead, please send an email to [SECURITY_EMAIL](mailto:security@puzzle.ch) with the subject line "SECURITY: [puzzle.opnsense] Vulnerability Report".

### What to Include

When reporting a vulnerability, please include as much information as possible, including:

- A detailed description of the vulnerability
- Steps to reproduce the issue
- The version of the collection where the vulnerability was found
- Any potential impact of the vulnerability
- Any suggested mitigations or fixes

### Our Commitment

- We will acknowledge receipt of your report within 3 business days
- We will confirm the vulnerability and determine its impact
- We will work on a fix as soon as possible
- We will keep you informed of our progress
- We will credit you in our security advisory (unless you prefer to remain anonymous)

### Public Disclosure

We follow responsible disclosure practices:

- Vulnerabilities will be disclosed publicly after a fix is available
- We will credit the reporter unless they wish to remain anonymous
- We will provide a detailed security advisory with each disclosure

## Security Updates

Security updates are released as patch versions. We recommend always using the latest version of the collection to ensure you have all security fixes.

To update to the latest version:

```bash
ansible-galaxy collection install puzzle.opnsense --upgrade
```

## Dependencies

This project depends on several third-party packages. We regularly update our dependencies to include the latest security patches. You can check for known vulnerabilities in our dependencies using:

```bash
pip install safety
safety check --full-report
```

## Secure Configuration

When using this collection, please ensure you follow security best practices:

- Never commit sensitive data (passwords, API keys) to version control
- Use Ansible Vault for encrypting sensitive data
- Follow the principle of least privilege when configuring user permissions
- Regularly rotate credentials and API keys
- Keep your Ansible control node and managed nodes up to date with security patches
