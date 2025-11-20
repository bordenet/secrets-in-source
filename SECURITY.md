# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly:

### Private Disclosure

**Do not** open a public GitHub issue for security vulnerabilities.

Instead, please email the maintainers directly with:

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Suggested fix (if available)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your vulnerability report within 48 hours
- **Assessment**: We will assess the vulnerability and determine its severity
- **Fix**: We will work on a fix and coordinate disclosure timing with you
- **Credit**: We will credit you in the security advisory (unless you prefer to remain anonymous)

## Security Best Practices

When using passhog:

1. **Review findings carefully**: Not all detected patterns are actual secrets
2. **Secure your output**: Results files may contain sensitive information
3. **Use appropriate permissions**: Ensure scan results are only accessible to authorized users
4. **Regular updates**: Keep passhog updated to benefit from the latest pattern improvements

## Known Limitations

- Passhog performs pattern-based detection and may produce false positives
- Encrypted or obfuscated secrets may not be detected
- Compressed archives (.zip, .tar.gz) are not currently scanned
- Very large files (>100MB) may impact performance

## Scope

This security policy applies to:

- The passhog codebase
- Pattern definition files (*.regex)
- Documentation and examples

It does not cover:

- Third-party dependencies (report to their respective maintainers)
- User-specific configurations or deployments

