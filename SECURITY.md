# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

The CVEWatch team takes security seriously. We appreciate your efforts to responsibly disclose your findings.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities by emailing the maintainers directly or through GitHub's private security advisory feature:

1. **GitHub Security Advisory** (Preferred):

   - Go to https://github.com/Amet13/CVEWatch/security/advisories
   - Click "Report a vulnerability"
   - Fill out the form with details

2. **Email**:
   - Send details to the project maintainers
   - Include "CVEWatch Security" in the subject line

### What to Include

Please include the following information in your report:

- **Type of vulnerability** (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- **Full paths** of source file(s) related to the vulnerability
- **Location** of the affected source code (tag/branch/commit or direct URL)
- **Step-by-step instructions** to reproduce the issue
- **Proof-of-concept or exploit code** (if possible)
- **Impact** of the vulnerability and how an attacker might exploit it
- **Any special configuration** required to reproduce the issue

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 5 business days
- **Fix Timeline**: Varies based on severity (see below)

### Severity Levels and Response Times

| Severity     | Description                           | Target Fix Time |
| ------------ | ------------------------------------- | --------------- |
| **Critical** | Actively exploited, RCE, data breach  | 1-7 days        |
| **High**     | Major security impact, no workaround  | 7-30 days       |
| **Medium**   | Moderate impact, workaround available | 30-60 days      |
| **Low**      | Minor impact, limited scope           | 60-90 days      |

### What to Expect

1. **Acknowledgment**: We'll acknowledge receipt of your vulnerability report
2. **Assessment**: We'll assess the vulnerability and determine its severity
3. **Updates**: We'll provide regular updates on our progress
4. **Fix**: We'll work on a fix and coordinate disclosure timing
5. **Credit**: We'll credit you in the security advisory (if desired)
6. **Disclosure**: We'll publicly disclose the vulnerability after a fix is available

### Public Disclosure Policy

- We request that you give us reasonable time to address the vulnerability before public disclosure
- Coordinated disclosure helps protect users and gives them time to update
- We aim to disclose vulnerabilities within 90 days of the initial report
- We'll work with you to agree on a disclosure timeline

### Security Update Process

When a security fix is released:

1. **Security Advisory**: Posted to GitHub Security Advisories
2. **Release Notes**: Included in the release with severity level
3. **Notification**: Users notified through GitHub releases and repository
4. **CVE**: Request CVE ID for significant vulnerabilities

## Security Best Practices for Users

### API Key Management

- **Never commit API keys** to version control
- Use environment variables: `export CVEWATCH_API_KEY=your-key-here`
- Rotate API keys regularly
- Use separate keys for different environments

### Configuration Security

- Store `config.yaml` with restricted permissions (600)
- Don't expose configuration files in public repositories
- Review security settings in configuration:
  ```yaml
  security:
    enable_ssl_verification: true # Always keep this enabled
    user_agent: "CVEWatch/2"
  ```

### Running CVEWatch Securely

- **Keep Updated**: Always use the latest version
- **Verify Downloads**: Check checksums when downloading releases
- **Scan Dependencies**: Run `go mod verify` to check dependencies
- **Least Privilege**: Run with minimal necessary permissions
- **Network Security**: Be aware of network requests to NVD API

### Dependencies

We regularly:

- Monitor dependencies for known vulnerabilities
- Update dependencies to patched versions
- Use `go mod verify` in CI/CD pipeline
- Run security scanners (gosec) on every commit

## Known Security Considerations

### API Rate Limiting

- Without API key: 100 requests/hour (NVD limitation)
- With API key: 1000 requests/hour (NVD limitation)
- Client-side rate limiting prevents hitting NVD limits
- Respect NVD API terms of service

### Data Validation

- All CVE IDs are validated before API calls
- Input sanitization prevents injection attacks
- HTTPS enforced for all API communications
- SSL/TLS verification enabled by default

### Error Handling

- Errors don't expose sensitive system information
- API keys not logged or displayed in error messages
- Stack traces sanitized in production builds

## Security Scanning

### Automated Security Checks

We use multiple security tools:

- **gosec**: Go security checker (runs on every commit)
- **CodeQL**: GitHub's semantic code analysis
- **Dependabot**: Automated dependency updates
- **golangci-lint**: Including security-focused linters

### Running Security Scans Locally

```bash
# Run security scan
make security-scan

# View security report
cat security-report.json

# Run full quality checks (includes security)
make pre-commit
```

## Vulnerability Disclosure History

No vulnerabilities have been reported or disclosed for this project yet.

## Security Contacts

For security-related questions or concerns:

- GitHub Security Advisories (preferred)
- Project maintainers via GitHub

## Compliance

CVEWatch:

- Uses HTTPS for all external communications
- Validates SSL/TLS certificates
- Follows OWASP security guidelines
- Implements secure coding practices
- Regular security audits through automated tools

## Additional Resources

- [NVD API Security](https://nvd.nist.gov/developers)
- [Go Security Policy](https://go.dev/security)
- [OWASP Go Secure Coding Practices](https://owasp.org/www-project-go-secure-coding-practices-guide/)

## Attribution

This security policy is based on industry best practices and adapted for CVEWatch.

---

**Last Updated**: 2025-01-01
**Version**: 2.0.0
