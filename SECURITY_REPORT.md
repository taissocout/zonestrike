# Security Report — ZoneStrike

## Overview
ZoneStrike is a network recon tool built for educational purposes as part of the DIO Cybersecurity Bootcamp.

## Security Considerations

### Input Validation
- Target hostname is validated via DNS resolution before scanning
- Port range inputs are parsed and bounded to prevent abuse

### Rate Limiting
- Thread count is configurable and defaults to a safe value
- Timeout prevents hanging connections

### Legal Disclaimer
- Tool includes explicit warnings about authorized use only
- No exploit capabilities — read-only reconnaissance only

## OWASP Relevance
- A05: Security Misconfiguration — tool helps identify exposed services
- A06: Vulnerable Components — banner grabbing aids version detection
