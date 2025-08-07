# Elite Nuclei Templates - Structure & Naming Conventions Guide

## Directory Structure

```
elite-nuclei-templates/
├── low-severity/
│   ├── info-disclosure/
│   │   ├── server-info/
│   │   ├── file-exposure/
│   │   ├── debug-info/
│   │   └── technology-detection/
│   ├── version-disclosure/
│   │   ├── cms-versions/
│   │   ├── framework-versions/
│   │   └── service-versions/
│   ├── default-credentials/
│   │   ├── admin-panels/
│   │   ├── databases/
│   │   └── services/
│   ├── misconfigurations/
│   │   ├── security-headers/
│   │   ├── ssl-tls/
│   │   └── cors-config/
│   └── exposed-services/
│       ├── admin-interfaces/
│       ├── monitoring-dashboards/
│       └── development-tools/
├── medium-severity/
│   ├── auth-bypass/
│   │   ├── login-bypass/
│   │   ├── mfa-bypass/
│   │   └── oauth-flaws/
│   ├── session-management/
│   │   ├── session-fixation/
│   │   ├── session-hijacking/
│   │   └── session-prediction/
│   ├── input-validation/
│   │   ├── waf-bypass/
│   │   ├── filter-bypass/
│   │   └── encoding-bypass/
│   ├── api-security/
│   │   ├── rest-api/
│   │   ├── graphql/
│   │   └── soap/
│   ├── business-logic/
│   │   ├── price-manipulation/
│   │   ├── workflow-bypass/
│   │   └── rate-limit-bypass/
│   ├── privilege-escalation/
│   │   ├── horizontal-escalation/
│   │   ├── vertical-escalation/
│   │   └── role-confusion/
│   └── cors-misconfig/
│       ├── wildcard-origins/
│       ├── credential-exposure/
│       └── subdomain-bypass/
├── high-severity/
│   ├── sql-injection/
│   │   ├── union-based/
│   │   ├── blind-sqli/
│   │   ├── error-based/
│   │   ├── time-based/
│   │   └── nosql-injection/
│   ├── xss/
│   │   ├── reflected-xss/
│   │   ├── stored-xss/
│   │   ├── dom-xss/
│   │   ├── csp-bypass/
│   │   └── mutation-xss/
│   ├── ssrf/
│   │   ├── internal-network/
│   │   ├── cloud-metadata/
│   │   ├── file-protocol/
│   │   └── blind-ssrf/
│   ├── file-upload/
│   │   ├── extension-bypass/
│   │   ├── mime-bypass/
│   │   ├── path-traversal/
│   │   └── polyglot-files/
│   ├── xxe-injection/
│   │   ├── classic-xxe/
│   │   ├── blind-xxe/
│   │   ├── xxe-via-upload/
│   │   └── xxe-soap/
│   ├── deserialization/
│   │   ├── java-deserialization/
│   │   ├── php-deserialization/
│   │   ├── python-pickle/
│   │   └── dotnet-deserialization/
│   └── command-injection/
│       ├── direct-injection/
│       ├── blind-injection/
│       ├── time-based-injection/
│       └── os-specific/
├── critical-severity/
│   ├── rce/
│   │   ├── direct-rce/
│   │   ├── template-injection/
│   │   ├── code-injection/
│   │   ├── expression-injection/
│   │   └── framework-specific/
│   ├── auth-bypass-admin/
│   │   ├── admin-takeover/
│   │   ├── root-access/
│   │   ├── jwt-bypass/
│   │   └── saml-bypass/
│   ├── critical-business-logic/
│   │   ├── payment-bypass/
│   │   ├── account-takeover/
│   │   ├── data-exfiltration/
│   │   └── system-config-change/
│   ├── privilege-escalation-admin/
│   │   ├── user-to-admin/
│   │   ├── service-to-system/
│   │   └── container-escape/
│   ├── critical-api/
│   │   ├── api-key-exposure/
│   │   ├── admin-api-access/
│   │   └── mass-assignment-critical/
│   ├── zero-day-style/
│   │   ├── race-conditions/
│   │   ├── memory-corruption/
│   │   ├── logic-bombs/
│   │   └── advanced-persistence/
│   └── infrastructure/
│       ├── container-attacks/
│       ├── kubernetes-exploits/
│       ├── cloud-attacks/
│       └── iot-exploitation/
├── workflows/
│   ├── multi-step-attacks/
│   ├── chained-exploits/
│   └── complex-scenarios/
├── helpers/
│   ├── payloads/
│   ├── wordlists/
│   └── utilities/
└── documentation/
    ├── usage-guides/
    ├── examples/
    └── troubleshooting/
```

## Naming Conventions

### Template File Naming Pattern
```
[severity]-[category]-[technology/target]-[attack-type]-[variant].yaml
```

### Examples by Severity

#### Low Severity Templates
```yaml
# Information Disclosure
low-info-disclosure-apache-server-version.yaml
low-info-disclosure-nginx-status-page.yaml
low-info-disclosure-php-phpinfo.yaml
low-info-disclosure-git-config-exposure.yaml
low-info-disclosure-env-file-disclosure.yaml

# Version Detection
low-version-disclosure-wordpress-version.yaml
low-version-disclosure-drupal-version.yaml
low-version-disclosure-joomla-version.yaml
low-version-disclosure-laravel-version.yaml
low-version-disclosure-spring-boot-version.yaml

# Default Credentials
low-default-creds-admin-admin.yaml
low-default-creds-mysql-root-blank.yaml
low-default-creds-postgres-postgres.yaml
low-default-creds-mongodb-no-auth.yaml
low-default-creds-redis-no-auth.yaml

# Misconfigurations
low-misconfig-missing-hsts.yaml
low-misconfig-missing-csp.yaml
low-misconfig-weak-ssl-cipher.yaml
low-misconfig-cors-wildcard.yaml
low-misconfig-directory-listing.yaml

# Exposed Services
low-exposed-service-phpmyadmin-panel.yaml
low-exposed-service-adminer-panel.yaml
low-exposed-service-grafana-dashboard.yaml
low-exposed-service-jenkins-console.yaml
low-exposed-service-kibana-dashboard.yaml
```

#### Medium Severity Templates
```yaml
# Authentication Bypass
med-auth-bypass-sql-injection-login.yaml
med-auth-bypass-nosql-injection-login.yaml
med-auth-bypass-ldap-injection-login.yaml
med-auth-bypass-jwt-none-algorithm.yaml
med-auth-bypass-oauth-state-bypass.yaml

# Session Management
med-session-fixation-php-session.yaml
med-session-hijacking-weak-token.yaml
med-session-prediction-sequential-id.yaml
med-session-timeout-missing.yaml
med-session-cross-domain-leak.yaml

# Input Validation Bypass
med-input-bypass-waf-cloudflare.yaml
med-input-bypass-waf-akamai.yaml
med-input-bypass-filter-xss.yaml
med-input-bypass-encoding-double.yaml
med-input-bypass-unicode-normalization.yaml

# API Security
med-api-rest-idor-user-data.yaml
med-api-graphql-introspection.yaml
med-api-soap-injection.yaml
med-api-rate-limit-bypass.yaml
med-api-mass-assignment.yaml

# Business Logic
med-business-logic-price-manipulation.yaml
med-business-logic-discount-abuse.yaml
med-business-logic-referral-exploit.yaml
med-business-logic-workflow-bypass.yaml
med-business-logic-quantity-bypass.yaml

# Privilege Escalation
med-privesc-horizontal-user-enum.yaml
med-privesc-vertical-role-confusion.yaml
med-privesc-parameter-pollution.yaml
med-privesc-cookie-manipulation.yaml
med-privesc-header-injection.yaml

# CORS Misconfiguration
med-cors-wildcard-credentials.yaml
med-cors-subdomain-bypass.yaml
med-cors-null-origin-bypass.yaml
med-cors-regex-bypass.yaml
med-cors-protocol-bypass.yaml
```

#### High Severity Templates
```yaml
# SQL Injection
high-sqli-union-mysql-error.yaml
high-sqli-blind-boolean-time.yaml
high-sqli-error-based-mssql.yaml
high-sqli-time-based-postgresql.yaml
high-sqli-nosql-mongodb-injection.yaml

# Cross-Site Scripting
high-xss-reflected-get-param.yaml
high-xss-stored-comment-field.yaml
high-xss-dom-based-hash.yaml
high-xss-csp-bypass-jsonp.yaml
high-xss-mutation-svg-upload.yaml

# Server-Side Request Forgery
high-ssrf-internal-network-scan.yaml
high-ssrf-cloud-metadata-aws.yaml
high-ssrf-file-protocol-read.yaml
high-ssrf-blind-dns-exfiltration.yaml
high-ssrf-http-parameter-pollution.yaml

# File Upload Vulnerabilities
high-file-upload-extension-bypass.yaml
high-file-upload-mime-bypass.yaml
high-file-upload-path-traversal.yaml
high-file-upload-polyglot-php.yaml
high-file-upload-double-extension.yaml

# XML External Entity
high-xxe-classic-file-read.yaml
high-xxe-blind-oob-http.yaml
high-xxe-via-svg-upload.yaml
high-xxe-soap-parameter.yaml
high-xxe-parameter-entity.yaml

# Deserialization
high-deserial-java-commons.yaml
high-deserial-php-unserialize.yaml
high-deserial-python-pickle.yaml
high-deserial-dotnet-binaryformatter.yaml
high-deserial-nodejs-serialize.yaml

# Command Injection
high-cmd-injection-direct-exec.yaml
high-cmd-injection-blind-time.yaml
high-cmd-injection-os-specific.yaml
high-cmd-injection-filter-bypass.yaml
high-cmd-injection-chained-commands.yaml
```

#### Critical Severity Templates
```yaml
# Remote Code Execution
crit-rce-direct-command-exec.yaml
crit-rce-template-injection-jinja2.yaml
crit-rce-code-injection-eval.yaml
crit-rce-expression-injection-spel.yaml
crit-rce-framework-struts2-ognl.yaml

# Authentication Bypass to Admin
crit-auth-bypass-admin-takeover.yaml
crit-auth-bypass-root-access.yaml
crit-auth-bypass-jwt-secret-key.yaml
crit-auth-bypass-saml-assertion.yaml
crit-auth-bypass-kerberos-ticket.yaml

# Critical Business Logic
crit-business-logic-payment-bypass.yaml
crit-business-logic-account-takeover.yaml
crit-business-logic-data-exfiltration.yaml
crit-business-logic-system-config.yaml
crit-business-logic-mass-privilege.yaml

# Privilege Escalation to Admin
crit-privesc-user-to-admin.yaml
crit-privesc-service-to-system.yaml
crit-privesc-container-escape.yaml
crit-privesc-kernel-exploit.yaml
crit-privesc-sudo-bypass.yaml

# Critical API Vulnerabilities
crit-api-key-exposure-admin.yaml
crit-api-admin-endpoint-access.yaml
crit-api-mass-assignment-admin.yaml
crit-api-graphql-admin-query.yaml
crit-api-rest-admin-bypass.yaml

# Zero-Day Style
crit-zero-day-race-condition.yaml
crit-zero-day-memory-corruption.yaml
crit-zero-day-logic-bomb.yaml
crit-zero-day-advanced-persistence.yaml
crit-zero-day-supply-chain.yaml

# Infrastructure Attacks
crit-infra-container-escape.yaml
crit-infra-kubernetes-exploit.yaml
crit-infra-docker-daemon-attack.yaml
crit-infra-cloud-service-exploit.yaml
crit-infra-iot-device-compromise.yaml
```

## Template Structure Standards

### Basic Template Structure
```yaml
id: template-unique-identifier

info:
  name: "Descriptive Template Name"
  author: "elite-security-team"
  severity: low|medium|high|critical
  description: "Detailed description of vulnerability and detection method"
  reference:
    - "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-XXXX-XXXX"
    - "https://example.com/vulnerability-details"
  classification:
    cvss-metrics: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    cvss-score: 9.8
    cve-id: "CVE-XXXX-XXXX"
    cwe-id: "CWE-XXX"
  metadata:
    verified: true
    max-request: 2
    shodan-query: "relevant shodan query"
  tags: severity,category,technology,attack-type

variables:
  payload1: "primary payload"
  payload2: "secondary payload"

http:
  - method: GET|POST|PUT|DELETE
    path:
      - "{{BaseURL}}/vulnerable-endpoint"
      - "{{BaseURL}}/alternative-endpoint"
    
    headers:
      User-Agent: "Elite-Scanner/1.0"
      Content-Type: "application/json"
    
    body: |
      {"param": "{{payload1}}"}
    
    attack: pitchfork|clusterbomb|batteringram
    
    matchers-condition: and|or
    matchers:
      - type: status
        status:
          - 200
          - 500
        condition: or
      
      - type: word
        words:
          - "vulnerability indicator"
          - "error message"
        condition: and
        case-insensitive: true
      
      - type: regex
        regex:
          - 'pattern-match-\d+'
        condition: and
      
      - type: dsl
        dsl:
          - 'len(body) > 1000'
          - 'status_code == 200'
        condition: and
    
    extractors:
      - type: regex
        name: sensitive_data
        regex:
          - 'extract-pattern-([a-zA-Z0-9]+)'
        group: 1
      
      - type: kval
        kval:
          - "response_header_value"
    
    # False Positive Reduction
    matchers:
      - type: word
        words:
          - "legitimate response"
          - "expected behavior"
        negative: true
```

### Advanced Template Features

#### Multi-Step Attack Template
```yaml
id: multi-step-attack-example

info:
  name: "Multi-Step Attack Chain"
  author: "elite-security-team"
  severity: critical
  description: "Complex multi-step attack demonstration"
  tags: multi-step,advanced,critical

http:
  # Step 1: Information Gathering
  - method: GET
    path:
      - "{{BaseURL}}/info-endpoint"
    matchers:
      - type: status
        status:
          - 200
    extractors:
      - type: regex
        name: session_token
        regex:
          - 'token=([a-zA-Z0-9]+)'
        group: 1
        internal: true

  # Step 2: Exploit Using Extracted Data
  - method: POST
    path:
      - "{{BaseURL}}/exploit-endpoint"
    headers:
      Authorization: "Bearer {{session_token}}"
    body: |
      {"exploit": "payload"}
    matchers:
      - type: word
        words:
          - "exploitation successful"
```

#### Race Condition Template
```yaml
id: race-condition-example

info:
  name: "Race Condition Vulnerability"
  author: "elite-security-team"
  severity: high
  description: "Detects race condition vulnerabilities"
  tags: race-condition,timing,advanced

http:
  - method: POST
    path:
      - "{{BaseURL}}/vulnerable-endpoint"
    
    race: true
    race_count: 10
    
    body: |
      {"action": "critical_operation"}
    
    matchers:
      - type: word
        words:
          - "race condition exploited"
```

## Quality Assurance Standards

### Template Validation Checklist
- [ ] **Syntax Validation**: YAML syntax is correct
- [ ] **Functionality Test**: Template works against vulnerable target
- [ ] **False Positive Test**: Template doesn't trigger on secure applications
- [ ] **Performance Test**: Template executes within 5 seconds
- [ ] **Documentation**: Clear description and references provided
- [ ] **Naming Convention**: Follows established naming pattern
- [ ] **Severity Classification**: Correctly classified severity level
- [ ] **Tag Consistency**: Appropriate tags applied
- [ ] **Matcher Accuracy**: Matchers are specific and accurate
- [ ] **Extractor Validation**: Extractors work correctly if present

### Testing Requirements
1. **Positive Testing**: Verify detection on vulnerable applications
2. **Negative Testing**: Ensure no false positives on secure applications
3. **Edge Case Testing**: Test unusual scenarios and configurations
4. **Performance Testing**: Measure execution time and resource usage
5. **Compatibility Testing**: Test across different environments

### Documentation Standards
- **Clear Description**: Explain what the template detects
- **Attack Vector**: Describe the attack method
- **Impact Assessment**: Explain potential impact
- **Remediation**: Provide fix recommendations
- **References**: Include relevant CVE, CWE, and research links
- **Examples**: Provide usage examples

## Maintenance Guidelines

### Regular Updates
- **Threat Intelligence**: Incorporate latest vulnerability data
- **Performance Optimization**: Regular performance improvements
- **False Positive Reduction**: Continuous accuracy improvements
- **Community Feedback**: Address user reports and suggestions
- **Technology Updates**: Update for new technologies and frameworks

### Version Control
- **Semantic Versioning**: Use semantic versioning for releases
- **Change Logs**: Maintain detailed change logs
- **Backward Compatibility**: Ensure compatibility with older versions
- **Migration Guides**: Provide migration guides for breaking changes

This comprehensive structure ensures our 2000+ elite Nuclei templates are:
- **Well-organized** and easy to navigate
- **Consistently named** for easy identification
- **High-quality** with minimal false positives
- **Maintainable** for long-term use
- **Scalable** for future expansion