# Fasthog Examples

This directory contains practical examples of using fasthog in different scenarios.

## Basic Usage Examples

### Scan a Single Directory

```bash
# Scan current directory with default extensions
fasthog .

# Scan specific directory
fasthog /path/to/repository
```

### Filter by File Types

```bash
# Scan only Python files
fasthog ~/projects/myapp --types=py

# Scan infrastructure files
fasthog ~/terraform --types=tf,yml,yaml

# Scan web application files
fasthog ~/webapp --types=js,ts,jsx,tsx,json

# Scan configuration files
fasthog ~/config --types=env,yaml,yml,properties
```

### Output Options

```bash
# Save results to a text file
fasthog /path/to/repo --output=scan_results.txt

# Generate JSON output for CI/CD
fasthog /path/to/repo --format=json --output=results.json

# JSON output (shorthand)
fasthog /path/to/repo --json --output=results.json
```

## Configuration File Examples

### Example 1: Python Project

Create `fasthog.yaml`:

```yaml
extensions:
  - .py
  - .yml
  - .yaml
  - .env

exclude_dirs:
  - venv
  - __pycache__
  - .pytest_cache
  - dist
  - build

output:
  format: text
  path: security_scan.txt
```

Run: `fasthog ~/my-python-project`

### Example 2: Node.js Project

Create `fasthog.yaml`:

```yaml
extensions:
  - .js
  - .ts
  - .jsx
  - .tsx
  - .json
  - .env

exclude_dirs:
  - node_modules
  - dist
  - build
  - coverage

output:
  format: json
  path: secrets_report.json
```

Run: `fasthog ~/my-node-project`

### Example 3: Infrastructure as Code

Create `fasthog.yaml`:

```yaml
extensions:
  - .tf
  - .tfvars
  - .yml
  - .yaml
  - .json

exclude_dirs:
  - .terraform
  - terraform.tfstate.d

output:
  format: json
  path: iac_secrets.json
```

Run: `fasthog ~/infrastructure`

### Example 4: Custom Patterns

Create `custom_patterns.regex` with your own patterns, then create `fasthog.yaml`:

```yaml
extensions:
  - .go
  - .mod

patterns:
  fast: custom_fast_patterns.regex
  strict: custom_strict_patterns.regex
  exclude: custom_exclude_patterns.regex

output:
  format: text
  path: custom_scan.txt
```

Run: `fasthog ~/my-go-project --config=fasthog.yaml`

## CI/CD Integration Examples

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  secrets-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      
      - name: Install fasthog
        run: |
          git clone https://github.com/bordenet/secrets-in-source.git
          cd secrets-in-source
          go install
      
      - name: Scan for secrets
        run: |
          fasthog . --format=json --output=secrets.json
          
      - name: Check for secrets
        run: |
          if [ -s secrets.json ]; then
            echo "Secrets detected!"
            cat secrets.json
            exit 1
          fi
```

### GitLab CI

```yaml
secrets-scan:
  stage: security
  image: golang:1.22
  script:
    - git clone https://github.com/bordenet/secrets-in-source.git
    - cd secrets-in-source && go install && cd ..
    - fasthog . --json --output=secrets.json
    - |
      if [ -s secrets.json ]; then
        echo "Secrets detected!"
        cat secrets.json
        exit 1
      fi
  artifacts:
    paths:
      - secrets.json
    when: always
```

## Advanced Usage

### Combining with Other Tools

```bash
# Scan and filter results with jq
fasthog /path/to/repo --json --output=results.json
jq '.matches[] | select(.file | contains("config"))' results.json

# Count matches by file type
fasthog /path/to/repo --json --output=results.json
jq '.matches | group_by(.file | split(".") | last) | map({ext: .[0].file | split(".") | last, count: length})' results.json
```

### Pre-commit Hook

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash

echo "Scanning for secrets..."
fasthog . --json --output=/tmp/fasthog_precommit.json

if [ -s /tmp/fasthog_precommit.json ]; then
    echo "ERROR: Secrets detected in staged files!"
    fasthog . --output=/dev/stdout
    rm /tmp/fasthog_precommit.json
    exit 1
fi

rm /tmp/fasthog_precommit.json
exit 0
```

Make it executable: `chmod +x .git/hooks/pre-commit`

