# ReconX

## Description
Automated reconnaissance tool for directory enumeration and basic tech fingerprinting.

## Features
- Endpoint enumeration
- Status code filtering
- Threaded execution
- Simple output

## Usage
```bash
python reconx.py -u https://target.com -w wordlist.txt
```

With options:
```bash
python reconx.py -u https://target.com -w wordlist.txt \
  --status 200,301,401 \
  --threads 15 \
  --output results.txt
```

## Disclaimer
Authorized testing only.
