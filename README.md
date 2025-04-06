# Advanced SQL Injection Testing Tool

### Created by: Ali Qassem (@t3s1a0x)

## Description
This is an advanced tool designed to test for SQL injection vulnerabilities in web applications. The tool utilizes a variety of techniques, including WAF (Web Application Firewall) bypass methods, to identify and report potential vulnerabilities. It supports multi-threaded execution, customizable payloads, and HTTP methods.

**Disclaimer:** This tool is strictly for ethical and authorized use only. Misuse is strictly prohibited.

---

## Features
- **Supports both GET and POST methods**
- **Customizable payload injection points**
- **WAF bypass techniques:**
  - URL encoding
  - Escaping characters
  - SQL comment insertion
  - Replacing operators
- **Proxy support** for request routing
- **Custom headers** for more flexibility
- Multi-threaded execution for faster testing
- Detailed vulnerability reports

---

## Installation
1. Clone the repository:
    ```bash
    git clone https://github.com/t3s1a0x/sql-injection-tool.git
    cd sql-injection-tool
    ```
2. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

---

## Usage
### Basic Command
```bash
python sql_tool.py -u "https://example.com/page?id=" -p payloads.txt
```

### Advanced Options
- Specify HTTP method:
    ```bash
    python sql_tool.py -u "https://example.com/page?id=" -p payloads.txt --method POST --data "id=<inject>&name=test"
    ```

- Use a proxy:
    ```bash
    python sql_tool.py -u "https://example.com/page?id=" -p payloads.txt --proxy "http://127.0.0.1:8080"
    ```

- Add custom headers:
    ```bash
    python sql_tool.py -u "https://example.com/page?id=" -p payloads.txt --headers "User-Agent: Custom, Authorization: Bearer token"
    ```

---

## Example Output
```
[#] Advanced SQL Injection Testing Tool [#]
[*] Loaded 50 payloads from payloads.txt
[*] Starting SQL Injection tests...

[!] SQL Injection Vulnerability Detected!
    [+] Payload: ' OR 1=1 --
    [+] Affected URL: https://example.com/page?id=' OR 1=1 --
    [+] HTTP Status Code: 200
    [+] Response Length: 5432 bytes

[!] Stopping further testing as vulnerability was detected.
```

---

## Contributing
Contributions are welcome! Feel free to submit issues or pull requests to improve the tool.

---

## License
This tool is licensed under the MIT License. See the `LICENSE` file for more details.

---

## Author
Ali Qassem (@t3s1a0x)
