"""
Static remediation library.

When Ollama is unavailable (connection error, timeout, model not loaded)
the remediation engine falls back to this dictionary instead of writing
"LLM request failed" in the report.

Look-up priority:
  1. TEST_ID_REMEDIATIONS  — most specific (tool + rule ID)
  2. CWE_REMEDIATIONS      — broad fallback by CWE number
  3. GENERIC_FALLBACK      — last resort
"""

# ── Per-rule remediations ─────────────────────────────────────────────────────

TEST_ID_REMEDIATIONS: dict[str, str] = {

    # ── Bandit: injection & process execution ─────────────────────────────────
    "B102": (
        "EXPLANATION:\n"
        "exec() runs arbitrary Python code. If any part of the string comes "
        "from user input this is Remote Code Execution.\n\n"
        "FIX:\n"
        "Remove exec(). Use a dispatch table of explicit function calls.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "exec(user_input)\n"
        "# After\n"
        "ALLOWED = {'foo': foo_fn, 'bar': bar_fn}\n"
        "ALLOWED[user_input]()"
    ),
    "B307": (
        "EXPLANATION:\n"
        "eval() executes arbitrary Python. Any user-controlled data reaching "
        "it is Remote Code Execution.\n\n"
        "FIX:\n"
        "Replace eval() with ast.literal_eval() for literals, or restructure "
        "the logic to avoid dynamic evaluation entirely.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "result = eval(user_expr)\n"
        "# After\n"
        "import ast\n"
        "result = ast.literal_eval(user_expr)"
    ),
    "B602": (
        "EXPLANATION:\n"
        "subprocess with shell=True and a string command — shell metacharacters "
        "in the input string enable OS command injection.\n\n"
        "FIX:\n"
        "Use shell=False (the default) and pass arguments as a list.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "subprocess.run(f'ls {path}', shell=True)\n"
        "# After\n"
        "subprocess.run(['ls', path], shell=False)"
    ),
    "B603": (
        "EXPLANATION:\n"
        "subprocess.Popen without shell=True is safer, but argv[0] must never "
        "come from user input — it controls which binary runs.\n\n"
        "FIX:\n"
        "Validate or whitelist the executable path before passing it.\n\n"
        "EXAMPLE:\n"
        "ALLOWED_BINS = ['/usr/bin/ls', '/usr/bin/stat']\n"
        "assert cmd[0] in ALLOWED_BINS\n"
        "subprocess.Popen(cmd)"
    ),
    "B604": (
        "EXPLANATION:\n"
        "A function is being called with shell=True — any user-controlled "
        "data in the command string allows OS command injection.\n\n"
        "FIX:\n"
        "Always pass shell=False and supply arguments as a list.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "os.system(f'convert {filename}')\n"
        "# After\n"
        "subprocess.run(['convert', filename], shell=False)"
    ),
    "B605": (
        "EXPLANATION:\n"
        "os.system() (or similar) passes the command to /bin/sh. Any "
        "shell metacharacter in the argument enables OS command injection.\n\n"
        "FIX:\n"
        "Replace os.system() with subprocess.run(args_list, shell=False). "
        "Pass arguments as a list, never as a formatted string.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "os.system(f'ping {host}')\n"
        "# After\n"
        "subprocess.run(['ping', '-c', '1', host], shell=False)"
    ),
    "B607": (
        "EXPLANATION:\n"
        "Using a relative/partial executable name — the binary is resolved "
        "via PATH, which can be hijacked to run a malicious binary.\n\n"
        "FIX:\n"
        "Use the absolute path to the executable.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "subprocess.run(['git', 'clone', url])\n"
        "# After\n"
        "subprocess.run(['/usr/bin/git', 'clone', url])"
    ),
    "B608": (
        "EXPLANATION:\n"
        "SQL query built with string formatting — user input in the query "
        "string enables SQL Injection (CWE-89).\n\n"
        "FIX:\n"
        "Use parameterised queries. Pass values as the second argument to "
        "cursor.execute() — never format them into the SQL string.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "cursor.execute(f'SELECT * FROM users WHERE id={uid}')\n"
        "# After\n"
        "cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))"
    ),

    # ── Bandit: secrets & credentials ─────────────────────────────────────────
    "B105": (
        "EXPLANATION:\n"
        "Hardcoded password in source code — credentials in a repository "
        "are accessible to anyone with read access.\n\n"
        "FIX:\n"
        "Move secrets to environment variables or a secrets manager "
        "(HashiCorp Vault, AWS Secrets Manager, etc.).\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "password = 'hunter2'\n"
        "# After\n"
        "import os\n"
        "password = os.environ['APP_PASSWORD']"
    ),
    "B106": (
        "EXPLANATION:\n"
        "Hardcoded password passed as a function argument — same risk as "
        "B105, credentials are visible in source.\n\n"
        "FIX:\n"
        "Load the credential from an environment variable at call time.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "connect(password='secret')\n"
        "# After\n"
        "connect(password=os.environ['DB_PASS'])"
    ),
    "B107": (
        "EXPLANATION:\n"
        "Hardcoded password as a default function argument — defaults are "
        "stored in bytecode and visible in source.\n\n"
        "FIX:\n"
        "Use None as default; read from the environment inside the function.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "def connect(pw='secret'): ...\n"
        "# After\n"
        "def connect(pw=None):\n"
        "    pw = pw or os.environ['DB_PASS']"
    ),

    # ── Bandit: cryptography ───────────────────────────────────────────────────
    "B303": (
        "EXPLANATION:\n"
        "MD5 or SHA-1 is used — both are cryptographically broken and "
        "vulnerable to collision attacks.\n\n"
        "FIX:\n"
        "Use SHA-256 or SHA-3 for checksums/signatures. For password "
        "storage use bcrypt, scrypt, or argon2.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "hashlib.md5(data).hexdigest()\n"
        "# After\n"
        "hashlib.sha256(data).hexdigest()"
    ),
    "B311": (
        "EXPLANATION:\n"
        "random module is not cryptographically secure — values are "
        "predictable and must not be used for tokens or passwords.\n\n"
        "FIX:\n"
        "Use the secrets module for all security-sensitive randomness.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "token = str(random.random())\n"
        "# After\n"
        "import secrets\n"
        "token = secrets.token_urlsafe(32)"
    ),
    "B501": (
        "EXPLANATION:\n"
        "TLS certificate verification is disabled — the connection is "
        "vulnerable to man-in-the-middle attacks.\n\n"
        "FIX:\n"
        "Remove verify=False. Certificate verification is on by default "
        "and should never be disabled in production.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "requests.get(url, verify=False)\n"
        "# After\n"
        "requests.get(url)  # verify=True is the default"
    ),
    "B506": (
        "EXPLANATION:\n"
        "yaml.load() without a Loader deserialises arbitrary Python "
        "objects — a malicious YAML file can execute code on load.\n\n"
        "FIX:\n"
        "Use yaml.safe_load() which restricts parsing to basic types.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "data = yaml.load(stream)\n"
        "# After\n"
        "data = yaml.safe_load(stream)"
    ),
    "B301": (
        "EXPLANATION:\n"
        "pickle.loads() deserialises arbitrary Python objects — a "
        "malicious payload executes code during deserialisation.\n\n"
        "FIX:\n"
        "Replace pickle with json or msgpack. Never unpickle data "
        "from untrusted sources.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "obj = pickle.loads(data)\n"
        "# After\n"
        "obj = json.loads(data)"
    ),

    # ── Bandit: network & misc ─────────────────────────────────────────────────
    "B104": (
        "EXPLANATION:\n"
        "Service bound to 0.0.0.0 exposes it on every network interface, "
        "including public-facing ones.\n\n"
        "FIX:\n"
        "Bind to 127.0.0.1 for local services. Use a reverse proxy "
        "(nginx, caddy) for external exposure.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "app.run(host='0.0.0.0')\n"
        "# After\n"
        "app.run(host='127.0.0.1')"
    ),
    "B113": (
        "EXPLANATION:\n"
        "HTTP request made without a timeout — the call can block "
        "indefinitely, exhausting worker threads (DoS).\n\n"
        "FIX:\n"
        "Pass timeout=(connect_secs, read_secs) to every requests call.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "requests.get(url)\n"
        "# After\n"
        "requests.get(url, timeout=(5, 30))"
    ),
    "B201": (
        "EXPLANATION:\n"
        "Flask debug mode is enabled — the interactive debugger allows "
        "arbitrary code execution for anyone who triggers an error.\n\n"
        "FIX:\n"
        "Set debug=False in production. Gate it behind an environment "
        "variable.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "app.run(debug=True)\n"
        "# After\n"
        "app.run(debug=os.getenv('FLASK_DEBUG', 'false') == 'true')"
    ),
    "B108": (
        "EXPLANATION:\n"
        "Predictable temporary file path — a race condition between "
        "name generation and file creation enables symlink attacks.\n\n"
        "FIX:\n"
        "Use tempfile.NamedTemporaryFile() or tempfile.mkstemp() which "
        "create files with unpredictable names and secure permissions.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "open('/tmp/myapp.tmp', 'w')\n"
        "# After\n"
        "with tempfile.NamedTemporaryFile(delete=False) as f:\n"
        "    f.write(data)"
    ),
    "B314": (
        "EXPLANATION:\n"
        "xml.etree.ElementTree is vulnerable to XML entity expansion "
        "(Billion Laughs / XXE) when parsing untrusted input.\n\n"
        "FIX:\n"
        "Install and use defusedxml, which disables dangerous XML "
        "features by default.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "from xml.etree import ElementTree as ET\n"
        "# After\n"
        "import defusedxml.ElementTree as ET"
    ),
    "B701": (
        "EXPLANATION:\n"
        "Jinja2 Environment created with autoescape=False — any "
        "user-controlled variable can inject HTML/JavaScript (XSS).\n\n"
        "FIX:\n"
        "Enable autoescape=True in the Environment constructor.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "Environment(loader=loader, autoescape=False)\n"
        "# After\n"
        "Environment(loader=loader, autoescape=True)"
    ),

    # ── Pylint ────────────────────────────────────────────────────────────────
    "W0611": (
        "EXPLANATION:\n"
        "Unused import — the module is imported but never referenced. "
        "Unused imports increase attack surface if the module has "
        "side-effects or is later misused.\n\n"
        "FIX:\n"
        "Remove the unused import line entirely.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "import subprocess  # never used\n"
        "# After\n"
        "# (line removed)"
    ),
    "W3101": (
        "EXPLANATION:\n"
        "requests method called without a timeout argument — the call can "
        "hang indefinitely and exhaust server resources.\n\n"
        "FIX:\n"
        "Add timeout=(connect_seconds, read_seconds) to every requests call.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "requests.get(url)\n"
        "# After\n"
        "requests.get(url, timeout=(5, 30))"
    ),
    "W0703": (
        "EXPLANATION:\n"
        "Catching a broad Exception silently swallows all errors, masking "
        "bugs and security events.\n\n"
        "FIX:\n"
        "Catch only the specific exception types you expect and always log.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "except Exception:\n"
        "    pass\n"
        "# After\n"
        "except (ValueError, IOError) as e:\n"
        "    logger.error('Unexpected error: %s', e)"
    ),

    # ── WAF / Web ─────────────────────────────────────────────────────────────
    "WAF-MISSING": (
        "EXPLANATION:\n"
        "No Web Application Firewall fingerprint was detected by wafw00f. "
        "Important caveat: cloud-native WAFs such as Google Cloud Armor, "
        "AWS WAF, and Cloudflare do not expose the HTTP fingerprints that "
        "wafw00f relies on, so this finding may be a false positive for "
        "large cloud providers. Google.com, for example, is protected by "
        "Google Cloud Armor.\n\n"
        "FIX:\n"
        "If no WAF is in place, deploy one. Recommended options:\n"
        "  - Cloudflare WAF (managed rules, free tier available)\n"
        "  - AWS WAF with managed rule groups\n"
        "  - Google Cloud Armor security policies\n"
        "  - ModSecurity with OWASP CRS (self-hosted)\n\n"
        "EXAMPLE:\n"
        "# Nginx + ModSecurity\n"
        "modsecurity on;\n"
        "modsecurity_rules_file /etc/nginx/modsec/main.conf;"
    ),
    "WAF-DETECTED": (
        "EXPLANATION:\n"
        "A Web Application Firewall was detected. This is informational — "
        "a WAF is a defence-in-depth layer, not a complete security solution.\n\n"
        "FIX:\n"
        "Ensure WAF rules are kept up to date. A WAF should complement, "
        "not replace, secure coding practices such as input validation "
        "and parameterised queries.\n\n"
        "EXAMPLE:\n"
        "# Regularly review and update WAF rule sets.\n"
        "# Enable logging and alerting on blocked requests."
    ),

    # ── Network (nmap) ────────────────────────────────────────────────────────
    "PORT-21": (
        "EXPLANATION:\n"
        "FTP is exposed on port 21. FTP transmits credentials and data "
        "in cleartext — trivial to intercept on any network path.\n\n"
        "FIX:\n"
        "Disable FTP. Replace with SFTP (SSH port 22) or FTPS.\n\n"
        "EXAMPLE:\n"
        "# Block FTP at the firewall\n"
        "iptables -A INPUT -p tcp --dport 21 -j DROP"
    ),
    "PORT-22": (
        "EXPLANATION:\n"
        "SSH is exposed publicly. Brute-force and credential-stuffing "
        "attacks are common against public SSH.\n\n"
        "FIX:\n"
        "Disable password authentication; use key-based auth only. "
        "Restrict access by IP. Consider moving to a non-standard port "
        "or using a VPN/bastion host.\n\n"
        "EXAMPLE:\n"
        "# /etc/ssh/sshd_config\n"
        "PasswordAuthentication no\n"
        "PermitRootLogin no\n"
        "AllowUsers deploy"
    ),
    "PORT-23": (
        "EXPLANATION:\n"
        "Telnet is exposed on port 23. All traffic — including credentials "
        "— is sent in plaintext.\n\n"
        "FIX:\n"
        "Disable Telnet immediately. Replace with SSH.\n\n"
        "EXAMPLE:\n"
        "systemctl disable telnet\n"
        "iptables -A INPUT -p tcp --dport 23 -j DROP"
    ),
    "PORT-3306": (
        "EXPLANATION:\n"
        "MySQL is exposed to the public internet. Databases should never "
        "be directly reachable from outside the private network.\n\n"
        "FIX:\n"
        "Bind MySQL to 127.0.0.1 or a private interface only. Use a "
        "VPN or SSH tunnel for remote DBA access.\n\n"
        "EXAMPLE:\n"
        "# /etc/mysql/mysql.conf.d/mysqld.cnf\n"
        "bind-address = 127.0.0.1"
    ),
    "PORT-5432": (
        "EXPLANATION:\n"
        "PostgreSQL is exposed to the public internet — a serious "
        "misconfiguration that risks data exfiltration.\n\n"
        "FIX:\n"
        "Restrict pg_hba.conf to local/private addresses. Never expose "
        "the database port publicly.\n\n"
        "EXAMPLE:\n"
        "# postgresql.conf\n"
        "listen_addresses = '127.0.0.1'\n"
        "# pg_hba.conf: allow only app server IP"
    ),
    "PORT-6379": (
        "EXPLANATION:\n"
        "Redis is exposed publicly. Redis has no authentication by default "
        "and allows reading all data and executing Lua scripts.\n\n"
        "FIX:\n"
        "Bind Redis to 127.0.0.1. Set a strong requirepass in redis.conf. "
        "Block port 6379 at the firewall.\n\n"
        "EXAMPLE:\n"
        "# redis.conf\n"
        "bind 127.0.0.1\n"
        "requirepass your_strong_password_here"
    ),
    "PORT-27017": (
        "EXPLANATION:\n"
        "MongoDB is exposed publicly. Default MongoDB has no authentication "
        "— attackers can read, overwrite, or delete all data.\n\n"
        "FIX:\n"
        "Enable --auth. Bind to 127.0.0.1. Block port 27017 at the "
        "firewall.\n\n"
        "EXAMPLE:\n"
        "# mongod.conf\n"
        "net:\n"
        "  bindIp: 127.0.0.1\n"
        "security:\n"
        "  authorization: enabled"
    ),
    "PORT-445": (
        "EXPLANATION:\n"
        "SMB (port 445) is exposed — this is the primary propagation "
        "vector for ransomware (WannaCry, NotPetya).\n\n"
        "FIX:\n"
        "Block port 445 at the perimeter firewall immediately. SMB "
        "must never be internet-facing.\n\n"
        "EXAMPLE:\n"
        "iptables -A INPUT -p tcp --dport 445 -j DROP\n"
        "iptables -A INPUT -p udp --dport 445 -j DROP"
    ),
    "PORT-2375": (
        "EXPLANATION:\n"
        "Docker daemon is exposed on port 2375 without TLS — any remote "
        "caller can gain full root access to the host.\n\n"
        "FIX:\n"
        "Close port 2375 immediately. If remote Docker API access is "
        "needed, enable TLS mutual auth on port 2376.\n\n"
        "EXAMPLE:\n"
        "# /etc/docker/daemon.json\n"
        '{"hosts": ["unix:///var/run/docker.sock"]}'
    ),

    # ── Secret detection ───────────────────────────────────────────────────────
    "GITLEAKS": (
        "EXPLANATION:\n"
        "A secret or credential was found in the repository history or "
        "source code — exposed secrets must be treated as compromised.\n\n"
        "FIX:\n"
        "1. Revoke and rotate the exposed credential immediately.\n"
        "2. Remove it from the git history with git-filter-repo.\n"
        "3. Move all secrets to environment variables or a secrets manager.\n"
        "4. Add pre-commit hooks (gitleaks, trufflehog) to prevent future leaks.\n\n"
        "EXAMPLE:\n"
        "pip install pre-commit\n"
        "# .pre-commit-config.yaml\n"
        "repos:\n"
        "  - repo: https://github.com/gitleaks/gitleaks\n"
        "    hooks:\n"
        "      - id: gitleaks"
    ),

    # ── Binary / checksec ──────────────────────────────────────────────────────
    "CHECKSEC-NX": (
        "EXPLANATION:\n"
        "NX (No-Execute) is disabled — the stack and heap are executable, "
        "making classic shellcode injection attacks possible.\n\n"
        "FIX:\n"
        "Compile with NX enabled (the default for modern compilers). "
        "Remove any -z execstack linker flags.\n\n"
        "EXAMPLE:\n"
        "# Before (explicitly disabled)\n"
        "gcc -z execstack -o binary source.c\n"
        "# After (default — NX is on)\n"
        "gcc -o binary source.c"
    ),
    "CHECKSEC-CANARY": (
        "EXPLANATION:\n"
        "Stack canary is absent — buffer overflows on the stack are not "
        "detected and can overwrite the return address.\n\n"
        "FIX:\n"
        "Compile with -fstack-protector-strong (GCC/Clang).\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "gcc -o binary source.c\n"
        "# After\n"
        "gcc -fstack-protector-strong -o binary source.c"
    ),
    "CHECKSEC-PIE": (
        "EXPLANATION:\n"
        "PIE (Position-Independent Executable) is disabled — the binary "
        "loads at a fixed address, making ASLR ineffective.\n\n"
        "FIX:\n"
        "Compile with -fPIE -pie.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "gcc -o binary source.c\n"
        "# After\n"
        "gcc -fPIE -pie -o binary source.c"
    ),
    "CHECKSEC-RELRO": (
        "EXPLANATION:\n"
        "RELRO is disabled — the GOT (Global Offset Table) is writable "
        "after startup, allowing GOT overwrite attacks.\n\n"
        "FIX:\n"
        "Link with Full RELRO: -Wl,-z,relro,-z,now.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "gcc -o binary source.c\n"
        "# After\n"
        "gcc -Wl,-z,relro,-z,now -o binary source.c"
    ),
}


# ── Per-CWE remediations (broad fallback) ─────────────────────────────────────

CWE_REMEDIATIONS: dict[str, str] = {

    "CWE-78": (
        "EXPLANATION:\n"
        "OS Command Injection — user-controlled data reaches a shell command, "
        "allowing an attacker to execute arbitrary OS commands.\n\n"
        "FIX:\n"
        "Never build shell commands from user input. Use subprocess with "
        "shell=False and a list of arguments. Validate all inputs against "
        "a strict allowlist before use.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "os.system(f'convert {user_file}')\n"
        "# After\n"
        "subprocess.run(['convert', user_file], shell=False)"
    ),
    "CWE-89": (
        "EXPLANATION:\n"
        "SQL Injection — user input is embedded directly in a SQL query, "
        "allowing an attacker to read, modify, or delete database data.\n\n"
        "FIX:\n"
        "Use parameterised queries / prepared statements for every database "
        "call. Never concatenate or format user input into SQL strings.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "cursor.execute(f\"SELECT * FROM users WHERE name='{name}'\")\n"
        "# After\n"
        "cursor.execute('SELECT * FROM users WHERE name = %s', (name,))"
    ),
    "CWE-79": (
        "EXPLANATION:\n"
        "Cross-Site Scripting (XSS) — user input is rendered in HTML "
        "without escaping, allowing script injection in victims' browsers.\n\n"
        "FIX:\n"
        "HTML-escape all user-controlled values before rendering. Use "
        "template engines with autoescape enabled (Jinja2 autoescape=True).\n\n"
        "EXAMPLE:\n"
        "# Flask/Jinja2\n"
        "# Unsafe: {{ user_input | safe }}\n"
        "# Safe:   {{ user_input }}  (autoescaped)"
    ),
    "CWE-22": (
        "EXPLANATION:\n"
        "Path Traversal — user-supplied file paths contain '../' sequences "
        "that escape the intended directory.\n\n"
        "FIX:\n"
        "Resolve the full path and verify it starts with the allowed base "
        "directory before opening any file.\n\n"
        "EXAMPLE:\n"
        "base = os.path.realpath('/app/uploads')\n"
        "target = os.path.realpath(os.path.join(base, user_filename))\n"
        "if not target.startswith(base + os.sep):\n"
        "    raise ValueError('Path traversal blocked')"
    ),
    "CWE-798": (
        "EXPLANATION:\n"
        "Hardcoded credential in source code — any person with repository "
        "access (or access to compiled binaries) can extract the secret.\n\n"
        "FIX:\n"
        "Store all credentials in environment variables or a dedicated "
        "secrets manager. Rotate the exposed credential immediately.\n\n"
        "EXAMPLE:\n"
        "# Before\n"
        "API_KEY = 'sk-abc123'\n"
        "# After\n"
        "API_KEY = os.environ['API_KEY']"
    ),
    "CWE-400": (
        "EXPLANATION:\n"
        "Uncontrolled Resource Consumption — a missing timeout, unbounded "
        "loop, or unconstrained allocation allows an attacker to exhaust "
        "CPU, memory, or threads (Denial of Service).\n\n"
        "FIX:\n"
        "Add timeouts to all blocking I/O calls. Set limits on loop "
        "iterations, payload sizes, and connection counts.\n\n"
        "EXAMPLE:\n"
        "requests.get(url, timeout=(5, 30))  # (connect, read)"
    ),
    "CWE-20": (
        "EXPLANATION:\n"
        "Improper Input Validation — data from an external source is used "
        "without sufficient validation, enabling a wide range of attacks.\n\n"
        "FIX:\n"
        "Validate all external input against a strict allowlist. Reject "
        "anything that does not match. Use Pydantic or marshmallow for "
        "structured validation in Python.\n\n"
        "EXAMPLE:\n"
        "from pydantic import BaseModel, constr\n"
        "class Request(BaseModel):\n"
        "    username: constr(pattern=r'^[a-z0-9_]{3,32}$')"
    ),
    "CWE-693": (
        "EXPLANATION:\n"
        "Protection Mechanism Failure — a critical security control "
        "(such as a WAF, CSRF token, or Content Security Policy) is "
        "absent or misconfigured.\n\n"
        "FIX:\n"
        "Identify the missing control and implement it. For missing WAF: "
        "deploy Cloudflare, AWS WAF, or ModSecurity with OWASP CRS. "
        "For missing CSRF protection: add SameSite cookies and CSRF tokens.\n\n"
        "EXAMPLE:\n"
        "# Content-Security-Policy header\n"
        "Content-Security-Policy: default-src 'self'; script-src 'self'"
    ),
    "CWE-200": (
        "EXPLANATION:\n"
        "Information Exposure — the application reveals sensitive details "
        "(software versions, stack traces, internal paths) that help "
        "an attacker plan further attacks.\n\n"
        "FIX:\n"
        "Disable debug/verbose error output in production. Return generic "
        "error messages to clients and log details server-side only.\n\n"
        "EXAMPLE:\n"
        "# Flask\n"
        "app.config['PROPAGATE_EXCEPTIONS'] = False\n"
        "# Return: {'error': 'Internal server error'}  # not the traceback"
    ),
    "CWE-284": (
        "EXPLANATION:\n"
        "Improper Access Control — a resource or service is reachable "
        "without proper authentication or authorisation checks.\n\n"
        "FIX:\n"
        "Apply authentication and role-based access control to every "
        "sensitive endpoint. Implement network-level controls (firewall "
        "rules, security groups) as a defence-in-depth layer.\n\n"
        "EXAMPLE:\n"
        "# FastAPI\n"
        "@router.get('/admin')\n"
        "def admin(user=Depends(require_admin_role)): ..."
    ),
    "CWE-319": (
        "EXPLANATION:\n"
        "Cleartext Transmission — sensitive data (credentials, tokens, PII) "
        "is transmitted without encryption and can be intercepted.\n\n"
        "FIX:\n"
        "Enforce HTTPS/TLS for all external communication. Disable HTTP "
        "entirely or redirect to HTTPS. Use TLS 1.2 or 1.3 only.\n\n"
        "EXAMPLE:\n"
        "# nginx\n"
        "server {\n"
        "  listen 80; return 301 https://$host$request_uri;\n"
        "}\n"
        "server {\n"
        "  listen 443 ssl; ssl_protocols TLSv1.2 TLSv1.3;\n"
        "}"
    ),
    "CWE-352": (
        "EXPLANATION:\n"
        "Cross-Site Request Forgery (CSRF) — a malicious site can trigger "
        "state-changing requests on behalf of an authenticated user.\n\n"
        "FIX:\n"
        "Use SameSite=Strict cookies and include a CSRF token in every "
        "state-changing form or API request.\n\n"
        "EXAMPLE:\n"
        "# FastAPI with fastapi-csrf-protect\n"
        "from fastapi_csrf_protect import CsrfProtect\n"
        "@app.post('/transfer')\n"
        "def transfer(csrf: CsrfProtect = Depends()): csrf.validate_csrf(request)"
    ),
    "CWE-601": (
        "EXPLANATION:\n"
        "Open Redirect — the application redirects users to an attacker-"
        "controlled URL, enabling phishing attacks.\n\n"
        "FIX:\n"
        "Never redirect to a URL taken directly from user input. Use a "
        "whitelist of allowed redirect destinations.\n\n"
        "EXAMPLE:\n"
        "ALLOWED = ['https://myapp.com/dashboard', 'https://myapp.com/home']\n"
        "if redirect_url not in ALLOWED:\n"
        "    redirect_url = '/'"
    ),
    "CWE-614": (
        "EXPLANATION:\n"
        "Sensitive cookie without the Secure flag — the cookie can be "
        "transmitted over HTTP and intercepted.\n\n"
        "FIX:\n"
        "Set Secure, HttpOnly, and SameSite=Strict on all session cookies.\n\n"
        "EXAMPLE:\n"
        "# FastAPI\n"
        "response.set_cookie('session', value, secure=True,\n"
        "                    httponly=True, samesite='strict')"
    ),
    "CWE-119": (
        "EXPLANATION:\n"
        "Buffer overflow — write beyond the bounds of an allocated buffer, "
        "enabling stack smashing, heap corruption, or arbitrary code execution.\n\n"
        "FIX:\n"
        "Compile with -fstack-protector-strong, -D_FORTIFY_SOURCE=2, "
        "and enable ASLR. Use safe string functions (strlcpy, snprintf) "
        "and validate all buffer lengths.\n\n"
        "EXAMPLE:\n"
        "// Before\n"
        "strcpy(buf, input);\n"
        "// After\n"
        "strlcpy(buf, input, sizeof(buf));"
    ),
    "CWE-121": (
        "EXPLANATION:\n"
        "Stack-based buffer overflow — writing past the end of a stack "
        "buffer can overwrite the return address and hijack execution.\n\n"
        "FIX:\n"
        "Enable stack canaries (-fstack-protector-strong), validate all "
        "input lengths before copying, and use safe string functions.\n\n"
        "EXAMPLE:\n"
        "// Before\n"
        "char buf[64]; strcpy(buf, argv[1]);\n"
        "// After\n"
        "char buf[64]; strlcpy(buf, argv[1], sizeof(buf));"
    ),
    "CWE-426": (
        "EXPLANATION:\n"
        "Untrusted Search Path (RPATH/RUNPATH) — the binary loads libraries "
        "from a directory that an attacker might control.\n\n"
        "FIX:\n"
        "Remove insecure RPATH entries at link time. Use system library "
        "paths only.\n\n"
        "EXAMPLE:\n"
        "# Remove RPATH with patchelf\n"
        "patchelf --remove-rpath ./binary"
    ),
    "CWE-506": (
        "EXPLANATION:\n"
        "Malicious code detected — the file contains a known malware "
        "signature and must be treated as compromised.\n\n"
        "FIX:\n"
        "Quarantine and delete the file immediately. Investigate how it "
        "entered the system. Scan all related files and systems. Rebuild "
        "from a clean, verified source.\n\n"
        "EXAMPLE:\n"
        "# Quarantine\n"
        "mv suspicious_file /quarantine/\n"
        "# Notify your security team immediately"
    ),
    "CWE-1035": (
        "EXPLANATION:\n"
        "Vulnerable third-party dependency — a package you depend on has "
        "a known CVE that could be exploited via your application.\n\n"
        "FIX:\n"
        "Upgrade the affected package to the patched version listed in "
        "the advisory. Pin versions in requirements.txt and run safety "
        "check in CI to catch future vulnerabilities early.\n\n"
        "EXAMPLE:\n"
        "pip install --upgrade <vulnerable-package>\n"
        "pip freeze > requirements.txt"
    ),
    "CWE-548": (
        "EXPLANATION:\n"
        "Directory listing is enabled — an attacker can enumerate all "
        "files in the directory, revealing sensitive content.\n\n"
        "FIX:\n"
        "Disable directory listing in your web server configuration.\n\n"
        "EXAMPLE:\n"
        "# nginx\n"
        "autoindex off;\n"
        "# Apache (.htaccess)\n"
        "Options -Indexes"
    ),
}


# ── Generic last-resort fallback ──────────────────────────────────────────────

GENERIC_FALLBACK = (
    "EXPLANATION:\n"
    "A security issue was detected by automated scanning. Review the "
    "description and location above for full details.\n\n"
    "FIX:\n"
    "1. Review the flagged code or configuration at the reported location.\n"
    "2. Apply the principle of least privilege — remove capabilities "
    "and permissions that are not required.\n"
    "3. Validate and sanitise all external input before use.\n"
    "4. Consult the CWE entry listed above for detailed guidance:\n"
    "   https://cwe.mitre.org/data/definitions/<ID>.html\n\n"
    "EXAMPLE:\n"
    "Refer to the OWASP Top 10 and the specific CWE entry for "
    "language-specific remediation examples."
)


def get_fallback(test_id: str = "", cwe: str = "") -> str:
    """
    Return the best static remediation available.

    Priority:
      1. Exact test_id match  (e.g. 'B605', 'W3101', 'WAF-MISSING')
      2. CWE match            (e.g. 'CWE-78', 'CWE-89')
      3. GENERIC_FALLBACK
    """
    if test_id and test_id in TEST_ID_REMEDIATIONS:
        return TEST_ID_REMEDIATIONS[test_id]

    if cwe:
        # Normalise: accept 'CWE-78', '78', 'cwe-78'
        cwe_key = cwe.upper()
        if not cwe_key.startswith("CWE-"):
            cwe_key = f"CWE-{cwe_key}"
        if cwe_key in CWE_REMEDIATIONS:
            return CWE_REMEDIATIONS[cwe_key]

    return GENERIC_FALLBACK