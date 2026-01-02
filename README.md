![alt text](dbcake.png)
# dbcake

**dbcake** is single-file, easy-to-use key/value database and secrets client with list/tuple and support for learning!!!, quick prototypes, and small projects and more!...

`dbcake.py` is a self-contained Python module that provides:

- Local key/value store in a single append-only `.dbce` file (centralized) **or** per-key files (decentralized)
- Built-in **list and tuple management** with intuitive operations
- Multiple on-disk formats: `binary`, `bits01`, `dec`, `hex`
- Encryption modes: `low | normal | high`. Uses AES-GCM (via `cryptography`) when available; otherwise a secure stdlib fallback
- Key rotation, file-locking for multi-process safety, compaction, export, preview, and per-key operations
- A small HTTP secrets client (`Client` / `AsyncClient`) for talking to a remote secrets API (optional)
- CLI for DB + secrets client and a tiny Tkinter GUI installer for optional packages
- Single-file distribution — `dbcake.py` — drop into a project and import or call from command line

---

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Basic Usage (Python API)](#basic-usage-python-api)
- [List & Tuple Operations](#list--tuple-operations)
- [Storage Formats & Modes](#storage-formats--modes)
- [Encryption, Passphrases & Key Rotation](#encryption-passphrases--key-rotation)
- [CLI Usage](#cli-usage)
- [Secrets HTTP Client](#secrets-http-client)
- [Examples](#examples)
- [Security Notes](#security-notes)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

1. Save `dbcake.py` into your project folder.

2. Use the module-level `db` object or create your own database instance:

```python
import dbcake

# Simple use (module-level default DB file: data.dbce)
dbcake.db.set("username", "armin")
print(dbcake.db.get("username"))   # -> "armin"

# Create/open a custom DB file
mydb = dbcake.open_db("project.dbce", store_format="binary", dataset="centerilized")
mydb.set("score", 100)
print(mydb.get("score"))
```

## Installation

dbcake.py is a single-file module — no installation required beyond having Python.

**Optional (recommended) packages:**

- `cryptography` — provides AES-GCM & Fernet support (stronger, standard crypto)
- `tkinter` — required only if you want to run the graphical installer

### Install cryptography:
```bash
python -m pip install cryptography
```

### Run the GUI installer (uses tkinter) to install optional packages:
```bash
python dbcake.py --installer
```

## Basic Usage (Python API)

### Module-level convenience DB
```python
import dbcake

# Default DB (data.dbce)
dbcake.db.set("a", 123)
print(dbcake.db.get("a"))           # -> 123

# Change file & format
dbcake.db.title("mydata.dbce", store_format="binary")
dbcake.db.set("user", {"name": "alice"})
print(dbcake.db.get("user"))

# Switch to decentralized per-key files
dbcake.db.decentralized()
dbcake.db.set("session", {"id": 1})

# List keys
print(dbcake.db.keys())

# Preview a few entries
print(dbcake.db.preview(limit=5))
dbcake.db.pretty_print_preview(limit=5)  # Prints nice table
```

### Factory style (explicit DB object)
```python
mydb = dbcake.open_db("project.dbce", store_format="hex", dataset="centerilized")
mydb.set("k", "v")
v = mydb.get("k")
```

## List & Tuple Operations

### List Management
dbcake provides special list operations that feel like native Python lists:

```python
import dbcake

# Set a list with multiple values
dbcake.db.list['users'] = ['armin', 'ali']
# or: dbcake.db.set('users', ['armin', 'ali'])

# Append to list
dbcake.db.list.append('users', 'mahsa')  # Now: ['armin', 'ali', 'mahsa']

# Remove from list
dbcake.db.list.remove('users', 'armin')  # Now: ['ali', 'mahsa']

# Get list
users = dbcake.db.list['users']  # Returns: ['ali', 'mahsa']
print(users)  # ['ali', 'mahsa']

# Extend list with multiple items
dbcake.db.list.extend('users', ['sara', 'reza'])  # Now: ['ali', 'mahsa', 'sara', 'reza']

# Insert at specific position
dbcake.db.list.insert('users', 0, 'first')  # Now: ['first', 'ali', 'mahsa', 'sara', 'reza']

# Pop from list (removes and returns last item)
last_user = dbcake.db.list.pop('users')  # Returns: 'reza'

# Clear all items from list
dbcake.db.list.clear('users')  # Now: []

# Check if key exists and is a list/tuple
if 'users' in dbcake.db.list:
    print("Users is a list")

# Get with default value
users = dbcake.db.list.get('users', default=['default_user'])
```

### Tuple Management
For immutable sequences, use tuple operations:

```python
import dbcake

# Set a tuple
dbcake.db.tuple['coordinates'] = (10, 20, 30)
# or: dbcake.db.set('coordinates', (10, 20, 30))

# Get tuple
coords = dbcake.db.tuple['coordinates']  # Returns: (10, 20, 30)

# Count occurrences of a value
count = dbcake.db.tuple.count('coordinates', 10)  # Returns: 1

# Find index of a value
index = dbcake.db.tuple.index('coordinates', 20)  # Returns: 1

# Check if key exists and is a tuple
if 'coordinates' in dbcake.db.tuple:
    print("Coordinates is a tuple")

# Get with default value
coords = dbcake.db.tuple.get('coordinates', default=(0, 0, 0))
```

### Mixed Usage Example
```python
import dbcake

# Store different data types
dbcake.db.set('name', 'Armin')                # String
dbcake.db.set('age', 25)                      # Integer
dbcake.db.set('scores', [95, 88, 92])         # List
dbcake.db.set('location', (35.6895, 51.3890)) # Tuple
dbcake.db.set('config', {'theme': 'dark', 'notifications': True})  # Dict

# Access them appropriately
name = dbcake.db.get('name')                  # String
age = dbcake.db.get('age')                    # Integer
scores = dbcake.db.list['scores']             # List
location = dbcake.db.tuple['location']        # Tuple
config = dbcake.db.get('config')              # Dict

# Modify lists
dbcake.db.list.append('scores', 87)           # Add new score
dbcake.db.list.remove('scores', 88)           # Remove score 88
```

## Storage Formats & Modes

### `store_format` options when creating or switching DB:
- `binary` — raw bytes (fast)
- `bits01` — ASCII '0' / '1' bit string
- `dec` — decimal digits grouped by 3 per byte
- `hex` — hex representation

Switch format programmatically:
```python
dbcake.db.set_format("hex")
```

### Switch dataset mode:
```python
dbcake.db.centerilized()   # centralized append-only .dbce
dbcake.db.decentralized()  # per-key files in .d directory
```

## Encryption, Passphrases & Key Rotation

`db.encryption_level` controls on-disk security:
- `db.encryption_level = "low"` — minimal (fast)
- `db.encryption_level = "normal"` — default (no re-encryption)
- `db.encryption_level = "high"` — records encrypted before writing (AES-GCM if cryptography is installed; otherwise a fallback)

### Set passphrase (derive key from passphrase):
```python
dbcake.db.encryption_level = "high"
dbcake.db.set_passphrase("my secret passphrase")
dbcake.db.set("secret", "value")
```

Generate/store keyfile (if you do not use passphrase) — DB will generate `.key` next to the DB file.

### Rotate keys (re-encrypt everything):
**CLI (interactive):**
```bash
python dbcake.py db rotate-key mydata.dbce --interactive
```

**Programmatic:**
```python
dbcake.db.set_passphrase("old")
dbcake.db.rotate_key(new_passphrase="new")
```

`rotate_key` rewrites the DB and re-encrypts records under the new key.

## CLI Usage

The single file exposes a CLI for both local DB, list operations, and the secrets client.

### Local DB commands
```bash
# Create file
python dbcake.py db create mydata.dbce --format binary

# Set key
python dbcake.py db set mydata.dbce username '"armin"'

# Get key
python dbcake.py db get mydata.dbce username

# List keys
python dbcake.py db keys mydata.dbce

# Preview
python dbcake.py db preview mydata.dbce --limit 5

# Compact (rewrite to keep only current items)
python dbcake.py db compact mydata.dbce

# Set passphrase (interactive)
python dbcake.py db set-passphrase mydata.dbce --interactive

# Rotate key (interactive)
python dbcake.py db rotate-key mydata.dbce --interactive

# Reveal DB file in OS file manager
python dbcake.py db reveal mydata.dbce
```

CLI values attempt JSON parsing; unparseable input will be stored as raw string.

### List operations (CLI)
```bash
# Get list
python dbcake.py list get mydata.dbce usernames

# Append to list
python dbcake.py list append mydata.dbce usernames '"new_user"'

# Remove from list
python dbcake.py list remove mydata.dbce usernames '"armin"'

# Clear list
python dbcake.py list clear mydata.dbce usernames
```

### Secrets HTTP client (CLI)
```bash
# Set secret
python dbcake.py secret set myname "value" --url https://secrets.example.com --api-key S3CR

# Get secret (reveal)
python dbcake.py secret get myname --reveal --url https://secrets.example.com --api-key S3CR

# List
python dbcake.py secret list --url https://secrets.example.com --api-key S3CR

# Delete
python dbcake.py secret delete myname --url https://secrets.example.com --api-key S3CR
```

## Secrets HTTP Client (Python)

```python
from dbcake import Client

client = Client("https://secrets.example.com", api_key="S3CR")
meta = client.set("db_token", "S3cR3tV@lue", tags=["prod","db"])
secret = client.get("db_token", reveal=True)
print(secret.value)

# With Fernet (encrypt locally before send)
from cryptography.fernet import Fernet
fkey = Fernet.generate_key().decode()
client2 = Client("https://secrets.example.com", api_key="S3", fernet_key=fkey)
client2.set("encrypted", "very-secret")
s = client2.get("encrypted", reveal=True)
print(s.value)
```

`AsyncClient` is available for async code (`AsyncClient.from_env()` to read env vars).

**Env vars for convenience:**
- `DBCAKE_URL`
- `DBCAKE_API_KEY`
- `DBCAKE_FERNET_KEY`

## Examples

### Complete Example: User Management System
```python
import dbcake

# Initialize database
db = dbcake.open_db("users.dbce")

# Store user profiles
db.set("user:1", {"name": "Armin", "email": "armin@example.com", "age": 25})
db.set("user:2", {"name": "Ali", "email": "ali@example.com", "age": 30})

# Store user roles as a list
db.list['roles:1'] = ['admin', 'editor']
db.list.append('roles:1', 'viewer')

# Store user permissions as a tuple (immutable)
db.tuple['permissions:1'] = ('read', 'write', 'delete')

# Store all user IDs in a list
db.list['all_users'] = [1, 2]

# Query users over 25
user_ids = db.list['all_users']
for user_id in user_ids:
    user = db.get(f"user:{user_id}")
    if user and user.get('age', 0) > 25:
        print(f"User over 25: {user['name']}")

# Remove a role
db.list.remove('roles:1', 'viewer')

# Get user's permissions
perms = db.tuple['permissions:1']
print(f"Permissions: {perms}")

# Add a new user
db.list.append('all_users', 3)
db.set("user:3", {"name": "Mahsa", "email": "mahsa@example.com", "age": 28})
```

### Example: Todo List Application
```python
import dbcake

db = dbcake.open_db("todos.dbce")

# Initialize todos list
db.list['todos'] = [
    {"id": 1, "task": "Learn Python", "done": True},
    {"id": 2, "task": "Build a project", "done": False}
]

# Add new todo
db.list.append('todos', {"id": 3, "task": "Learn dbcake", "done": False})

# Mark todo as done
todos = db.list['todos']
for i, todo in enumerate(todos):
    if todo['task'] == "Build a project":
        todo['done'] = True
        db.list['todos'] = todos  # Update the list
        break

# Remove completed todos
todos = [todo for todo in db.list['todos'] if not todo['done']]
db.list['todos'] = todos

# Get active todos
active_todos = db.list['todos']
print(f"Active todos: {len(active_todos)}")
```

## Security Notes

1. **Passphrase Security**:
   - If you use `db.set_passphrase("...")`, a salt file (`.salt`) is created and used to derive an encryption key
   - Keep passphrases secret and never commit them to version control

2. **Keyfile Security**:
   - If you don't set a passphrase, the DB generates a `.key` keyfile next to the DB
   - Keep that file safe and never commit it to version control
   - Consider using `.gitignore` to exclude `*.key` and `*.salt` files

3. **Network Security**:
   - Use TLS for server communication (HTTPS) and protect API keys
   - Never transmit sensitive data over unencrypted connections

4. **Key Rotation**:
   - Use `rotate_key` regularly for long-lived data
   - Consider rotating keys when team members leave or credentials are compromised

5. **Use Cases**:
   - This project is intended for learning, quick prototypes, and small projects
   - For production secrets management, consider hardened solutions (HashiCorp Vault, AWS KMS/Secrets Manager, etc.)

## Troubleshooting

### Common Issues:

1. **`cryptography` not installed**:
   - AES-GCM and Fernet features disabled
   - Library will use a secure fallback
   - Install cryptography: `pip install cryptography`

2. **`tkinter` missing**:
   - GUI installer will not run
   - Install system package:
     - Ubuntu/Debian: `sudo apt-get install python3-tk`
     - macOS: Comes with Python from python.org
     - Windows: Usually installed with Python

3. **Lock timeouts**:
   - Another process may hold the DB
   - Wait or increase timeout
   - Ensure only compatible writers access the DB

4. **Permission errors**:
   - Ensure the process can write to DB folder and key/salt files
   - Check file permissions and ownership

5. **List operations not working**:
   - Ensure you're using `db.list` for list operations, not `db.get/set` directly
   - Lists stored with `db.set()` can be accessed with `db.list[]`

### Debug Mode:
To see what's happening internally, you can enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

---

## License & Contribution

dbcake is released as open-source software. Feel free to use, modify, and distribute as needed.

For issues, feature requests, or contributions, please refer to the project repository.

---

**Happy coding with dbcake!** 🍰
>[!CAUTION]
