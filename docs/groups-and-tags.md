# Groups & Tags

Groups and tags are two complementary ways to organise your targets.

---

## Groups

A **group** is a named collection of targets. Each target belongs to at most one group. Good uses:

- **Environment** — Production, Staging, Development
- **Network zone** — DMZ, Internal, Cloud
- **Ownership** — Ops, Dev, Security

### Creating a Group

1. Go to **Groups** in the sidebar.
2. Click **Add Group**.
3. Enter a name, optional description, and pick a colour.
4. Click **Save**.

### Scanning an Entire Group

Each group card has a **Scan Group** button. You can also scope a scan from the Dashboard's **Run New Scan** modal by selecting "By group".

---

## Tags

A **tag** is a freeform label. A target can have **multiple tags**. Good uses:

| Tag | What it marks |
|-----|---------------|
| `web` | Has a web application |
| `external` | Internet-facing |
| `critical` | Business-critical |
| `database` | Runs a database |
| `mail` | Handles email |

### Creating a Tag

1. Go to **Tags** in the sidebar.
2. Click **Add Tag**, enter a name and colour.
3. Click **Save**.

Tags can also be created automatically when importing a YAML targets file.

---

## Example Structure

```
Production
  ├── www.example.com    [web, external, critical]
  ├── api.example.com    [web, external]
  └── mail.example.com   [mail, external]

Internal
  ├── db01.internal      [database, critical]
  └── 10.10.0.0/24       [internal, network]
```

---

## Related Pages

- [Managing Targets](targets.md)
- [Web GUI Guide](web-gui.md)
