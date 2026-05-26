# Lab: Standard File Permissions — `chmod` and the `ugo/rwx` Model

**Series:** linux-ops-mastery — RHCSA Permissions, Special Bits & ACLs
**Subjects covered:** POSIX permission triplets (user / group / other), read/write/execute bits, symbolic and octal `chmod`, `umask` effect on new files, interpreting `ls -l`, directories vs files (execute = traverse), permission math without a calculator
**Career arcs covered:** RHCSA (EX200 file permission objectives), RHCE (Ansible `file` module `mode:`), SRE (least-privilege incident response), DevOps (container image UID/GID and volume mount modes), AI/MLOps (securing model weights and dataset directories on shared clusters)
**Prerequisite:** Comfort with `ls`, `cd`, and basic shell navigation as root or with `sudo`
**Time Estimate:** 30 to 45 minutes
**Difficulty arc:** Task 1 baseline inspection · 2–3 symbolic and octal `chmod` core · 4 directory execute semantics · 5 `umask` and new-file behavior · 6 RHCSA-style capstone plus cleanup

---

## Objective

Build reflex-level skill with **standard POSIX permissions** — the `rwx` bits for **user**, **group**, and **other** on every file and directory. By the end of this lab you can read `ls -l` output like a table, set modes with both **symbolic** (`chmod u+x`) and **octal** (`chmod 750`) forms, and explain why a directory needs `x` before anyone can `cd` into it.

The capstone is an exam-style prompt: *"Create `/opt/appdata` owned by `root:appgrp`, mode `2770` is out of scope here — use `0770` instead: only owner and group may read/write/enter; others have no access. Place a proof file inside and verify a non-member cannot read it."* (You will use `0770` and group collaboration patterns from this lab; SGID is covered in Lab 43.)

> **Lab safety note:** All paths live under `/tmp` or a disposable lab directory. You will create test users only if your VM policy allows; otherwise run the "denied" checks from a second shell as a normal user vs root. Nothing here alters system-critical paths like `/etc/shadow`.

---

## Concept: Permissions Are Three Switches × Three Audiences

Every inode stores nine permission bits (plus special bits you will see in later labs). Think of them as a **3×3 matrix**: who (user / group / other) × what (read / write / execute).

```
   ┌────────────────────────────────────────────────────────────┐
   │  ls -l output:  -rwxr-x---  1 alice devops  ...  script.sh │
   │                 │││││││││                                 │
   │                 │└┴┴ user (u)  r w x                       │
   │                   └┴┴ group (g) r w x                      │
   │                     └┴┴ other (o) r w x                    │
   ├────────────────────────────────────────────────────────────┤
   │  first column char: file type (- file, d directory, l link) │
   └────────────────────────────────────────────────────────────┘

   Octal view of rwx:  r=4, w=2, x=1   (add per triplet)
     rwx = 4+2+1 = 7
     r-x = 4+0+1 = 5
     --- = 0
   So -rwxr-x---  ==  750
```

For **directories**, the same bits mean slightly different things: `r` lists names in the directory; `x` grants **search/traverse** (required to reach inodes inside); `w` allows creating/removing directory entries (names) subject to ownership rules.

> **Why this matters:** RHCSA and every security audit assume you can set **least privilege** without breaking applications. Mis-set directory `x` is one of the top reasons a service "cannot find" a file that is world-readable on disk. Octal mode strings like `0640` appear in systemd unit `UMask=`, Dockerfile `USER`, and Ansible `mode:` everywhere.

---

## 📜 Why `chmod` Exists — The Story

Early research Unix (late 1960s–1970s) treated the machine as a shared workshop: multiple researchers, one filesystem, no elaborate access-control lists on every file. The model that shipped was deliberately small: three **actors** (the file's owner, the file's group, everyone else) and three **capabilities** (read, write, execute) encoded in the inode.

The `chmod` system call (and the userland `chmod` command built on top of it) exists so administrators can flip those bits **atomically** without rewriting the file. Symbolic notation (`u+w`, `go-rwx`) grew up beside octal because humans reason about "take write away from others" faster than "what is 755 minus 002 again?" — but automation speaks octal fluently.

Modern Linux adds SELinux contexts, ACLs, capabilities, and namespaces — yet the **base mode** is still the first line of defense on every inode. Containers and orchestrators still map volume permissions back to this same 9-bit story. Learning `chmod` is not legacy trivia; it is the compression algorithm the entire ecosystem assumes you already know.

> **The point of the story:** Fancy policy engines still bottom out on `rwxrwxrwx`. If you can read and set the base mode cold, every other layer is easier to explain to auditors, developers, and interviewers.

---

## 👪 The chmod Family — Who Lives There

### Core permission commands

| Tool | Role |
|---|---|
| `chmod` | Change mode bits (this lab) |
| `chown` | Change owner (and optionally group) — Lab 41 |
| `chgrp` | Change group ownership — Lab 41 |
| `umask` | Shell mask applied when creating new files/dirs |
| `ls -l` / `ls -ld` | Human-readable permission display |
| `stat` | Precise numeric mode, owner, major/minor, etc. |
| `getfacl` / `setfacl` | POSIX ACLs — beyond base 9 bits |

### Symbolic vs octal mental map

| Form | Example | When to use it |
|---|---|---|
| Symbolic | `chmod u+x,g-w,o=` | Surgical edits; scripts that toggle one bit |
| Octal | `chmod 750 file` | Known target modes; Ansible `mode: '0750'` |
| Recursive | `chmod -R g+rX dir` | Tree-wide fixes (use carefully) |

> **The point of the family tree:** `chmod` answers "what can happen to this inode's bytes and names?" `chown`/`chgrp` answer "whose rules apply?" Combine them on every RHCSA permission task.

---

## 🔬 The Anatomy of `ls -l` — In One Diagram

```
$ ls -l /tmp/demo.txt
-rw-r----- 1 root wheel 12 May 26 10:00 /tmp/demo.txt
│││││││││  │ │    │     │            │              │
│││││││││  │ │    │     └─ size then mtime then path
│││││││││  │ └────┴─ owning group name (wheel)
│││││││││  └─ owning user (root)
││││││││└─ alternate access method indicator (`.` SELinux, `+` ACL)
│││││││└─ other: no permissions in this example (--- would appear here)
││││││└─ group: r--
│││││└─ user: rw-
││││└─ file type (- regular file; d directory; l symlink)
││└─ write bit for user
│└─ read bit for user
└─ leading type char (not a permission bit on the triplet)
```

> **Reading rule:** Always identify **file type** first, then **user triplet**, then **group**, then **other**. For directories, re-read the triplets with "list / write-entries / traverse" semantics.

---

## 📚 chmod / Permission Reference Table

| Task | Command | Notes |
|---|---|---|
| Show permissions | `ls -l FILE` | Symlinks: `ls -l` shows link; `ls -lL` follows |
| Show directory itself | `ls -ld DIR` | Without `-d`, `ls` lists contents |
| Set mode octally | `chmod 0640 FILE` | Leading 0 = sticky/SUID/SGID prefix slot |
| Add user execute | `chmod u+x FILE` | Symbolic |
| Deny other everything | `chmod o-rwx FILE` | Symbolic |
| Set equal triplets | `chmod a=r FILE` | `a` = all (ugo) |
| Copy user bits to group | `chmod g=u FILE` | Handy template pattern |
| Recursive | `chmod -R MODE DIR` | Dangerous on `/`; fine in `/tmp` lab trees |
| Default for new files | `umask` | Subtracted from `0666` files / `0777` dirs (common shell rule) |
| Precise metadata | `stat -c '%a %U %G %n' FILE` | Octal mode, owner, group, name |

> **Rule one of chmod:** Changing bits on a symlink with GNU `chmod` usually affects the **target** unless `-h` is used — know your platform; on RHCSA practice VMs, operate on real files first.

---

## 🎯 Career Pathway Sidebar

| Level | Why this lab matters |
|---|---|
| **RHCSA candidate** | EX200 repeatedly asks you to normalize permissions on files, scripts, and directories under `/opt`, `/var`, or home directories. Octal and symbolic `chmod` are first-class skills. |
| **RHCE candidate** | Ansible `ansible.builtin.file` and `copy` modules take `mode:` as octal strings — same mental model as the shell. |
| **SRE / Platform** | Incidents often begin with "the service user cannot read its config" — always check ownership **and** mode, not just path existence. |
| **DevOps** | CI images set `USER` non-root; bind mounts inherit host UID/GID/mode — mismatched triplets break pods in subtle ways. |
| **AI / MLOps** | Shared dataset folders on NFS or parallel filesystems still expose POSIX modes; training jobs fail with `Permission denied` when group `x` on a parent dir is missing. |

---

## 🔧 The 6 Tasks

> Six phases that build **inspect → set → verify → explain directories → umask → capstone** muscle memory.

---

### Task 1 — Sandbox and inspect baseline permissions

**Purpose:** Create a lab tree under `/tmp`, add a few files with default umask, and practice reading `ls -l` and `stat` output before changing anything.

```bash
sudo -i
mkdir -p /tmp/chmod-lab/{docs,bin}
cd /tmp/chmod-lab

echo "public readme" > docs/README.txt
echo '#!/bin/bash' > bin/tool.sh
echo 'echo hello' >> bin/tool.sh

ls -l docs/README.txt bin/tool.sh
stat -c '%a %A %U %G %n' docs/README.txt bin/tool.sh
```

**Human-Readable Breakdown:** Become root (RHCSA systems often expect root for permission drills), create two files — a plain text file and a tiny shell script — then display classic and numeric permission views.

**Reading it left to right:** `mkdir -p` creates nested directories. `echo ... >` creates files with default permissions governed by `umask` (commonly `0022` → files `0644`). `ls -l` shows symbolic triplets; `stat -c '%a %A ...'` prints octal mode (`%a`), human symbols (`%A`), owner, group, and path.

**The story:** You cannot set what you cannot read. Task 1 exists so your eyes parse `rw-r--r--` as "644" instantly before you start flipping bits.

**Expected output:**

```text
-rw-r--r--. 1 root root 14 May 26 10:01 docs/README.txt
-rw-r--r--. 1 root root 27 May 26 10:01 bin/tool.sh

644 -rw-r--r-- root root docs/README.txt
644 -rw-r--r-- root root bin/tool.sh
```

**Switches**

| Token | Meaning |
|---|---|
| `mkdir -p` | Create parents; no error if exists |
| `ls -l` | Long listing with permissions |
| `stat -c FORMAT` | Print metadata using a format string |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| `Permission denied` on `/tmp/chmod-lab` | Use `sudo -i` or `sudo mkdir` |
| Modes differ from 644 | Check `umask` with `umask -S`; still valid for the lab |
| `stat: command not found` | Install `coreutils` (extremely rare on RHEL) |

---

### Task 2 — Core operation A: symbolic chmod

**Purpose:** Grant execute to the file owner for `bin/tool.sh`, remove read from "other," and verify with `ls` and a test run.

```bash
cd /tmp/chmod-lab

chmod u+x bin/tool.sh
chmod o-r bin/tool.sh

ls -l bin/tool.sh
./bin/tool.sh
```

**Human-Readable Breakdown:** Use symbolic `chmod` to add user execute and strip other read. Run the script without a separate `bash` invocation to prove the execute bit matters.

**Reading it left to right:** `chmod u+x` adds the execute bit for the user triplet only. `chmod o-r` removes read from other only. `./bin/tool.sh` requires execute (+ read for scripts) on the file.

**The story:** Symbolic edits are how you express intent in English fragments: "user gains execute," "group loses write." They are harder to typo than large octal numbers when you only need one bit.

**Expected output:**

```text
-rwxr-xr-x. 1 root root 27 May 26 10:05 bin/tool.sh
hello
```

**Switches**

| Token | Meaning |
|---|---|
| `u+x` | User: add execute |
| `o-r` | Other: remove read |
| `./path` | Execute file if execute bit set and filesystem not `noexec` |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| `Permission denied` running `./bin/tool.sh` | Missing `u+x`; or mounted with `noexec` — move lab dir |
| Script runs with `bash tool.sh` but not `./tool.sh` | Execute bit still missing — `chmod u+x` |
| Group lost access unexpectedly | You used `a-r` instead of `o-r` — re-audit command |

---

### Task 3 — Core operation B: octal chmod

**Purpose:** Force a known-good mode using octal notation — the RHCSA and Ansible default style.

```bash
cd /tmp/chmod-lab

chmod 640 docs/README.txt
ls -l docs/README.txt
stat -c '%a' docs/README.txt
```

**Human-Readable Breakdown:** Set `README.txt` to `640` → user read/write, group read only, other nothing.

**Reading it left to right:** `chmod 640` supplies one octal digit per triplet: `6=rw-`, `4=r--`, `0=---`. `stat -c '%a'` prints `640` for quick exams.

**The story:** Octal is compact. When an exam item says "mode 640," symbolic `chmod` works, but octal is faster and matches `sshd_config` comments, tmpfiles snippets, and automation.

**Expected output:**

```text
-rw-r-----. 1 root root 14 May 26 10:07 docs/README.txt
640
```

**Switches**

| Token | Meaning |
|---|---|
| `640` | `rw-` / `r--` / `---` |
| `stat -c '%a'` | Print octal permission bits only |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Mode shows `0640` vs `640` in stat | Same value — leading zero is display |
| Still group-writable | You typed `660` — re-run with intended digits |
| Operation not permitted | File is immutable (Lab 44) or read-only FS |

---

### Task 4 — Directories: why `x` matters for `cd`

**Purpose:** Demonstrate that read without execute on a directory allows `ls` but not traverse, and that adding `x` fixes access to nested files.

```bash
cd /tmp/chmod-lab

install -m 600 -T /dev/null docs/secret.dat
echo classified > docs/secret.dat

chmod 644 docs
ls -ld docs

sudo -u nobody cat docs/secret.dat 2>&1 | head -n 2

chmod 711 docs
sudo -u nobody cat docs/secret.dat 2>&1 | head -n 2
```

**Human-Readable Breakdown:** Create a file inside `docs/`, open the directory wide for listing but remove execute for "other," then try access as `nobody`. Add execute for other (`1` in last triplet) and retry.

**Reading it left to right:** `chmod 644` on a directory gives `rw-` to owner and `r--` to group/other — other can read directory **names** but cannot traverse without `x`. `chmod 711` gives owner full `rwx` and others `x` only — enough to reach known file names.

**The story:** This is the lecture every junior skips until NFS mysteriously breaks. **Directory execute is the gate** to any inode inside.

**Expected output:**

```text
drw-r--r--. 2 root root 4096 May 26 10:10 docs
cat: docs/secret.dat: Permission denied
classified
```

**Switches**

| Token | Meaning |
|---|---|
| `chmod 644 DIR` | Dangerous pattern if you forget dir semantics |
| `sudo -u nobody CMD` | Run as unprivileged `nobody` user |
| `chmod 711 DIR` | Owner rwx; group/other only x |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| `nobody` cannot run `sudo` | Enable `sudoers` rule or use a second normal user account |
| Still denied after `711` | Check parent directories (`/tmp`, `/tmp/chmod-lab`) for `x` |
| `ls` fails but `cat` works | Unusual — re-check path; you may be root |

---

### Task 5 — Edge case: umask and predictable new files

**Purpose:** Observe how `umask` subtracts from default creation modes, then set a stricter umask for a subshell session.

```bash
cd /tmp/chmod-lab

umask -S
umask
touch umask-default.txt
stat -c '%a' umask-default.txt

( umask 077; touch umask-strict.txt; stat -c '%a' umask-strict.txt )
stat -c '%a' umask-default.txt
```

**Human-Readable Breakdown:** Print symbolic and numeric umask, create a file with the default mask, then create another file inside a subshell with `umask 077` so only the owner has any permission.

**Reading it left to right:** `umask` with no arguments prints the numeric mask (bits **cleared** from `0666` for files). Subshell `( umask 077; touch ... )` limits the stricter setting to one compound command.

**The story:** Shared development boxes with `umask 0002` create group-writable files by default — fine for some teams, wrong for secrets. Know how to tighten a session before extracting tarballs or generating keys.

**Expected output:**

```text
u=rwx,g=rx,o=rx
0022
644
600
644
```

**Switches**

| Token | Meaning |
|---|---|
| `umask -S` | Symbolic summary |
| `( umask 077; touch f )` | Subshell — temporary umask |
| `umask 077` | Owner-only default for new files (typical) |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| File is `666` minus umask shows `644` but you expected `600` | Remember directories use `0777` baseline; files use `0666` |
| umask resets | Expected — global umask lives in `/etc/profile` or shell rc |

---

### Task 6 — Capstone: collaborative directory + cleanup

**Task statement:** *"Create group `appgrp` if your policy allows (otherwise reuse an existing secondary group). Create `/tmp/chmod-lab/appdrop` owned by `root:appgrp` with mode `2770` deferred — use `0770` here: owner and group full access including traverse; other none. Add a file `INVENTORY.txt` readable/writable by group. Verify permissions with `ls -ld` and `stat`."*

**Purpose:** Combine ownership mindset (you will use `chgrp` / `chown` minimally here) with strict base modes, then tear the lab tree down.

```bash
sudo -i
cd /tmp/chmod-lab

groupadd -f appgrp 2>/dev/null || true
mkdir -p appdrop
chgrp appgrp appdrop
chmod 0770 appdrop
echo "widget A" > appdrop/INVENTORY.txt
chgrp appgrp appdrop/INVENTORY.txt
chmod 0660 appdrop/INVENTORY.txt

ls -ld appdrop
ls -l appdrop/INVENTORY.txt
stat -c '%a %U %G %n' appdrop appdrop/INVENTORY.txt
```

**Human-Readable Breakdown:** Ensure a group exists, point both directory and file at that group, set directory `770` and file `660` so collaborators in `appgrp` share write access without opening the file to world.

**Reading it left to right:** `chgrp` sets owning group; `chmod 0770` directory gives `rwx` to owner and group; file `660` is the usual companion for shared editable documents.

**The story:** This is the daily-work pattern behind "put us both in `devgrp` and `chmod 770` the sprint folder." SGID on directories (auto-inherit group) is Lab 43 — here you set group explicitly once.

**Expected output:**

```text
drwxrwx---. 2 root appgrp 4096 May 26 10:20 appdrop
-rw-rw----. 1 root appgrp 11 May 26 10:20 appdrop/INVENTORY.txt
770 root appgrp appdrop
660 root appgrp appdrop/INVENTORY.txt
```

**Cleanup**

```bash
sudo -i
groupdel appgrp 2>/dev/null || true
rm -rf /tmp/chmod-lab
exit
```

**Switches**

| Token | Meaning |
|---|---|
| `groupadd -f` | Create group if missing; ignore if exists |
| `chgrp GROUP PATH` | Set group ownership |
| `chmod 0770 DIR` | `rwxrwx---` |
| `chmod 0660 FILE` | `rw-rw----` |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| `groupadd: command not found` | Use `dnf install libgroupmgmt` / consult admin policy; skip group and use `wheel` for practice |
| File still `root root` | Re-run `chgrp` on the file after creation |
| Others can still read | You used `0775` or `0644` — reapply correct octal |

---

## 🔍 chmod Decision Guide

```
Need to change permissions?
  │
  ├── "I know the final octal string"
  │       └── chmod 0750 path
  │
  ├── "I want to tweak one bit for one audience"
  │       └── chmod u+x / go-w / o=  style
  │
  ├── "It is a tree under a lab directory"
  │       └── chmod -R ...   (double-check path first)
  │
  ├── "Users cannot cd into a directory"
  │       └── add user/group/other x on every path component
  │
  ├── "Default for NEW files wrong"
  │       └── adjust umask or deployment uploader
  │
  └── "Base modes are not enough (per-user exceptions)"
          └── ACLs (future lab) / SELinux contexts
```

---

## ✅ Lab Checklist (6 Tasks)

- [ ] 01 Create `/tmp/chmod-lab` and capture baseline `ls -l` / `stat`
- [ ] 02 Apply symbolic `chmod` to add `u+x` and remove `o-r` on a script
- [ ] 03 Set `640` with octal `chmod` on a documentation file
- [ ] 04 Prove directory `x` is required for `cat path/file` as non-owner
- [ ] 05 Show default vs `umask 077` file creation modes
- [ ] 06 Build shared `0770` / `0660` group directory and cleanup

---

## ⚠️ Common Pitfalls

| Mistake | Symptom | Fix |
|---|---|---|
| `chmod -R 777 /` typo | Catastrophic world-writable tree | Never run recursive chmod from `/`; use absolute lab paths |
| Confused directory `r` vs `x` | `ls` works, access fails | Add `x` for whichever actor must traverse |
| Used `chmod +x` blindly | Added execute for all | Prefer `u+x` or explicit octal |
| Set file `600` but group needs read | Peers cannot read | Pair file group with directory group + `g+r` or `660` |
| Forgot `chgrp` after `mkdir` | Group still primary group of user | `chgrp -R` carefully on lab dir |
| Symlink surprise | `chmod` touched target | Use `chmod -h` when available or operate on target directly |
| SELinux denial despite `777` | AVC denied | `ls -Z` and `audit2why` (separate topic) |

---

## 🎯 Career & Interview Strategy

**RHCSA candidate**
- Practice writing **both** `chmod u+s` style (later lab) and `chmod 4755` style here. Examiners accept either when the prompt is numeric.

**RHCE candidate**
- Translate each `chmod` you would type into `mode: '0750'` in playbooks; keep leading zeros in YAML strings to avoid octal-as-decimal bugs.

**SRE / Platform interview**
- Be ready to whiteboard **why** `chmod 644` on a directory broke CI artifact downloads — emphasize directory execute.

**DevOps**
- Document required POSIX modes beside volume mount instructions; pods running as arbitrary UIDs may need `o+rX` or ACL fixes.

**AI / MLOps**
- Dataset staging directories on shared storage: always set **group sticky workflow** (Lab 43) **and** sane `umask` for batch users.

---

## 🔗 Related Labs

| Lab | Connection |
|---|---|
| Lab 41 — Changing Ownership | Pair `chmod` with `chown`/`chgrp` for complete permission stories |
| Lab 43 — SGID and Sticky Bit | Directory inheritance and shared drop-box semantics |
| Lab 44 — Immutable Attribute | When even `chmod` cannot change bits until `chattr -i` |
| Lab 02 — stderr redirection | Silence noisy permission denied during recursive finds |

---

## 👤 Author

**Kelvin R. Tobias**
[kelvinintech.com](https://kelvinintech.com) · [GitHub](https://github.com/kelvintechnical) · [LinkedIn](https://www.linkedin.com/in/kelvin-r-tobias-211949219)
