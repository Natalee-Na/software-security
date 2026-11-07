# Worksheet 13 — Cloud & Container Security (4 hrs)

> **Course:** Software Security (KOSEN69) · Week 13
> **Aligned to:** OWASP 2025 **A02 Security Misconfiguration** · **CWE-732** (incorrect permission assignment), **CWE-16** (configuration), plus CWE-798, CWE-250, CWE-538, CWE-269, CWE-1104
> **Signature game:** 🔍 *Misconfig Hunt* (CloudGoat-style) — each misconfig you find **and** fix = a flag.

> ⚠️ **Ethics note:** All artifacts here are deliberately broken for teaching and are marked *"Sandbox/teaching only; for authorized lab use."* Scan, exploit, and harden **only** these lab files (or systems you own / are authorized to test). Never point Trivy or these techniques at third-party cloud accounts or images without written permission.

---

## Part 1 — Student Information

| Name | Student ID | Date | Group |
|------|-----------|------|-------|
| Nararat Kritphet | 6631503110 | 5/11/2026 |       |

---

## Part 2 — Lecture Questions

Answer in your own words (2–4 sentences each).

1. Explain the **shared-responsibility model**. In `harden.md` it says "the cloud provider secures *of* the cloud; you secure what you put *in* it." Give one concrete example of each side for an S3-backed app.
2. `iam-policy-insecure.json` uses `"Action": "*"` and `"Resource": "*"`. Describe **why this violates least privilege** and map it to CWE-732 vs CWE-269 — what is the difference between the two CWEs here?
3. The insecure Dockerfile bakes `ENV API_TOKEN=sk_live_...`. Explain how an attacker recovers that secret from a shipped image (name the `docker` commands) and why this is **CWE-798 / CWE-200**.
4. Why is `FROM python:latest` (CWE-1104/CWE-16) a security and reproducibility problem, and how does pinning to an `@sha256:` digest fix it?
5. What does a **distroless** base image remove (relative to `python:3.11-slim`), and how does that shrink the attack surface for an RCE or container-escape attacker?

---

## Part 3 — Hands-on Lab (180 min)

**Learning goals:** find cloud/container misconfigurations with Trivy, map each to a CWE, and rebuild the IAM policy + Dockerfile to least privilege / hardened so the findings drop.

**Prerequisites:** Docker installed and running; the `week13-cloud-container/` lab folder; internet access to pull `aquasec/trivy:latest`.

### Environment setup (real commands)

```bash
cd labs/week13-cloud-container

# Option A — the provided wrapper (trivy config over the Dockerfiles; IAM JSON is reviewed manually, see Task 2):
bash scan.sh

# Option B — run Trivy directly (MEDIUM is in the filter on purpose: one of the
# three rules Task 1 asks you to cite is rated MEDIUM, and HIGH,CRITICAL hides it):
docker run --rm -v "$PWD:/src" aquasec/trivy:latest config --severity MEDIUM,HIGH,CRITICAL /src

# (Optional) build + CVE-scan the hardened image:
docker build -f Dockerfile.hardened -t week13-hardened:lab .
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --severity HIGH,CRITICAL week13-hardened:lab
```

**What to submit per task:** the command(s) you ran + the relevant output (finding count or the specific finding line), a screenshot of the Trivy/terminal result, and a 2–3 sentence mitigation explaining *why* the fix reduces risk (cite the CWE).

![The same app shipped as two stacked container images, Dockerfile.insecure beside Dockerfile.hardened, with each layer paired to its fix and its CWE, and only the unpinned :latest tag, the root user and the ENV secret marked as things trivy config actually flags.](img/container-hardening.svg)

### Tasks

- **Task 0 — Onboarding (15 min).** Confirm Docker works (`docker version`), run `bash scan.sh`, and record the **baseline finding count** against `Dockerfile.insecure` (Trivy's `config` scanner does not parse standalone IAM policy JSON, so `iam-policy-insecure.json` is reviewed manually instead — see Task 2). **Deliverable:** screenshot of the baseline scan.

- **Task 1 — Misconfig Hunt: container image (40 min).** *Goal:* find every defect in `Dockerfile.insecure`. *Steps:* read each `# DEFECT:` comment, then locate the matching Trivy finding where one exists — only 3 of the 6 (unpinned `:latest`, runs as root, secrets in `ENV`) map to a Trivy config rule (`DS-0001`, `DS-0002`, `DS-0031`); `COPY . .`, `chmod -R 777`, and unpinned `pip install` are instruction-level RUN/COPY semantics Trivy's Dockerfile scanner doesn't check, so identify those 3 by code review instead. Build a table: defect → CWE → Trivy rule/severity (write "manual review — no Trivy rule" where none exists). *Deliverable:* completed table (6 rows) using the IDs from `harden.md`.

#	Defect	CWE	Trivy Rule / Severity
1	FROM python:latest — uses an unpinned, mutable image tag.	CWE-1104 / CWE-16	DS-0001 / MEDIUM
2	ENV API_TOKEN=... — hard-coded secret stored in the image.	CWE-798 / CWE-200 / CWE-16	DS-0031 / CRITICAL
3	COPY . . — copies the entire build context, including potentially sensitive files.	CWE-538	Manual review — no Trivy rule
4	RUN chmod -R 777 /app — grants everyone read, write, and execute permissions.	CWE-732	Manual review — no Trivy rule
5	No USER directive — container runs as root by default.	CWE-250	DS-0002 / HIGH
6	RUN pip install -r requirements.txt — installs unpinned dependencies.	CWE-1104	Manual review — no Trivy rule

- **Task 2 — Misconfig Hunt: IAM (30 min).** *Goal:* document why `iam-policy-insecure.json` is full-admin. *Steps:* identify the `Action:*` / `Resource:*` / no-`Condition` problems; map to CWE-269 / CWE-732. *Deliverable:* 3-row table + one sentence on the blast radius if these creds leak.

#	Misconfiguration	CWE	Explanation
7	"Action": "*"	CWE-269	Allows all AWS actions instead of limiting permissions to required operations.
8	"Resource": "*"	CWE-732	Grants access to every resource instead of restricting access to specific S3 buckets and objects.
9	No Condition	CWE-732	Does not restrict access based on conditions such as S3 prefixes, source IP, or MFA.

Blast radius:

If these credentials are leaked, an attacker could perform unauthorized actions across AWS services and access, modify, or delete resources throughout the account.

- **Task 3 — Secrets & storage (25 min).** *Goal:* show secrets must not live in the image. *Steps:* explain how `ENV API_TOKEN` / `AWS_SECRET_ACCESS_KEY` are exposed via `docker history`; propose where they belong instead (secrets manager / mounted secret / orchestrator secret per `harden.md`). *Deliverable:* 2–3 sentence remediation + the `.dockerignore` entries you would add to stop `COPY . .` leaking `.git`/`.env` (CWE-538).

1. Evidence / Security Risk
The `docker history --no-trunc` command revealed both `API_TOKEN` and `AWS_SECRET_ACCESS_KEY` in the Docker image build history. The `docker inspect` command also confirmed that these secrets were stored in the image's `Config.Env` metadata. Anyone with access to the image could recover these sensitive credentials without running the container. This is a security risk related to CWE-798 and CWE-200.
2. RemediationSecrets should never be stored in Dockerfile ENV instructions because they can be exposed through `docker history` and `docker inspect`. Instead, secrets should be injected at runtime using a secrets manager, mounted secret files, or orchestrator secrets. A `.dockerignore` file should also exclude sensitive files such as `.env` and `.git` to prevent accidental inclusion in the build context (CWE-538).
3. .dockerignore Entries
.git
.gitignore
.env
.env.*
!.env.example
*.pem
*.key
*.crt
secrets/

- **Task 4 — Hardened-Dockerfile + least-priv-IAM defense (50 min).** *Goal:* prove the "after" is clean. *Steps:* (a) re-run `bash scan.sh` (or `trivy config`) against `Dockerfile.hardened` and capture the **reduced** finding count (Trivy's config scanner does not parse standalone IAM JSON, so confirm the IAM fix manually per Task 2 by diffing `iam-policy-leastpriv.json` against the insecure policy); (b) for the Dockerfile, point to the fix for each Task-1 defect (digest pin, multi-stage venv, distroless runtime, `USER 65532:65532`, no secrets in `ENV`, copy only `app.py`); (c) for IAM, confirm the rewrite scopes `s3:GetObject` to `arn:aws:s3:::lab-app-bucket/app/*` and adds the `s3:prefix` `Condition`; (d) list the extra runtime flags from `harden.md` (`--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`). *Deliverable:* before/after finding counts, the defect→fix mapping, and the diffed policy/Dockerfile with one sentence per fix.

# Task 4 — Hardened Dockerfile + Least-Privilege IAM Defense

## 1. Before / After Scan Results

Trivy config scan was performed using the same severity levels (MEDIUM, HIGH, CRITICAL) for both Dockerfiles.

| Dockerfile | Findings |
|---|---:|
| Dockerfile.insecure (Before) | 4 |
| Dockerfile.hardened (After) | 0 |

The findings decreased from 4 to 0, representing a 100% reduction in the selected Trivy misconfiguration findings.

Before: MEDIUM 1, HIGH 1, CRITICAL 2.

After: No misconfiguration findings detected.

## 2. Dockerfile Defect → Fix Mapping

1. **Unpinned base image:** Replaced `python:latest` with a Python image pinned by SHA256 digest to ensure reproducible builds and prevent unexpected image changes.
2. **Secrets in ENV:** Removed hard-coded secrets from the Dockerfile and moved secret injection to runtime using a secrets manager, mounted secret files, or orchestrator secrets.
3. **COPY . .:** Replaced the instruction with `COPY app.py .` and copied only the required application files to prevent accidental exposure of sensitive files (CWE-538).
4. **chmod -R 777 /app:** Removed insecure world-writable permissions and used default permissions with a non-root runtime user to reduce unauthorized file modification.
5. **Running as root:** Added `USER 65532:65532` to run the application as a non-root user and reduce the impact of container compromise.
6. **Unpinned pip dependencies:** Used a dedicated build stage and installed dependencies into a virtual environment. Dependencies are listed in `requirements.txt`; version pinning and hashes should be maintained there for reproducible installation.

The hardened Dockerfile also uses a multi-stage build and a distroless runtime image to reduce the final image size and attack surface.

## 3. IAM Policy Comparison

The insecure policy used `"Action": "*"` and `"Resource": "*"`, granting excessive permissions.

The least-privilege policy makes the following changes:

- Replaced wildcard actions with `s3:GetObject` for reading application objects.
- Restricted the object resource to `arn:aws:s3:::lab-app-bucket/app/*`.
- Added a separate `s3:ListBucket` statement restricted to the `lab-app-bucket` resource.
- Added a `Condition` using `StringLike` and `s3:prefix` with `app/*` to limit bucket listing to the application prefix.

These changes follow the principle of least privilege by granting only the required actions on the required resources under specific conditions.

## 4. Extra Runtime Hardening

The following Docker runtime flags are recommended:

- `--read-only`: Prevents writing to the container filesystem.
- `--cap-drop ALL`: Removes all Linux capabilities.
- `--security-opt no-new-privileges`: Prevents processes from gaining additional privileges.

Additional protections include resource limits such as `--memory` and `--pids-limit` to reduce the risk of denial-of-service attacks.

**Conclusion:** The hardened Dockerfile reduced Trivy findings from 4 to 0. The Dockerfile and IAM policy changes reduce the attack surface, prevent credential exposure, and enforce least-privilege access.

- **Task 5 — Flag tally (20 min).** *Goal:* score the hunt. *Steps:* one flag per misconfig found **and** fixed (6 container + 3 IAM = 9). *Deliverable:* flag count + the single biggest-risk misconfig and why.

# Task 5 — Flag Tally

## 1. Flag Count

- Container misconfigurations found and fixed: 6 flags.
- IAM misconfigurations found and fixed: 3 flags.
- **Total: 9 flags.**

## 2. Biggest-Risk Misconfiguration

The biggest-risk misconfiguration is hard-coded secrets stored in Dockerfile ENV instructions, especially `AWS_SECRET_ACCESS_KEY` and `API_TOKEN`.

These secrets can be exposed through `docker history` and `docker inspect`, allowing anyone with access to the Docker image to recover sensitive credentials. An attacker could use the exposed credentials to access unauthorized resources or services, potentially causing data breaches and financial damage.

The issue was fixed by removing secrets from the Dockerfile and injecting them securely at runtime using a secrets manager, mounted secret files, or orchestrator secrets.

---

## Part 4 — Reflection

1. **Mapping.** For three findings, write the line of the artifact → CWE → OWASP 2025 A02, and the one-line fix.

Finding 1: Hard-coded secrets

Artifact: Dockerfile.insecure — ENV API_TOKEN=... and ENV AWS_SECRET_ACCESS_KEY=...

CWE: CWE-798 (Use of Hard-coded Credentials) / CWE-200 (Exposure of Sensitive Information)

OWASP 2025: A02 – Security Misconfiguration

Fix: Remove secrets from Dockerfile ENV instructions and inject them securely at runtime using a secrets manager or mounted secret files.

Finding 2: Insecure file permissions

Artifact: Dockerfile.insecure — RUN chmod -R 777 /app

CWE: CWE-732 (Incorrect Permission Assignment for Critical Resource)

OWASP 2025: A02 – Security Misconfiguration

Fix: Remove world-writable permissions and use appropriate default file permissions with a non-root user.

Finding 3: Over-permissive IAM policy

Artifact: iam-policy-insecure.json — "Action": "*" and "Resource": "*"

CWE: CWE-269 (Improper Privilege Management) / CWE-732 (Incorrect Permission Assignment)

OWASP 2025: A02 – Security Misconfiguration

Fix: Replace wildcard permissions with specific actions and resource ARNs, and add conditions such as s3:prefix.

2. **Real incident.** Briefly describe a real breach caused by a cloud/container misconfiguration (e.g., a public S3 bucket leak, or an over-permissive IAM role). What single control from this lab would have prevented it?

The 2019 Capital One data breach is an example of a cloud security incident involving misconfiguration and excessive permissions.

An attacker exploited a Server-Side Request Forgery (SSRF) vulnerability to obtain credentials associated with an AWS IAM role. The attacker then used those credentials to access data stored in Amazon S3.

The single control from this lab that could have reduced the impact was Least-Privilege IAM. Restricting the IAM role to only the necessary actions and specific resources could have limited the attacker's access to sensitive data.

3. **Best mitigation.** Of everything you did, which control gives the most risk reduction per unit of effort, and why? Argue for least-privilege IAM vs. distroless+non-root.

I believe Least-Privilege IAM provides the greatest risk reduction per unit of effort in this lab.

It limits what an attacker can access even if credentials are compromised. Restricting actions, resources, and conditions helps reduce the potential damage across cloud services.

Distroless images and non-root users are also important because they reduce the container attack surface and limit privileges if an application is compromised. However, Least-Privilege IAM provides broader protection against unauthorized access to cloud resources.

Therefore, I would prioritize Least-Privilege IAM while still applying distroless images and non-root execution as additional defense-in-depth controls.
---

## Grading rubric (100)

| Component | Points | What earns full marks |
|-----------|:------:|-----------------------|
| Part 2 — Lecture questions | 20 | All 5 answered correctly with CWE/A02 reasoning |
| Part 3 — Tasks + evidence | 40 | Tasks 0–5 complete; commands, outputs, and screenshots present |
| Defense (Task 4 hardening) | 25 | Hardened Dockerfile + least-priv IAM shown to reduce findings; per-fix justification |
| Part 4 — Reflection | 15 | Accurate mapping, relevant incident, well-argued best mitigation |

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
- **Personalized flag (if this lab issues one):** ____________________
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?
  2. **Why does your fix actually stop it** — and what could still break it?

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.
2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).
3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*
