---
sidebar_position: 4
title: Run the server on its own
---

# Run the server part on its own

A team that has no central product, and no Themis.NET, can run the server part of AI.Sentinel itself. It is a set of extensions in `AI.Sentinel.AspNetCore` that you add to a plain ASP.NET Core app. The app reads policy from a folder, signs a profile per repository, lets a team lead pause and release sessions, lets an approver approve and deny, and keeps a signed audit log of those actions.

**Every new setting on this page is optional and off by default. Without them AI.Sentinel behaves exactly as before: the hooks, the proxy and the dashboard do not change, and nothing is registered or mapped until your host calls the extensions below.**

A working host is in [`samples/AI.Sentinel.ServerSample`](https://github.com/MarcelRoozekrans/AI.Sentinel/tree/main/samples/AI.Sentinel.ServerSample). The test `StandaloneServerSampleTests` hosts it in-process and drives approve, deny, pause, release and the audit export over its HTTP API. The code below is from it.

## What runs where

| Part | Where | Does |
|---|---|---|
| Server host | your ASP.NET Core app | Serves profiles, session control, the dashboard and the audit export |
| Policy folder | a folder on the server, filled from git | The only source of policy and node configuration. No endpoint accepts either |
| Identity provider | yours: Keycloak, Entra ID or any OIDC provider with the device authorization grant | Signs developers in and puts their groups in the token |
| Plugin | each developer's PC: `sentinel-hook` or `sentinel-copilot-hook` | Signs in, holds the signed profile, applies pauses |

Three other pieces of the server part are separate items and have their own pages once they are merged: the event endpoints that receive events from developer machines, the approval store that takes requests over HTTP, and the per-team visibility of the dashboard. This page does not rely on them. Approvals reach the dashboard through whatever `IApprovalStore` the host registers; the sample uses `InMemoryApprovalStore`.

## 1. Host the server in an ASP.NET Core app

Reference `AI.Sentinel` and `AI.Sentinel.AspNetCore`, plus the JWT bearer package for the sign-in:

```xml
<ItemGroup>
  <PackageReference Include="AI.Sentinel" Version="*" />
  <PackageReference Include="AI.Sentinel.AspNetCore" Version="*" />
  <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="10.0.15" />
</ItemGroup>
```

Pin real versions in your project. Then register and map:

```csharp
var builder = WebApplication.CreateBuilder(args);
var signingKey = builder.Configuration["Sentinel:SigningKey"]!;   // section 2
var policyPath = builder.Configuration["Sentinel:PolicyPath"]!;   // section 3

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.Authority = builder.Configuration["Oidc:Authority"];     // section 4
        o.Audience = builder.Configuration["Oidc:Audience"];
        o.MapInboundClaims = false;                                 // keep "sub" and "groups" as they are
        o.TokenValidationParameters.NameClaimType = "sub";
    });
builder.Services.AddAuthorization(o =>
{
    o.AddPolicy("AISentinelDeveloper", p => p.RequireAuthenticatedUser());
    o.AddPolicy("AISentinelAdminAudit", p => p.RequireAuthenticatedUser());
});

builder.Services.AddAISentinel();
builder.Services.AddSentinelApprovalStore(_ => new InMemoryApprovalStore());
builder.Services.AddAISentinelAdminAudit(o =>
{
    o.SigningKey = signingKey;
    o.Organisation = "acme";
});
builder.Services.AddAISentinelPolicyFolder(o =>
{
    o.Path = policyPath;
    o.SigningKey = signingKey;
    o.PreviousSigningKey = builder.Configuration["Sentinel:PreviousSigningKey"];
    o.OpaPath = builder.Configuration["Sentinel:OpaPath"];
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapAISentinel("/ai-sentinel").RequireAuthorization();   // dashboard with approve and deny
app.MapAISentinelPolicyServer();                             // profile-keys, profile, node-map
app.MapAISentinelSessionControl();                           // pause, release, list, events
app.MapAISentinelAdminAudit();                               // audit export
app.Run();
```

- `AddAISentinelPolicyFolder` needs `AddAISentinelAdminAudit`: a publish and a rejected publish are written to that log. `MapAISentinelSessionControl` needs both.
- The two policy names are the defaults of `PolicyFolderOptions.PolicyName` and `AdminAuditOptions.PolicyName`. The host defines them, and the organisation is passed as the resource. `RequireAuthenticatedUser` is enough when your provider only issues tokens for your organisation; add a claim requirement when it serves several. What a user may do then comes from the role bindings in section 5.
- The host runs `opa` in a child process to compile policy. Put the `opa` executable on the `PATH` of the image, or set `Sentinel:OpaPath`.
- **The dashboard and its approve and deny accept any user your authorization lets in.** `RequireAuthorization()` with a policy of your own, for example one that needs a group claim, limits who approves. Approve and deny without a signed-in user return `401`.
- Pauses and the audit log are kept in memory, so they end when the server restarts. Export the audit log on a schedule (section 8).

## 2. The signing key from the deployment

The server signs profiles and audit exports with one Ed25519 key. The setting is the base64 of a 32 byte seed. It reaches the server through the deployment at startup. It is never stored by AI.Sentinel and never fetched.

```bash
openssl rand -base64 32        # make the seed once; keep it in your secret store
```

Hand it to the process as an environment variable, which ASP.NET Core maps to `Sentinel:SigningKey`:

```yaml
env:
  - name: Sentinel__SigningKey
    valueFrom:
      secretKeyRef: { name: ai-sentinel-signing-key, key: seed }
```

Do not put it in `appsettings.json` or in the image. The sample throws at startup when it is missing, and the policy folder registration throws when the key is first needed.

**Rotation.** Set the new seed as `Sentinel:SigningKey` and the old one as `Sentinel:PreviousSigningKey`. Profiles then carry the endorsement of the old key for the new one, so a plugin that pinned the old key accepts the new one. The audit export is signed with the current key only, so verify an older export with the key that was current when it was made: `sentinel audit-verify` takes `--public-key` more than once.

**The public key.** A signed-in developer gets the key to pin from `GET /.well-known/ai-sentinel/profile-keys`, which answers `{"organisation": "...", "keys": ["<base64 Ed25519 public key>"]}`. Take the same value for `sentinel audit-verify`.

## 3. A policy folder kept in sync with git

Policy and node configuration only ever come from the folder. Keep the repository that holds them under branch protection and review as for any code, and let a sidecar keep a checkout of the protected branch in the folder. With [git-sync](https://github.com/kubernetes/git-sync) in Kubernetes:

```yaml
containers:
  - name: git-sync
    image: registry.k8s.io/git-sync/git-sync:v4.4.0   # use a current release
    env:
      - { name: GITSYNC_REPO, value: "https://git.example.com/acme/sentinel-policy.git" }
      - { name: GITSYNC_REF, value: "main" }
      - { name: GITSYNC_ROOT, value: "/policy" }
      - { name: GITSYNC_LINK, value: "current" }
      - { name: GITSYNC_PERIOD, value: "30s" }
    volumeMounts: [{ name: policy, mountPath: /policy }]
  - name: ai-sentinel
    image: registry.example.com/acme/ai-sentinel-server:1
    env:
      - { name: Sentinel__PolicyPath, value: "/policy/current" }
    volumeMounts: [{ name: policy, mountPath: /policy, readOnly: true }]
volumes:
  - { name: policy, emptyDir: {} }
```

- **The swap has to be atomic.** git-sync checks out each version in its own folder and moves the `current` link to it in one step. The server resolves the real path once, reads every file into memory, compiles from that copy, reads the files again and publishes only when both reads are equal. On any difference it publishes nothing and tries again with backoff. A plain `git pull` into the folder is not atomic and is not safe to use.
- **A link swap raises no file event**, so the server also looks at the folder every `PolicyFolderOptions.PollInterval`, 30 seconds by default, and waits `SettleDelay`, half a second, for changes to settle.
- **Put `nodes.json` and the Rego bundles at the root of the repository**, so that the link itself is the folder you give the server. Files and folders that start with a dot, such as `.git`, are not read. A link inside the folder refuses the folder.
- **A bad commit does not take the server down.** A configuration that fails validation is not published, the last good one stays in force, and a `rejected_publish` entry is written to the audit log. Each published version writes a `publish` entry.

The layout of the folder, `nodes.json` and the Rego rules are described under [Policy folder and signed profiles](./claude-code#policy-folder-and-signed-profiles-server-part).

## 4. Sign-in with your identity provider

The plugin signs a developer in with the OIDC device authorization grant (RFC 8628), so the provider must support it. The server validates the access token the plugin sends as a bearer token.

At the provider:

1. Create a **public client** for the plugin, with the device authorization grant enabled and no client secret. Its id is `SENTINEL_HOOK_OIDC_CLIENT_ID` below.
2. Allow the `offline_access` scope, so the plugin gets a refresh token. A provider that issues none still works: the developer signs in again when the access token expires.
3. Make the **access token** carry the `sub` claim, an audience that is the one the server expects, and a **`groups` claim** that lists the groups of the user. Keycloak does this with a group membership mapper with the token claim name `groups` and the full group path switched off. Microsoft Entra ID does it with the groups optional claim on the access token, which gives group object ids. Check the documentation of your provider; the names must match what `nodes.json` binds.

At the server, `Oidc:Authority` is the issuer address and `Oidc:Audience` the audience. With `MapInboundClaims = false` the developer is the `sub` claim and the groups are the `groups` claim, which `PolicyFolderOptions.DeveloperClaim` and `PolicyFolderOptions.GroupsClaim` rename. A provider can send one claim per group or one claim holding a JSON array.

## 5. Group-to-role bindings

The `roles` list in `nodes.json` binds groups to roles on nodes:

```json
{
  "organisation": "acme",
  "nodes": [
    {"id": "acme", "kind": "organisation", "settings": {"fail_mode": "closed"}},
    {"id": "team-a", "kind": "team"}
  ],
  "repositories": {"github.com/acme/widgets": "team-a"},
  "roles": [
    {"group": "security", "role": "administrator", "node": "acme"},
    {"group": "team-a-leads", "role": "team_lead", "node": "team-a"}
  ]
}
```

An administrator holds the role on every node, a team lead on their team, and everyone else is a developer. Only an administrator, or a team lead of the node that owns the repository, can pause and release a session of it. The audit export needs the administrator role. The bindings are read from the configuration that is current at each check, so a change in git changes who may do what, with no restart. See [Roles on nodes](./claude-code#roles-on-nodes).

## 6. The plugin on each PC

The plugin needs the address of the server and of the provider. Set these where the developer's shell, or the tool that starts Claude Code, can see them:

| Variable | Value |
|---|---|
| `SENTINEL_HOOK_SERVER_URL` | The address of your server. https, or http on loopback |
| `SENTINEL_HOOK_OIDC_ISSUER` | The identity provider. Its `/.well-known/openid-configuration` must name a device authorization endpoint and a token endpoint, both https |
| `SENTINEL_HOOK_OIDC_CLIENT_ID` | The public client of step 4 |
| `SENTINEL_HOOK_OIDC_SCOPE` | Optional. Defaults to `openid offline_access` |
| `SENTINEL_HOOK_RESIDENT` | `on`. The process that holds the tokens, the pause state and the profiles needs it |

Then sign in once per PC:

```bash
sentinel-hook --sign-in          # or sentinel-copilot-hook --sign-in
```

The command prints an address and a code. The developer opens the address, enters the code and signs in at the provider. The command pins the server's public keys, stores the refresh token in the OS keychain and hands the tokens to the resident process. From then on the process keeps a connection to `GET /ai-sentinel/sessions/events`, fetches the signed profile of each repository, and applies a pause or a release within a second.

Without these variables the plugin does not sign in and does not open a connection, and nothing changes. See [Sign-in](./claude-code#sign-in) and [Server connection](./claude-code#server-connection-pause-and-profiles) for the details, and [Fail mode](./claude-code#fail-mode) for what the hook does when no decision can be made.

## 7. Approve, deny, pause and release

Approve and deny go through the dashboard of the host, at `/ai-sentinel`, or its two endpoints:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" https://sentinel.example.com/ai-sentinel/api/approvals/$ID/approve
curl -X POST -H "Authorization: Bearer $TOKEN" -d "reason=not needed" https://sentinel.example.com/ai-sentinel/api/approvals/$ID/deny
```

Pause and release are on the session control endpoints, for a repository on a node you lead:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"repository": "github.com/acme/widgets", "reason": "check the last commands"}' \
  https://sentinel.example.com/ai-sentinel/sessions/$SESSION/pause

curl -X POST -H "Authorization: Bearer $TOKEN" https://sentinel.example.com/ai-sentinel/sessions/$SESSION/release   # 204
curl -H "Authorization: Bearer $TOKEN" https://sentinel.example.com/ai-sentinel/sessions                              # pauses in force
```

`until` in the pause body is optional and ends the pause by itself. A pause names a session, never a person. Each approve, deny, pause and release is written to the admin audit log with the channel `web`; a pause is recorded before it takes effect.

## 8. Export the audit log and verify it offline

An administrator exports the log of the organisation:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://sentinel.example.com/ai-sentinel/admin-audit/acme/export > export.json
```

The export ends with a head that the deployment key signed: entry count, last hash, export time and organisation. Verify it on any machine, with only the public key:

```bash
sentinel audit-verify export.json --organisation acme --public-key <base64 public key>
```

The command checks the chain, the signed head, and the organisation. It prints the signed count, last hash and export time. Pass them back as `--checkpoint-count`, `--checkpoint-hash` and `--checkpoint-time` on the next run, and an export that is older than the checkpoint, or does not contain it, is rejected, so cutting off the newest entries is found. Exit codes: `0` verified, `1` usage error or unreadable file, `2` verification failed.

The log is in memory in this version, so export it on a schedule, keep the files, and keep the last checkpoint with them. A restart of the server starts a new, empty log, and an export of it cannot pass the checkpoint of the log before. Export before you restart, archive that export with its checkpoint, and verify the new log without a checkpoint at first. From then on keep one checkpoint per log lifetime and pass only the one of the current log.

## Checklist

- [ ] The host calls `AddAISentinelAdminAudit`, `AddAISentinelPolicyFolder`, and maps the policy server, the session control and the audit export.
- [ ] The signing key is a secret of the deployment, not a file in the image or the repository.
- [ ] The policy folder is a git-sync link of a protected branch, with `nodes.json` at its root.
- [ ] The provider has a public device-code client, and the access token carries `sub`, the audience and `groups`.
- [ ] `nodes.json` binds an administrator group and the team lead groups.
- [ ] Each PC has the three server and provider variables, `SENTINEL_HOOK_RESIDENT=on`, and has run `--sign-in`.
