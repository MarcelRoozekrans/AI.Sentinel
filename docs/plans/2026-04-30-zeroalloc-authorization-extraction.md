# ZeroAlloc.Authorization Extraction — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (or superpowers:subagent-driven-development for same-session execution) to implement this plan task-by-task.

**Goal:** Extract `ISecurityContext` / `IAuthorizationPolicy` / `[Authorize]` / `[AuthorizationPolicy]` / `AnonymousSecurityContext` from AI.Sentinel into a new standalone NuGet package `ZeroAlloc.Authorization` 1.0.0, then migrate AI.Sentinel 1.4.1 → 1.5.0 to consume it via type-forwarders so existing downstream consumers see no breakage.

**Architecture:** Two-repo move with a strict release ordering. Build the new package in `C:\Projects\Prive\ZeroAlloc\ZeroAlloc.Authorization\` first, ship it to nuget.org, then bump AI.Sentinel to `<PackageReference>` it and add `[TypeForwardedTo]` redirects so the old `AI.Sentinel.Authorization.X` names continue to resolve at the metadata level. Async overload (`ValueTask<bool> IsAuthorizedAsync`) bundled into v1 with default-interface-method fallback so existing sync impls keep working.

**Tech Stack:** .NET 8 / 9 / 10 multi-target, xUnit, conventional commits, release-please, GitVersion, NuGet.

**Design doc:** [`docs/plans/2026-04-30-zeroalloc-authorization-extraction-design.md`](2026-04-30-zeroalloc-authorization-extraction-design.md). Read that first if anything below is unclear.

---

## Phase 1 — Build ZeroAlloc.Authorization 1.0 in the ZeroAlloc monorepo

All Phase 1 work happens in `C:\Projects\Prive\ZeroAlloc\` on a new branch in that repo. Pattern is `ZeroAlloc.Inject` — single-package, no sub-projects.

### Task 1.1: Scaffold the repo dir

**Files:**
- Create: `C:\Projects\Prive\ZeroAlloc\ZeroAlloc.Authorization\ZeroAlloc.Authorization.slnx`
- Create: `C:\Projects\Prive\ZeroAlloc\ZeroAlloc.Authorization\Directory.Build.props`
- Create: `C:\Projects\Prive\ZeroAlloc\ZeroAlloc.Authorization\GitVersion.yml`
- Create: `C:\Projects\Prive\ZeroAlloc\ZeroAlloc.Authorization\global.json`
- Create: `C:\Projects\Prive\ZeroAlloc\ZeroAlloc.Authorization\LICENSE` (copy from sibling, MIT)
- Create: `C:\Projects\Prive\ZeroAlloc\ZeroAlloc.Authorization\.gitignore`
- Create: `C:\Projects\Prive\ZeroAlloc\ZeroAlloc.Authorization\src\ZeroAlloc.Authorization\ZeroAlloc.Authorization.csproj`
- Create: `C:\Projects\Prive\ZeroAlloc\ZeroAlloc.Authorization\tests\ZeroAlloc.Authorization.Tests\ZeroAlloc.Authorization.Tests.csproj`
- Create: `C:\Projects\Prive\ZeroAlloc\ZeroAlloc.Authorization\assets\` (copy `icon.png` from `ZeroAlloc.Inject\assets\` if it exists; otherwise leave empty for now)

**Step 1: Create dir + branch**

```bash
cd C:/Projects/Prive/ZeroAlloc
mkdir -p ZeroAlloc.Authorization/src/ZeroAlloc.Authorization
mkdir -p ZeroAlloc.Authorization/tests/ZeroAlloc.Authorization.Tests
mkdir -p ZeroAlloc.Authorization/assets
cd ZeroAlloc.Authorization
git init -b main
```

If the parent `ZeroAlloc` is not a git repo (it's a workspace, each subproject is its own repo), you'll create a fresh repo here and link it to `https://github.com/ZeroAlloc-Net/ZeroAlloc.Authorization` in Phase 3. Skip `git init` if the parent IS a single git repo (in that case just stay on the existing branching workflow).

**Step 2: `Directory.Build.props`** — clone `ZeroAlloc.Inject\Directory.Build.props` and adapt:

```xml
<Project>
  <PropertyGroup>
    <Version>1.0.0</Version>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <LangVersion>latest</LangVersion>
    <Authors>Marcel Roozekrans</Authors>
    <Company>Marcel Roozekrans</Company>
    <PackageLicenseExpression>MIT</PackageLicenseExpression>
    <PackageProjectUrl>https://github.com/ZeroAlloc-Net/ZeroAlloc.Authorization</PackageProjectUrl>
    <RepositoryUrl>https://github.com/ZeroAlloc-Net/ZeroAlloc.Authorization</RepositoryUrl>
    <RepositoryType>git</RepositoryType>
    <Description>Authorization primitives for .NET — ISecurityContext, IAuthorizationPolicy, [Authorize] / [AuthorizationPolicy] attributes. Shared by AI.Sentinel and ZeroAlloc.Mediator.Authorization.</Description>
    <PackageTags>authorization;security;policy;dotnet;zeroalloc</PackageTags>
    <PackageReadmeFile>README.md</PackageReadmeFile>
    <PackageIcon>icon.png</PackageIcon>
    <Copyright>Copyright (c) Marcel Roozekrans</Copyright>
  </PropertyGroup>
  <ItemGroup Condition="'$(IsPackable)' != 'false'">
    <None Include="$(MSBuildThisFileDirectory)README.md" Pack="true" PackagePath="\" />
    <None Include="$(MSBuildThisFileDirectory)assets\icon.png" Pack="true" PackagePath="\" Condition="Exists('$(MSBuildThisFileDirectory)assets\icon.png')" />
  </ItemGroup>
  <ItemGroup>
    <PackageReference Include="Meziantou.Analyzer" Version="3.0.23">
      <PrivateAssets>all</PrivateAssets>
      <IncludeAssets>runtime; build; native; contentfiles; analyzers</IncludeAssets>
    </PackageReference>
    <PackageReference Include="Roslynator.Analyzers" Version="4.15.0">
      <PrivateAssets>all</PrivateAssets>
      <IncludeAssets>runtime; build; native; contentfiles; analyzers</IncludeAssets>
    </PackageReference>
    <PackageReference Include="ErrorProne.NET.CoreAnalyzers" Version="0.1.2">
      <PrivateAssets>all</PrivateAssets>
      <IncludeAssets>runtime; build; native; contentfiles; analyzers</IncludeAssets>
    </PackageReference>
    <PackageReference Include="ZeroAlloc.Analyzers" Version="1.3.1">
      <PrivateAssets>all</PrivateAssets>
      <IncludeAssets>runtime; build; native; contentfiles; analyzers</IncludeAssets>
    </PackageReference>
  </ItemGroup>
</Project>
```

**Step 3: `global.json`** — copy verbatim from `ZeroAlloc.Inject\global.json`:

```json
{ "sdk": { "version": "10.0.202", "rollForward": "latestMinor" } }
```

**Step 4: `GitVersion.yml`** — copy verbatim from `ZeroAlloc.Inject\GitVersion.yml`.

**Step 5: `ZeroAlloc.Authorization.slnx`**:

```xml
<Solution>
  <Project Path="src/ZeroAlloc.Authorization/ZeroAlloc.Authorization.csproj" />
  <Project Path="tests/ZeroAlloc.Authorization.Tests/ZeroAlloc.Authorization.Tests.csproj" />
</Solution>
```

**Step 6: `src/ZeroAlloc.Authorization/ZeroAlloc.Authorization.csproj`**:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFrameworks>net8.0;net9.0;net10.0</TargetFrameworks>
    <RootNamespace>ZeroAlloc.Authorization</RootNamespace>
    <PackageId>ZeroAlloc.Authorization</PackageId>
  </PropertyGroup>
</Project>
```

**Step 7: `tests/ZeroAlloc.Authorization.Tests/ZeroAlloc.Authorization.Tests.csproj`**:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <RootNamespace>ZeroAlloc.Authorization.Tests</RootNamespace>
    <IsPackable>false</IsPackable>
    <NoWarn>$(NoWarn);MA0074;NU1608;NU1701</NoWarn>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="18.*" />
    <PackageReference Include="xunit" Version="2.*" />
    <PackageReference Include="xunit.runner.visualstudio" Version="2.*" />
  </ItemGroup>
  <ItemGroup>
    <Using Include="Xunit" />
  </ItemGroup>
  <ItemGroup>
    <ProjectReference Include="..\..\src\ZeroAlloc.Authorization\ZeroAlloc.Authorization.csproj" />
  </ItemGroup>
</Project>
```

**Step 8: `.gitignore`** — copy from `ZeroAlloc.Inject\.gitignore`.

**Step 9: Verify the empty solution restores**

Run from `C:\Projects\Prive\ZeroAlloc\ZeroAlloc.Authorization\`:

```bash
dotnet restore ZeroAlloc.Authorization.slnx
```

Expected: 0 errors, packages download. Build will fail (no source yet) — that's expected.

**Step 10: Commit**

```bash
git add .
git commit -m "chore: scaffold ZeroAlloc.Authorization repo from ZeroAlloc.Inject template"
```

---

### Task 1.2: `ISecurityContext` + `AnonymousSecurityContext` (test-first)

**Files:**
- Create: `tests/ZeroAlloc.Authorization.Tests/AnonymousSecurityContextTests.cs`
- Create: `src/ZeroAlloc.Authorization/ISecurityContext.cs`
- Create: `src/ZeroAlloc.Authorization/AnonymousSecurityContext.cs`

**Step 1: Write the failing tests**

`tests/ZeroAlloc.Authorization.Tests/AnonymousSecurityContextTests.cs`:

```csharp
using ZeroAlloc.Authorization;

namespace ZeroAlloc.Authorization.Tests;

public class AnonymousSecurityContextTests
{
    [Fact]
    public void Instance_Singleton_HasAnonymousId()
    {
        Assert.Equal("anonymous", AnonymousSecurityContext.Instance.Id);
    }

    [Fact]
    public void Instance_Singleton_HasEmptyRoles()
    {
        Assert.Empty(AnonymousSecurityContext.Instance.Roles);
    }

    [Fact]
    public void Instance_Singleton_HasEmptyClaims()
    {
        Assert.Empty(AnonymousSecurityContext.Instance.Claims);
    }

    [Fact]
    public void Instance_Singleton_ReturnsSameReference()
    {
        Assert.Same(AnonymousSecurityContext.Instance, AnonymousSecurityContext.Instance);
    }
}
```

**Step 2: Run tests — verify they fail**

```bash
dotnet test ZeroAlloc.Authorization.slnx
```

Expected: build error — `ISecurityContext` and `AnonymousSecurityContext` don't exist.

**Step 3: Implement `ISecurityContext.cs`**

`src/ZeroAlloc.Authorization/ISecurityContext.cs`:

```csharp
namespace ZeroAlloc.Authorization;

/// <summary>Caller identity for authorization decisions. Hosts downcast to richer
/// subinterfaces (e.g. tool-call context, request context) inside the policy body.</summary>
public interface ISecurityContext
{
    /// <summary>Stable caller identifier — user, agent, or service name.</summary>
    string Id { get; }

    /// <summary>Role membership of the caller. Empty for anonymous callers.</summary>
    IReadOnlySet<string> Roles { get; }

    /// <summary>Optional claims (tenant, scope, sub, etc.). Empty by default.</summary>
    IReadOnlyDictionary<string, string> Claims { get; }
}
```

**Step 4: Implement `AnonymousSecurityContext.cs`**

`src/ZeroAlloc.Authorization/AnonymousSecurityContext.cs`:

```csharp
using System.Collections.Frozen;

namespace ZeroAlloc.Authorization;

/// <summary>Singleton anonymous caller — no roles, no claims. Default when no
/// caller-provider is configured.</summary>
public sealed class AnonymousSecurityContext : ISecurityContext
{
    /// <summary>Shared singleton instance used whenever no caller identity is configured.</summary>
    public static readonly AnonymousSecurityContext Instance = new();

    private AnonymousSecurityContext() { }

    /// <inheritdoc />
    public string Id => "anonymous";

    /// <inheritdoc />
    public IReadOnlySet<string> Roles { get; } = FrozenSet<string>.Empty;

    /// <inheritdoc />
    public IReadOnlyDictionary<string, string> Claims { get; } = FrozenDictionary<string, string>.Empty;
}
```

**Step 5: Run tests — verify they pass**

```bash
dotnet test ZeroAlloc.Authorization.slnx
```

Expected: 4/4 pass.

**Step 6: Commit**

```bash
git add src tests
git commit -m "feat: add ISecurityContext + AnonymousSecurityContext"
```

---

### Task 1.3: `IAuthorizationPolicy` with bundled async overload (test-first)

**Files:**
- Create: `tests/ZeroAlloc.Authorization.Tests/AuthorizationPolicyAsyncTests.cs`
- Create: `src/ZeroAlloc.Authorization/IAuthorizationPolicy.cs`

**Step 1: Write the failing tests**

`tests/ZeroAlloc.Authorization.Tests/AuthorizationPolicyAsyncTests.cs`:

```csharp
using ZeroAlloc.Authorization;

namespace ZeroAlloc.Authorization.Tests;

public class AuthorizationPolicyAsyncTests
{
    private sealed class SyncOnlyPolicy(bool result) : IAuthorizationPolicy
    {
        public bool IsAuthorized(ISecurityContext ctx) => result;
    }

    private sealed class AsyncOverridePolicy : IAuthorizationPolicy
    {
        public bool SyncCalled { get; private set; }
        public bool AsyncCalled { get; private set; }
        public bool IsAuthorized(ISecurityContext ctx) { SyncCalled = true; return false; }
        public ValueTask<bool> IsAuthorizedAsync(ISecurityContext ctx, CancellationToken ct = default)
        {
            AsyncCalled = true;
            return new ValueTask<bool>(true);
        }
    }

    [Fact]
    public async Task AsyncDefault_DelegatesToSync_True()
    {
        IAuthorizationPolicy policy = new SyncOnlyPolicy(true);
        Assert.True(await policy.IsAuthorizedAsync(AnonymousSecurityContext.Instance));
    }

    [Fact]
    public async Task AsyncDefault_DelegatesToSync_False()
    {
        IAuthorizationPolicy policy = new SyncOnlyPolicy(false);
        Assert.False(await policy.IsAuthorizedAsync(AnonymousSecurityContext.Instance));
    }

    [Fact]
    public async Task AsyncOverride_BypassesSync()
    {
        var policy = new AsyncOverridePolicy();
        var result = await ((IAuthorizationPolicy)policy).IsAuthorizedAsync(AnonymousSecurityContext.Instance);
        Assert.True(result);
        Assert.True(policy.AsyncCalled);
        Assert.False(policy.SyncCalled);
    }

    [Fact]
    public async Task AsyncCancellation_ThrowsOperationCanceled()
    {
        var policy = new SlowAsyncPolicy();
        using var cts = new CancellationTokenSource();
        var task = ((IAuthorizationPolicy)policy).IsAuthorizedAsync(AnonymousSecurityContext.Instance, cts.Token);
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await task);
    }

    private sealed class SlowAsyncPolicy : IAuthorizationPolicy
    {
        public bool IsAuthorized(ISecurityContext ctx) => true;
        public async ValueTask<bool> IsAuthorizedAsync(ISecurityContext ctx, CancellationToken ct = default)
        {
            await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);
            return true;
        }
    }
}
```

**Step 2: Run tests — verify they fail**

```bash
dotnet test ZeroAlloc.Authorization.slnx
```

Expected: build error — `IAuthorizationPolicy` doesn't exist.

**Step 3: Implement `IAuthorizationPolicy.cs`**

`src/ZeroAlloc.Authorization/IAuthorizationPolicy.cs`:

```csharp
namespace ZeroAlloc.Authorization;

/// <summary>Pluggable authorization rule. Implementations override <see cref="IsAuthorized"/>
/// for sync checks; override <see cref="IsAuthorizedAsync"/> for I/O-bound checks (e.g. tenant
/// lookup, claims validation against an external source). The default async implementation
/// delegates to the sync method.</summary>
public interface IAuthorizationPolicy
{
    /// <summary>Returns true if the caller is allowed. Hosts may pass a richer subinterface
    /// (e.g. <c>IToolCallSecurityContext</c>); downcast inside the policy body.</summary>
    bool IsAuthorized(ISecurityContext ctx);

    /// <summary>I/O-bound override point. Default delegates to <see cref="IsAuthorized"/>.
    /// Override to perform asynchronous lookups; honor <paramref name="ct"/> for cancellation.</summary>
    ValueTask<bool> IsAuthorizedAsync(ISecurityContext ctx, CancellationToken ct = default)
        => ValueTask.FromResult(IsAuthorized(ctx));
}
```

**Step 4: Run tests — verify they pass**

```bash
dotnet test ZeroAlloc.Authorization.slnx
```

Expected: all 8 tests pass (4 from Task 1.2 + 4 new).

**Step 5: Commit**

```bash
git add src tests
git commit -m "feat: add IAuthorizationPolicy with async overload via default-interface-method"
```

---

### Task 1.4: Attributes (test-first)

**Files:**
- Create: `tests/ZeroAlloc.Authorization.Tests/AttributeTests.cs`
- Create: `src/ZeroAlloc.Authorization/AuthorizeAttribute.cs`
- Create: `src/ZeroAlloc.Authorization/AuthorizationPolicyAttribute.cs`

**Step 1: Write the failing tests**

`tests/ZeroAlloc.Authorization.Tests/AttributeTests.cs`:

```csharp
using ZeroAlloc.Authorization;

namespace ZeroAlloc.Authorization.Tests;

public class AttributeTests
{
    [Fact]
    public void AuthorizeAttribute_StoresPolicyName()
    {
        var attr = new AuthorizeAttribute("DBA");
        Assert.Equal("DBA", attr.PolicyName);
    }

    [Fact]
    public void AuthorizeAttribute_AttributeUsage_IsMethodOnly()
    {
        var usage = (AttributeUsageAttribute)Attribute.GetCustomAttribute(
            typeof(AuthorizeAttribute), typeof(AttributeUsageAttribute))!;
        Assert.Equal(AttributeTargets.Method, usage.ValidOn);
    }

    [Fact]
    public void AuthorizationPolicyAttribute_StoresName()
    {
        var attr = new AuthorizationPolicyAttribute("AdminOnly");
        Assert.Equal("AdminOnly", attr.Name);
    }

    [Fact]
    public void AuthorizationPolicyAttribute_AttributeUsage_IsClassOnly()
    {
        var usage = (AttributeUsageAttribute)Attribute.GetCustomAttribute(
            typeof(AuthorizationPolicyAttribute), typeof(AttributeUsageAttribute))!;
        Assert.Equal(AttributeTargets.Class, usage.ValidOn);
    }
}
```

**Step 2: Run tests — verify they fail (build error).**

**Step 3: Implement attributes**

`src/ZeroAlloc.Authorization/AuthorizeAttribute.cs`:

```csharp
namespace ZeroAlloc.Authorization;

/// <summary>Binds a method (e.g. an AIFunction-bound method or a Mediator request handler)
/// to a named <see cref="IAuthorizationPolicy"/>.</summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class AuthorizeAttribute(string policyName) : Attribute
{
    /// <summary>Name of the policy this method requires (matches <see cref="AuthorizationPolicyAttribute.Name"/>).</summary>
    public string PolicyName { get; } = policyName;
}
```

`src/ZeroAlloc.Authorization/AuthorizationPolicyAttribute.cs`:

```csharp
namespace ZeroAlloc.Authorization;

/// <summary>Names a policy class so it can be referenced from <see cref="AuthorizeAttribute"/>
/// and host-specific binding APIs (e.g. AI.Sentinel's <c>RequireToolPolicy</c>).</summary>
[AttributeUsage(AttributeTargets.Class)]
public sealed class AuthorizationPolicyAttribute(string name) : Attribute
{
    /// <summary>The name used to reference this policy.</summary>
    public string Name { get; } = name;
}
```

**Step 4: Run tests — verify all pass.**

**Step 5: Commit**

```bash
git add src tests
git commit -m "feat: add [Authorize] and [AuthorizationPolicy] attributes"
```

---

### Task 1.5: README + CHANGELOG + release-please config

**Files:**
- Create: `README.md`
- Create: `CHANGELOG.md`
- Create: `release-please-config.json`
- Create: `.release-please-manifest.json`

**Step 1: `README.md`** — operator-facing, ~60 lines:

```markdown
# ZeroAlloc.Authorization

[![NuGet](https://img.shields.io/nuget/v/ZeroAlloc.Authorization.svg)](https://www.nuget.org/packages/ZeroAlloc.Authorization)
[![Build](https://github.com/ZeroAlloc-Net/ZeroAlloc.Authorization/actions/workflows/ci.yml/badge.svg)](https://github.com/ZeroAlloc-Net/ZeroAlloc.Authorization/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/MarcelRoozekrans?style=flat&logo=githubsponsors&color=ea4aaa&label=Sponsor)](https://github.com/sponsors/MarcelRoozekrans)

Authorization primitives for .NET. Five types — `ISecurityContext`, `IAuthorizationPolicy`, `[Authorize]`, `[AuthorizationPolicy]`, `AnonymousSecurityContext` — designed to be shared across hosts that need a unified policy contract.

Used by:
- [AI.Sentinel](https://github.com/MarcelRoozekrans/AI.Sentinel) — tool-call authorization for `IChatClient`-based agents
- ZeroAlloc.Mediator.Authorization (planned) — request-handler authorization

## Install

\`\`\`bash
dotnet add package ZeroAlloc.Authorization
\`\`\`

Targets `net8.0`, `net9.0`, `net10.0`.

## The contract

\`\`\`csharp
public interface ISecurityContext
{
    string Id { get; }
    IReadOnlySet<string> Roles { get; }
    IReadOnlyDictionary<string, string> Claims { get; }
}

public interface IAuthorizationPolicy
{
    bool IsAuthorized(ISecurityContext ctx);
    ValueTask<bool> IsAuthorizedAsync(ISecurityContext ctx, CancellationToken ct = default)
        => ValueTask.FromResult(IsAuthorized(ctx));
}
\`\`\`

## Writing a policy

\`\`\`csharp
[AuthorizationPolicy("AdminOnly")]
public sealed class AdminOnlyPolicy : IAuthorizationPolicy
{
    public bool IsAuthorized(ISecurityContext ctx) => ctx.Roles.Contains("Admin");
}
\`\`\`

Bind it on a method:

\`\`\`csharp
public sealed class UserService
{
    [Authorize("AdminOnly")]
    public Task DeleteUserAsync(string userId) { ... }
}
\`\`\`

The host (AI.Sentinel, ZeroAlloc.Mediator.Authorization, your own dispatcher) is responsible for matching `[Authorize]` to a registered `[AuthorizationPolicy]` and invoking the policy's `IsAuthorized` / `IsAuthorizedAsync` before dispatching the call.

## Hosts can extend `ISecurityContext`

Hosts define their own subinterface for richer payloads. AI.Sentinel adds `IToolCallSecurityContext : ISecurityContext` with `ToolName` + `Args`. Mediator.Authorization will add `IRequestSecurityContext<TRequest>`. Inside the policy body, downcast:

\`\`\`csharp
public bool IsAuthorized(ISecurityContext ctx)
    => ctx is IToolCallSecurityContext tc && tc.ToolName != "delete_database";
\`\`\`

## Async overrides

For I/O-bound checks (tenant lookup, external claims validation), override `IsAuthorizedAsync`:

\`\`\`csharp
public sealed class TenantPolicy(ITenantService tenants) : IAuthorizationPolicy
{
    public bool IsAuthorized(ISecurityContext ctx) =>
        throw new InvalidOperationException("Use async — tenant lookup is I/O-bound.");

    public async ValueTask<bool> IsAuthorizedAsync(ISecurityContext ctx, CancellationToken ct = default)
        => await tenants.IsActiveAsync(ctx.Id, ct).ConfigureAwait(false);
}
\`\`\`

The host is responsible for calling the async overload.

## License

MIT.
```

**Step 2: `CHANGELOG.md`**:

```markdown
# Changelog

All notable changes to ZeroAlloc.Authorization will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
```

(release-please appends entries.)

**Step 3: `release-please-config.json`**:

```json
{
  "packages": {
    ".": {
      "release-type": "simple",
      "bump-minor-pre-major": true,
      "bump-patch-for-minor-pre-major": true,
      "changelog-types": [
        { "type": "feat",     "section": "Features" },
        { "type": "fix",      "section": "Bug Fixes" },
        { "type": "docs",     "section": "Documentation" },
        { "type": "refactor", "section": "Refactors" }
      ]
    }
  },
  "$schema": "https://raw.githubusercontent.com/googleapis/release-please/main/schemas/config.json"
}
```

**Step 4: `.release-please-manifest.json`**:

```json
{ ".": "1.0.0" }
```

(Pre-seeded so the first release ships at 1.0.0 instead of 0.x.)

**Step 5: Commit**

```bash
git add README.md CHANGELOG.md release-please-config.json .release-please-manifest.json
git commit -m "docs: README + CHANGELOG + release-please config"
```

---

### Task 1.6: CI workflows

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/release-please.yml`
- Create: `.github/workflows/publish.yml`

**Step 1: Copy workflows from `ZeroAlloc.Inject`** and adapt the package names.

```bash
cp -r ../ZeroAlloc.Inject/.github/workflows .github/
```

**Step 2: Open each `.yml` and replace `ZeroAlloc.Inject` → `ZeroAlloc.Authorization`** (project paths, slnx name, package names in pack/push steps).

The publish workflow's pack loop should target a single project:

```yaml
- name: Pack
  run: dotnet pack src/ZeroAlloc.Authorization/ZeroAlloc.Authorization.csproj -c Release --no-build -p:Version=${{ needs.release-please.outputs.version }} -o nupkgs
```

**Step 3: Verify CI YAML parses**

```bash
# Local check via gh CLI (optional)
gh workflow view ci.yml --repo ZeroAlloc-Net/ZeroAlloc.Authorization 2>/dev/null || echo "(remote not yet pushed — that's fine)"
```

**Step 4: Commit**

```bash
git add .github
git commit -m "ci: add ci.yml + release-please.yml + publish.yml"
```

---

### Task 1.7: Verify full Phase 1 build + test

**Step 1: Build everything**

```bash
cd C:/Projects/Prive/ZeroAlloc/ZeroAlloc.Authorization
dotnet build ZeroAlloc.Authorization.slnx -c Release
```

Expected: 0 errors, 0 warnings (with the analyzers active).

**Step 2: Run all tests**

```bash
dotnet test ZeroAlloc.Authorization.slnx -c Release --no-build
```

Expected: 12/12 tests pass (4 anonymous + 4 attributes + 4 async).

**Step 3: Pack the NuGet locally to verify metadata**

```bash
dotnet pack src/ZeroAlloc.Authorization/ZeroAlloc.Authorization.csproj -c Release -o /tmp/za-authz-nupkg
ls /tmp/za-authz-nupkg/
```

Expected: `ZeroAlloc.Authorization.1.0.0.nupkg` exists. Inspect:

```bash
unzip -l /tmp/za-authz-nupkg/ZeroAlloc.Authorization.1.0.0.nupkg | grep -E "lib/(net8|net9|net10)|README|icon"
```

Expected: 3 TFM directories with `ZeroAlloc.Authorization.dll`, README.md at root, icon.png at root.

No commit needed — verification only.

---

## Phase 2 — Cross-repo integration via ProjectReference (local validation only)

Phase 2 happens on `C:\Projects\Prive\AI.Sentinel\` on a new branch. The branch `feat/zeroalloc-authorization-extraction` is already open per the design-doc commit.

### Task 2.1: Add cross-repo ProjectReference to AI.Sentinel.csproj

**Files:**
- Modify: `src/AI.Sentinel/AI.Sentinel.csproj`

**Step 1: Add a `<ProjectReference>` pointing across the repo boundary.**

Find the existing `<ItemGroup>` containing PackageReferences and add:

```xml
<ItemGroup>
  <ProjectReference Include="..\..\..\ZeroAlloc\ZeroAlloc.Authorization\src\ZeroAlloc.Authorization\ZeroAlloc.Authorization.csproj" />
</ItemGroup>
```

The `..\..\..\` walks up `src/AI.Sentinel/` → `src/` → `AI.Sentinel/` → `Prive/`, then down into ZeroAlloc.

**Step 2: Verify the reference resolves**

```bash
dotnet restore src/AI.Sentinel/AI.Sentinel.csproj
```

Expected: 0 errors.

No commit yet — Phase 2 is one logical commit at the end.

---

### Task 2.2: Update internal `using` statements in the 17 AI.Sentinel source files

The 5 deleted types must be referenced via `using ZeroAlloc.Authorization;` from inside AI.Sentinel.dll's own source. Type-forwarders only redirect EXTERNAL consumers; AI.Sentinel.dll's internal references must point at the canonical namespace.

**Files (17, run grep to confirm — list verified at plan-write time):**

```
src/AI.Sentinel/Approvals/IApprovalStore.cs
src/AI.Sentinel/Approvals/InMemoryApprovalStore.cs
src/AI.Sentinel/Authorization/AuthorizationChatClient.cs
src/AI.Sentinel/Authorization/AuthorizationChatClientBuilderExtensions.cs
src/AI.Sentinel/Authorization/DefaultToolCallGuard.cs
src/AI.Sentinel/Authorization/IToolCallGuard.cs
src/AI.Sentinel/Authorization/IToolCallSecurityContext.cs
src/AI.Sentinel/Authorization/Policies/AdminOnlyPolicy.cs
src/AI.Sentinel/Authorization/SentinelOptionsAuthorizationExtensions.cs
src/AI.Sentinel/Authorization/ToolCallAuthorizationException.cs
src/AI.Sentinel/Authorization/ToolCallAuthorizationPolicy.cs
src/AI.Sentinel/ServiceCollectionExtensions.cs
```

**Step 1: Re-run the grep to confirm the list hasn't drifted**

```bash
cd C:/Projects/Prive/AI.Sentinel
grep -rl "ISecurityContext\|IAuthorizationPolicy\|AuthorizeAttribute\|AuthorizationPolicyAttribute\|AnonymousSecurityContext" src/AI.Sentinel --include="*.cs" | grep -v "src/AI.Sentinel/Authorization/\(ISecurityContext\|IAuthorizationPolicy\|AuthorizeAttribute\|AuthorizationPolicyAttribute\|AnonymousSecurityContext\)\.cs"
```

(The `grep -v` filters out the 5 files being deleted in Task 2.3 themselves.)

**Step 2: For each listed file, add `using ZeroAlloc.Authorization;`**

Use the Edit tool. For each file, prepend the new using to the existing using block. Many files already have `namespace AI.Sentinel.Authorization;` — they need the explicit using because they're in the namespace but the types are no longer defined there.

Example for `src/AI.Sentinel/Authorization/IToolCallSecurityContext.cs`:

Before:
```csharp
using System.Text.Json;

namespace AI.Sentinel.Authorization;

public interface IToolCallSecurityContext : ISecurityContext
```

After:
```csharp
using System.Text.Json;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Authorization;

public interface IToolCallSecurityContext : ISecurityContext
```

**Step 3: Don't touch the 9 sibling-package files or the 12 test files yet.** They consume `using AI.Sentinel.Authorization;` which will keep working via type-forwarders after Task 2.4. They can be migrated in a follow-up cleanup if desired (out of scope for this plan).

No commit yet.

---

### Task 2.3: Delete the 5 source files

**Files:**
- Delete: `src/AI.Sentinel/Authorization/ISecurityContext.cs`
- Delete: `src/AI.Sentinel/Authorization/IAuthorizationPolicy.cs`
- Delete: `src/AI.Sentinel/Authorization/AuthorizeAttribute.cs`
- Delete: `src/AI.Sentinel/Authorization/AuthorizationPolicyAttribute.cs`
- Delete: `src/AI.Sentinel/Authorization/AnonymousSecurityContext.cs`

**Step 1: Delete**

```bash
rm src/AI.Sentinel/Authorization/ISecurityContext.cs
rm src/AI.Sentinel/Authorization/IAuthorizationPolicy.cs
rm src/AI.Sentinel/Authorization/AuthorizeAttribute.cs
rm src/AI.Sentinel/Authorization/AuthorizationPolicyAttribute.cs
rm src/AI.Sentinel/Authorization/AnonymousSecurityContext.cs
```

**Step 2: Build to confirm internal refs resolve via the package**

```bash
dotnet build src/AI.Sentinel/AI.Sentinel.csproj
```

Expected: 0 errors, 0 warnings. If you get `CS0246: type 'ISecurityContext' could not be found`, it means a file in the Task 2.2 list is missing `using ZeroAlloc.Authorization;` — go back and fix.

No commit yet.

---

### Task 2.4: Append type-forwarders to AssemblyAttributes.cs

**Files:**
- Modify: `src/AI.Sentinel/AssemblyAttributes.cs`

**Step 1: Read the current file**

```bash
cat src/AI.Sentinel/AssemblyAttributes.cs
```

It currently contains the existing `[InternalsVisibleTo]` lines. Append:

```csharp
using System.Runtime.CompilerServices;

[assembly: TypeForwardedTo(typeof(ZeroAlloc.Authorization.ISecurityContext))]
[assembly: TypeForwardedTo(typeof(ZeroAlloc.Authorization.IAuthorizationPolicy))]
[assembly: TypeForwardedTo(typeof(ZeroAlloc.Authorization.AuthorizeAttribute))]
[assembly: TypeForwardedTo(typeof(ZeroAlloc.Authorization.AuthorizationPolicyAttribute))]
[assembly: TypeForwardedTo(typeof(ZeroAlloc.Authorization.AnonymousSecurityContext))]
```

(If the `using System.Runtime.CompilerServices;` line is already there for `[InternalsVisibleTo]`, don't duplicate it.)

**Step 2: Build**

```bash
dotnet build src/AI.Sentinel/AI.Sentinel.csproj
```

Expected: 0 errors.

**Step 3: Verify type-forwarders are emitted to the assembly**

```bash
# Inspect the compiled DLL's metadata for the forwarded types
dotnet tool install -g dotnet-ildasm 2>/dev/null || true   # idempotent
ildasm src/AI.Sentinel/bin/Debug/net8.0/AI.Sentinel.dll | grep -i "forwarder"
```

Expected: 5 lines mentioning the forwarded types. (If `ildasm` isn't available, skip — the next task's full test run validates the forwarders work.)

---

### Task 2.5: Run full AI.Sentinel test suite

**Step 1: Build everything**

```bash
cd C:/Projects/Prive/AI.Sentinel
dotnet build AI.Sentinel.slnx --nologo 2>&1 | tail -10
```

Expected: 0 errors, 0 warnings.

**Step 2: Run all tests**

```bash
dotnet test AI.Sentinel.slnx --nologo --no-build 2>&1 | grep -E "(Passed|Failed)!" | sort -u
```

Expected: every test project shows `Passed!` with the same counts as before the migration:
- `AI.Sentinel.Tests.dll`: 583 (or whatever the current main count is — verify with `git log` to find the most recent commit's reported count)
- `AI.Sentinel.Approvals.Sqlite.Tests.dll`: 14
- `AI.Sentinel.Approvals.EntraPim.Tests.dll`: 19
- All others: unchanged

**If anything fails:** the type-forwarders or `using` updates are wrong. Roll back, debug. The most likely cause: a sibling-package file (e.g. `src/AI.Sentinel.Mcp/Authorization/EnvironmentSecurityContext.cs`) has `: ISecurityContext` and the type-forwarder isn't kicking in. Diagnose by checking which test failed and which assembly owns the type reference.

---

### Task 2.6: Commit Phase 2

**Step 1: Stage everything**

```bash
git add src/AI.Sentinel/AI.Sentinel.csproj
git add src/AI.Sentinel/AssemblyAttributes.cs
git add -u src/AI.Sentinel/   # picks up the 5 deletions + the using-line edits
```

**Step 2: Commit**

```bash
git commit -m "$(cat <<'EOF'
refactor(authz): extract primitives to ZeroAlloc.Authorization (local ProjectReference)

Phase 2 of the ZeroAlloc.Authorization extraction. Adds a cross-repo
ProjectReference to ..\..\..\ZeroAlloc\ZeroAlloc.Authorization\... for
local validation; deletes the 5 source files (ISecurityContext,
IAuthorizationPolicy, AuthorizeAttribute, AuthorizationPolicyAttribute,
AnonymousSecurityContext); adds [TypeForwardedTo] redirects in
AssemblyAttributes.cs so external consumers' using AI.Sentinel.Authorization;
keeps resolving.

Internal AI.Sentinel sources updated with using ZeroAlloc.Authorization;
where needed. Sibling AI.Sentinel.* packages and tests unchanged — they
resolve through the type-forwarders.

Phase 3 (publish ZeroAlloc.Authorization 1.0.0 to nuget.org) and
Phase 4 (switch to PackageReference + bump AI.Sentinel to 1.5.0) follow.

Full test suite green (583 main + per-package totals unchanged).
EOF
)"
```

---

## Phase 3 — Ship ZeroAlloc.Authorization 1.0.0 to nuget.org

This phase happens in the ZeroAlloc.Authorization repo, not AI.Sentinel. AI.Sentinel sits with `<ProjectReference>` until Phase 4.

### Task 3.1: Push ZeroAlloc.Authorization branch + open PR

**Step 1: Create the GitHub repo** (if it doesn't exist) at `https://github.com/ZeroAlloc-Net/ZeroAlloc.Authorization`. User-driven step — do this through the GitHub UI or `gh repo create ZeroAlloc-Net/ZeroAlloc.Authorization --public --source=. --remote=origin`.

**Step 2: Push**

```bash
cd C:/Projects/Prive/ZeroAlloc/ZeroAlloc.Authorization
git remote add origin https://github.com/ZeroAlloc-Net/ZeroAlloc.Authorization.git 2>/dev/null || true
git push -u origin main
```

**Step 3: Verify CI runs and goes green** on the first push (the `ci.yml` workflow). Wait for it to finish.

---

### Task 3.2: Trigger 1.0.0 release

The release-please workflow already triggered on the first push to main; it should have opened a PR titled `chore: release 1.0.0`.

**Step 1: Verify the release PR exists**

```bash
gh pr list --repo ZeroAlloc-Net/ZeroAlloc.Authorization
```

Expected: one open PR for the 1.0.0 release.

**Step 2: Merge the release PR.**

This triggers the `publish.yml` workflow which builds, packs, and pushes to nuget.org with the `NUGET_API_KEY` secret. Verify the secret is set on the new repo: `gh secret list --repo ZeroAlloc-Net/ZeroAlloc.Authorization`. If absent, add it before merging.

**Step 3: Wait for publish to complete**

```bash
gh run list --repo ZeroAlloc-Net/ZeroAlloc.Authorization --workflow=publish.yml --limit 1
```

Expected: status `completed`, conclusion `success`.

---

### Task 3.3: Verify package is live on nuget.org

**Step 1: Wait ~5 minutes for the NuGet indexing to settle, then probe:**

```bash
mkdir /tmp/za-authz-probe && cd /tmp/za-authz-probe
dotnet new classlib
dotnet add package ZeroAlloc.Authorization --version 1.0.0
dotnet build
```

Expected: package resolves, build succeeds.

If the package isn't found, NuGet indexing might still be propagating. The package page at `https://www.nuget.org/packages/ZeroAlloc.Authorization/1.0.0` is the authoritative check.

---

## Phase 4 — Switch AI.Sentinel to PackageReference and ship 1.5.0

Back on `C:\Projects\Prive\AI.Sentinel\` on the same `feat/zeroalloc-authorization-extraction` branch.

### Task 4.1: Replace ProjectReference with PackageReference

**Files:**
- Modify: `src/AI.Sentinel/AI.Sentinel.csproj`

**Step 1: Open the csproj. Find the line added in Task 2.1:**

```xml
<ProjectReference Include="..\..\..\ZeroAlloc\ZeroAlloc.Authorization\src\ZeroAlloc.Authorization\ZeroAlloc.Authorization.csproj" />
```

**Step 2: Replace with:**

```xml
<PackageReference Include="ZeroAlloc.Authorization" Version="1.0.*" />
```

(Use a wildcard so future patch releases of ZeroAlloc.Authorization flow in automatically; AI.Sentinel doesn't care about specific patch versions.)

**Step 3: Restore + build**

```bash
dotnet restore src/AI.Sentinel/AI.Sentinel.csproj
dotnet build src/AI.Sentinel/AI.Sentinel.csproj
```

Expected: NuGet downloads `ZeroAlloc.Authorization 1.0.x` from nuget.org; 0 errors, 0 warnings.

**Step 4: Run full test suite**

```bash
dotnet test AI.Sentinel.slnx --nologo --no-build 2>&1 | grep -E "(Passed|Failed)!" | sort -u
```

Expected: same counts as Task 2.5. The only difference between ProjectReference and PackageReference is where the DLL comes from; behaviour must be identical.

---

### Task 4.2: Commit Phase 4

```bash
git add src/AI.Sentinel/AI.Sentinel.csproj
git commit -m "feat(authz): consume ZeroAlloc.Authorization 1.0 via PackageReference

Switches src/AI.Sentinel/AI.Sentinel.csproj from the cross-repo
ProjectReference (used during Phase 2 local validation) to a
PackageReference targeting ZeroAlloc.Authorization 1.0.*. This is
the change that ships in AI.Sentinel 1.5.0; combined with the
type-forwarders from Phase 2, existing 1.4.x consumers see no
breaking change.

Full test suite green."
```

---

### Task 4.3: Push + open PR + merge

**Step 1: Push**

```bash
git push -u origin feat/zeroalloc-authorization-extraction
```

**Step 2: Open PR**

```bash
gh pr create --base main --head feat/zeroalloc-authorization-extraction \
  --title "feat(authz): extract primitives to ZeroAlloc.Authorization" \
  --body "$(cat <<'EOF'
## Summary

Extracts the 5 generic authorization primitives — \`ISecurityContext\`, \`IAuthorizationPolicy\`, \`[Authorize]\`, \`[AuthorizationPolicy]\`, \`AnonymousSecurityContext\` — out of AI.Sentinel into the new \`ZeroAlloc.Authorization\` 1.0 NuGet package.

\`[TypeForwardedTo]\` redirects in \`AI.Sentinel.AssemblyAttributes\` mean existing 1.4.x consumers' \`using AI.Sentinel.Authorization;\` keeps resolving — zero breaking change. AI.Sentinel-specific types (\`IToolCallSecurityContext\`, \`AuthorizationDecision\`, \`IToolCallGuard\`, \`DefaultToolCallGuard\`, the \`AuthorizationChatClient\` middleware, concrete policies) all stay in AI.Sentinel.

The async overload (\`ValueTask<bool> IsAuthorizedAsync\`) is bundled into ZeroAlloc.Authorization 1.0 with a default-interface-method fallback, so existing sync-only AI.Sentinel policies keep working unchanged.

## Design + Plan

- Design: [\`docs/plans/2026-04-30-zeroalloc-authorization-extraction-design.md\`](docs/plans/2026-04-30-zeroalloc-authorization-extraction-design.md)
- Plan: [\`docs/plans/2026-04-30-zeroalloc-authorization-extraction.md\`](docs/plans/2026-04-30-zeroalloc-authorization-extraction.md)

## Test plan

- [ ] Full \`dotnet test AI.Sentinel.slnx\` green on net8 + net10 (counts match pre-extraction)
- [ ] AOT publish CI matrix green for all three CLIs
- [ ] After merge, release-please opens a 1.5.0 PR
- [ ] After 1.5.0 ships, an existing 1.4.x consumer with \`using AI.Sentinel.Authorization;\` recompiles without source changes

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

**Step 3: Wait for CI to go green, then merge.**

After merge, release-please opens a 1.5.0 PR. Merging that triggers the publish workflow, which packs all 15 packages and pushes to nuget.org as 1.5.0.

---

## Final review checklist

- [ ] ZeroAlloc.Authorization 1.0.0 published on nuget.org with all 3 TFMs (net8/net9/net10)
- [ ] AI.Sentinel 1.5.0 published with `<PackageReference Include="ZeroAlloc.Authorization" Version="1.0.*" />`
- [ ] Existing AI.Sentinel 1.4.x consumers can recompile against 1.5.0 with no source changes (verify with a smoke test consumer)
- [ ] Type-forwarders emitted to `AI.Sentinel.dll` metadata (verify with ildasm or by recompiling a 1.4.x consumer)
- [ ] No type duplications (only one `ISecurityContext` definition, in `ZeroAlloc.Authorization.dll`)
- [ ] BACKLOG entry "`ZeroAlloc.Authorization.Abstractions` extraction" removed (or updated to reflect the no-`.Abstractions` decision)
- [ ] Async overload exercised by tests (default-impl delegation + override + cancellation)

---

## Rollback strategy

If anything goes catastrophically wrong:

- **Phase 1–3 rollback**: don't merge the AI.Sentinel PR. ZeroAlloc.Authorization 1.0.0 stays on nuget.org as a no-op (no consumers yet); we can bump it to 1.0.1 with a fix later or leave it.
- **Phase 4 rollback**: if 1.5.0 ships and breaks consumers, ship 1.5.1 reverting the AI.Sentinel-side changes (type-forwarders + PackageReference removal). The 5 types come back to AI.Sentinel.dll. ZeroAlloc.Authorization stays on nuget.org but unused.

The TypeForwardedTo design specifically minimizes blast radius — even a worst-case rollback is a clean revert.

---

## Out of scope (deferred follow-ups)

- Migrating sibling AI.Sentinel.* packages and test files from `using AI.Sentinel.Authorization;` to `using ZeroAlloc.Authorization;` (works fine via forwarders; cleanup is optional).
- Building `ZeroAlloc.Mediator.Authorization` (separate work in the Mediator repo).
- Source generator for policy-name lookup (backlog item "Source-gen-driven policy name lookup").
- `[Authorize]` attribute discovery for AIFunction-bound methods at registration time (backlog item).
