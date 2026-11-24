# Have I Been Pwned integration

The `Crestacle.Bedrock.HaveIBeenPwned` package adds breach detection to password validation. When enabled, passwords are checked against the [Have I Been Pwned](https://haveibeenpwned.com/Passwords) k-anonymity API during registration and password changes. Passwords that appear in known data breaches are rejected.

The k-anonymity model means only the first 5 characters of the SHA-1 hash are sent to the API — the full password is never transmitted.

---

## Install

```bash
dotnet add package Crestacle.Bedrock.HaveIBeenPwned
```

---

## Registration

```csharp
builder.Services
    .AddBedrockEntityFramework<AppDbContext>()
    .AddBedrockAspNetCore(opts => { ... })
    .WithHaveIBeenPwnedPasswordValidator()
    .AddBedrockControllers();
```

`WithHaveIBeenPwnedPasswordValidator()` wraps whatever `IPasswordValidator` is already registered — the built-in complexity validator by default, or your own custom validator if you registered one earlier in the chain — so both run on every password submission.

---

## Combining with the common password deny-list

For maximum coverage, enable both the HIBP validator and the built-in common password deny-list:

```csharp
builder.Services.AddBedrockAspNetCore(opts =>
{
    opts.Password.CommonPasswordDenyListPath = "embedded";
    // ...
})
.AddHaveIBeenPwnedPasswordValidator();
```

The built-in list blocks the top 1,000 most common passwords without a network call, while HIBP covers billions of breached passwords.

---

## Network dependency

HIBP validation requires an outbound HTTPS call to `api.pwnedpasswords.com` during password submission. If the API is unreachable (network failure, timeout, or a non-2xx/parse error), the validator fails **open** — the password is accepted rather than rejected, so an HIBP outage never blocks registration or password changes. The inner validator's own complexity/history rules still run regardless.

If you need the stricter fail-closed behaviour instead, implement a custom `IPasswordValidator` that wraps `HaveIBeenPwnedPasswordValidator` and rejects the password when the breach check could not be completed.
