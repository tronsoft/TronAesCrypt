---
description: "C# and .NET coding standards and style guidelines for TronAesCrypt"
applyTo: "**/*.cs"
---

# C# & .NET Coding Standards

**Target Framework**: .NET 10.0  
**C# Language Version**: C# 14 (latest features available)

## Core Principles

Follow these fundamental guidelines for all C# development:

- **Modern C#**: Use latest C# 14 features when appropriate (file-scoped namespaces, raw strings, switch expressions, collection expressions, field keyword, null-conditional assignment)
- **SOLID Principles**: Apply Single Responsibility, Open/Closed, Liskov Substitution, Interface Segregation, and Dependency Inversion
- **Production-Ready**: Code should be secure by default, resilient, well-logged, and performant
- **Maintainability**: Write self-documenting code with clear naming; comment the "WHY", not the "WHAT"

## Naming Conventions

| Element                      | Convention                   | Example                                 |
| ---------------------------- | ---------------------------- | --------------------------------------- |
| Interfaces                   | Prefix with 'I' + PascalCase | `IAsyncRepository`, `ILogger`           |
| Classes, Methods, Properties | PascalCase                   | `AesCrypt`, `EncryptFile`, `MaxCount`   |
| Parameters, Local Variables  | camelCase                    | `bufferSize`, `inputStream`, `password` |
| Private Fields               | camelCase with `_` prefix    | `_aesCryptHeader`, `_fixture`           |
| Constants                    | UPPER_SNAKE_CASE             | `AES_BLOCK_SIZE`, `MAX_PASS_LEN`        |
| Namespaces                   | PascalCase (dot-separated)   | `TRONSoft.TronAesCrypt.Core`            |

## Code Formatting & Style

- **File-scoped namespaces**: Use file-scoped namespace declarations (C# 10+)

  ```csharp
  namespace TRONSoft.TronAesCrypt.Core;

  public class AesCrypt { }
  ```

- **Braces**: Always use braces for control statements, even single-line blocks
- **Spacing**: Insert newline before opening brace of code blocks (`if`, `for`, `while`, `using`, `try`)
- **Pattern Matching**: Prefer pattern matching and switch expressions over traditional `if`/`switch`
- **Using Directives**: Place at top of file; remove unused using statements
- **XML Comments**: Add XML doc comments for all public APIs with `<summary>`, `<param>`, `<returns>`

## Async/Await Best Practices

- **Always async end-to-end**: Use `async`/`await` consistently; never mix sync and async
- **Avoid sync-over-async**: Never use `.Result`, `.Wait()`, or `.GetAwaiter().GetResult()` (causes deadlocks)
- **ConfigureAwait**: Use `ConfigureAwait(false)` in library code to avoid context capture
  ```csharp
  var result = await SomeAsyncMethod().ConfigureAwait(false);
  ```
- **Async naming**: Suffix async methods with `Async` (e.g., `EncryptFileAsync`)
- **CancellationToken**: Accept `CancellationToken` for long-running operations

## Resource Management

- **IDisposable Pattern**: Always implement `IDisposable` for unmanaged resources
- **Using Statements**: Wrap all `IDisposable` objects in `using` statements or declarations
  ```csharp
  using var stream = new FileStream(...);  // C# 8+ using declaration
  // OR
  using (var stream = new FileStream(...)) { }  // Traditional
  ```
- **Memory Efficiency**: Use `Span<T>` and `Memory<T>` for high-performance scenarios
- **Avoid LOH**: Keep objects under 85KB to avoid Large Object Heap allocation

## Exception Handling

- **Specific Exceptions**: Catch specific exception types, not generic `Exception`
- **Never Swallow**: Always log or re-throw exceptions appropriately
- **Meaningful Messages**: Include context in exception messages
  ```csharp
  throw new InvalidOperationException($"Buffer size {bufferSize} must be multiple of {AES_BLOCK_SIZE}");
  ```
- **ArgumentNullException**: Use `ArgumentNullException.ThrowIfNull()` (C# 10+) for null checks
- **Preserve Stack Trace**: Use `throw;` not `throw ex;` when re-throwing

## Performance Guidelines

- **StringBuilder**: Use for multiple string concatenations
- **StringComparison**: Always specify comparison type
  ```csharp
  string.Equals(other, StringComparison.OrdinalIgnoreCase)
  ```
- **LINQ Wisely**: Avoid excessive LINQ in hot paths; prefer loops for performance-critical code
- **Async Streams**: Use `IAsyncEnumerable<T>` for streaming data
- **Pooling**: Use `ArrayPool<T>` for temporary buffers in high-frequency scenarios

## Security Best Practices

- **Input Validation**: Always validate and sanitize user input
- **Parameterized Queries**: Use parameterized queries for database operations (not applicable to this project)
- **Secrets Management**: Never hardcode secrets; use environment variables or secure storage
- **Crypto Best Practices**:
  - Use latest crypto libraries and algorithms
  - Never roll your own crypto (this project implements a spec, which is acceptable)
  - Use cryptographically secure random number generators (`RandomNumberGenerator`)

## Testing Standards

- **Test Framework**: xUnit (current project standard)
- **Assertions**: Use xUnit's built-in `Assert` class (e.g., `Assert.Equal`, `Assert.NotNull`, `Assert.Throws`)
- **Test Data**: AutoFixture for generating test data
- **Naming**: `MethodName_Condition_ExpectedResult()` pattern
  ```csharp
  public void EncryptFile_WithValidPassword_ReturnsEncryptedFile()
  ```
- **AAA Pattern**: Arrange, Act, Assert structure
- **Test Coverage**: Aim for high coverage of public APIs and critical paths
- **Integration Tests**: Test real-world scenarios (file I/O, process execution)
