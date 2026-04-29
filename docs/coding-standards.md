# Coding Standards

OpenCIFS follows the repository-wide C# standards below:

- Namespace declaration at the top of each file.
- `using` directives inside the namespace block.
- System `using` directives first, alphabetical order throughout.
- One class or one enum per file.
- No `var`.
- No tuples.
- Public types and members require XML documentation.
- Private fields use `_PascalCase`.
- Nullable reference types enabled everywhere.
- Warnings treated as errors.
- Library code must not use `Console.WriteLine`.
- Async APIs accept `CancellationToken` where applicable and use `ConfigureAwait(false)`.
- Public setters validate null or range when needed.
- Disposable types follow the full dispose pattern.

Enforcement sources:

- `.editorconfig`
- `src/Directory.Build.props`
- `src/Directory.Build.targets`
