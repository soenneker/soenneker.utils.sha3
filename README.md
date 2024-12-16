[![](https://img.shields.io/nuget/v/soenneker.utils.sha3.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.utils.sha3/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.utils.sha3/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.utils.sha3/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.utils.sha3.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.utils.sha3/)

# ![](https://user-images.githubusercontent.com/4441470/224455560-91ed3ee7-f510-4041-a8d2-3fc093025112.png) Soenneker.Utils.SHA3
### A utility library for SHA-3 hashing

Providing methods for computing SHA3 hashes for strings and files. It supports hardware-accelerated hashing and has software fallbacks for non-hardware environments.

## Installation

```
dotnet add package Soenneker.Utils.SHA3
```

## Registration

```csharp
services.AddSha3UtilAsScoped();
```

## Usage

```csharp
string hash = sha3Util.HashString("example input");
```

```csharp
string hash = await sha3Util.HashFile("/path/to/file.txt");
```