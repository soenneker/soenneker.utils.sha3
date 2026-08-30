[![](https://img.shields.io/nuget/v/soenneker.utils.sha3.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.utils.sha3/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.utils.sha3/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.utils.sha3/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.utils.sha3.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.utils.sha3/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.utils.sha3/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.utils.sha3/actions/workflows/codeql.yml)

# ![](https://user-images.githubusercontent.com/4441470/224455560-91ed3ee7-f510-4041-a8d2-3fc093025112.png) Soenneker.Utils.SHA3

Computes SHA3-256 digests for UTF-8 strings, files, and framed directory trees.

## Installation

```bash
dotnet add package Soenneker.Utils.SHA3
```

## Registration

```csharp
using Soenneker.Utils.SHA3.Registrars;

services.AddSha3UtilAsSingleton();
```

Scoped registration is also available. The utility keeps no per-operation hash state, so a
singleton can safely serve concurrent callers.

## Hash a string or file

```csharp
string textDigest = sha3Util.HashString("example input");

string fileDigest = await sha3Util.HashFile(
    filePath,
    cancellationToken: cancellationToken);
```

Strings are encoded as UTF-8. Files are streamed rather than loaded completely into memory. Both
methods return a 64-character uppercase hexadecimal SHA3-256 digest with no prefix or separators.
Missing/inaccessible files and I/O failures propagate; file hashing observes cancellation.

The implementation uses the platform `System.Security.Cryptography` SHA3-256 implementation when
available and falls back to BouncyCastle otherwise. The digest is the same algorithm and format on
both paths; platform support does not by itself guarantee hardware acceleration.

## Hash a directory tree

```csharp
string treeDigest = await sha3Util.HashDirectory(
    directoryPath,
    cancellationToken: cancellationToken);
```

Directory hashing recursively enumerates files, orders their paths ordinally, and combines each
file's relative path with its SHA3-256 content digest. Directory separators in relative paths are
normalized to `/`. Each UTF-8 path is framed with a four-byte little-endian byte length before the
fixed-size file digest, so record boundaries are unambiguous. An empty directory returns the
SHA3-256 digest of empty input, not an empty string.

The directory operation is not a filesystem snapshot. Concurrent renames, writes, additions, or
deletions can change the result or cause an exception. Metadata such as timestamps, permissions,
empty subdirectories, and the root directory's own name are not included.

Directory digest framing changed from the earlier unframed concatenation format; existing stored
directory hashes must be regenerated. String and file digest formats did not change.

## Security scope

SHA3-256 is an unkeyed digest. It can detect changes when compared with a trusted expected value,
but an attacker who can replace both content and digest can recompute it. Use HMAC or a digital
signature for authenticity, and a password-hashing function with salt and work factor for
passwords. Avoid logging sensitive input even though only operational details are logged here.
