# AES-GCM-SIV for Zig

Nonce misuse-resistant AEAD (Authenticated Encryption with Associated Data) scheme specified in [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452.html).

## Usage

1. Create or modify the `build.zig.zon` file in the project root to include `aes-gcm-siv-zig` as a dependency.
    
    <details>

    <summary><code>build.zig.zon</code> example</summary>

    ```zig
    .{
        .name = "<name of your program>",
        .version = "<version of your program>",
        .dependencies = .{
            .aes_gcm_siv = .{
                .url = "https://github.com/e4m2/aes-gcm-siv-zig/archive/refs/tags/<git tag>.tar.gz",
                .hash = "<package hash>",
            },
        },
    }
    ```

    If unsure what to fill out for `<package hash>`, remove the field entirely and Zig will tell you the correct value in an error message.

    </details>

2. Add `aes-gcm-siv-zig` as a dependency in `build.zig`.

    <details>

    <summary><code>build.zig</code> example</summary>

    ```zig
    const aes_gcm_siv = b.dependency("aes_gcm_siv", .{
        .target = target,
        .optimize = optimize,
    });
    exe.addModule("aes_gcm_siv", aes_gcm_siv.module("aes_gcm_siv"));
    ```

    </details>