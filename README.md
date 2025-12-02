# efile
A cli tool for simple encryption of files

## Usage
Encrypt
```bash
efile enc <file1> <file2> ... <fileN>

efile enc <file_folder>
```
> Prompts interactively for passphrase

Decrypt
```bash
efile dec <file1> <file2> ... <fileN>

efile dec <file_folder>
```

## Installation

Nix (local flake)
```bash
nix run github:Beriholic/efile

nix profile add github:Beriholic/efile
```

Cargo (from crates.io)
```bash
cargo install efile
```

Cargo from Git
```bash
cargo install --git https://github.com/Beriholic/efile.git
```

Build from source
```bash
git clone https://github.com/Beriholic/efile.git
cd efile
cargo install --path .
# or run directly
cargo run -- enc <path>
```
