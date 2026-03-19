# k32dump

A minimal x86-32 Windows file dumper written in pure assembly with zero CRT
dependencies. Dumps any file's raw contents in hex, decimal, octal, or binary
with offset tracking. All output is handled directly through kernel32, and yes,
that's literally what the k in k32dump stands for, no CRT, no standard library,
just raw Windows API calls and hand-rolled argument parsing.

## Usage
```
k32dump.exe <file> <flag>
```

| Flag | Mode    | Bytes per row |
|------|---------|---------------|
| -h   | hex     | 16            |
| -d   | decimal | 16            |
| -o   | octal   | 16            |
| -b   | binary  | 8             |

## Examples
```
k32dump.exe file.exe -h
k32dump.exe "C:\path\to\file.bin" -b
k32dump.exe 'file.dat' -o
k32dump.exe file.dat -d
```

## Installing
```
git clone https://github.com/0xNullll/k32dump.git
cd k32dump
```


## Building
```
nasm -w+all -f win32 k32dump.asm -o k32dump.obj
link /subsystem:console /entry:_main /nodefaultlib k32dump.obj <path>\kernel32.lib
```

`kernel32.lib` is found in the Windows SDK under `Lib\<version>\um\x86\kernel32.lib`

## Requirements

- NASM 2.16
- MSVC linker (link.exe)
- Windows SDK (for kernel32.lib)
- x86 32-bit Windows

---

## License

This project is released under the **MIT license**. See [LICENSE](LICENSE) for full text.