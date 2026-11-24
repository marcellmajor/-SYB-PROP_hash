# SYB-PROP_hash

The story, algorithm and public password-cracking modules for **SYB-PROP**,
the proprietary password hash used by Sybase Adaptive Server Enterprise
(ASE) before ASE 15.0.2.

This repository is self-contained. It contains:

- `README.md` — this file.
- `Hacktivity2010_WritingOwnPasswordCracker.pdf` — the original
  Hacktivity 2010 presentation by Marcell Major.
- `SYB-PROP_PoC/` — Marcell Major's proof-of-concept C reproduction of
  SYB-PROP: `syb-prop_repro.cpp` / `syb-prop_repro.h` (the algorithm),
  `feal8.cpp` / `feal8.h` (FEAL-8, Sybase variant) and
  `FEAL_proba.cpp` (test program). No Visual Studio files: it builds
  with any standard C++ compiler (see "Building the proof of
  concept" below). Two portability changes from the original
  Windows-only PoC: `FEAL_proba.cpp` no longer includes
  `<Windows.h>` (standard `int main`), and `syb-prop_repro.cpp`
  reimplements the MSVC `rand()`/`srand()` generator explicitly so
  the salts no longer depend on the platform C library. Note: the
  FEAL-8 code itself (`feal8.cpp`) splits words through C unions and
  is little-endian dependent, so byte-identical output is verified
  on little-endian platforms (x86-64, g++ and clang++); a big-endian
  build will differ (John the Ripper later patched `f()` for
  big-endian — this PoC does not have that patch).
- `sybase_sha256.html` — Toth & Major's description of the newer,
  SHA-256-based Sybase hash (explained in section 5 below).

Public John the Ripper modules (plain URLs, copy/paste friendly):

- Sybase ASE SHA-256 format:
  https://github.com/openwall/john/blob/bleeding-jumbo/src/SybaseASE_fmt_plug.c
- Sybase SYB-PROP (FEAL-8) format:
  https://github.com/openwall/john/blob/bleeding-jumbo/src/SybasePROP_fmt_plug.c

---

### Building the proof of concept

```sh
g++ -std=c++11 -O2 -o syb-prop_test \
    SYB-PROP_PoC/FEAL_proba.cpp SYB-PROP_PoC/feal8.cpp \
    SYB-PROP_PoC/syb-prop_repro.cpp
./syb-prop_test
```

(`clang++` works with the same command line.) Full expected output,
for password `almafa4` with seed `0xD4` — the example stored hash
from the Hacktivity presentation:

```text

hash:

c8a83114cf59fe51
0d92c7e90c37f274
1e0a04f70af14d9b
d8a21f46


Result:
0xd405c8a83114cf59fe510d92c7e90c37f2741e0a04f70af14d9bd8a21f46

```


## 1. The Hacktivity 2010 story

In September 2010, Marcell Major presented
"Writing Your Own Password Cracker" at Hacktivity in Budapest.

The talk is a case study in what to do when no cracker exists for a hash:

1. Understand password hashing in general (password + salt -> hash,
   stored hash/salt, verification by recomputation).
2. Analyse a system where source code is available (Apache Derby; the
   talk found the `toHexByte()` flaw later tracked as CVE-2009-4269).
3. Analyse systems where only binaries are available (Sybase ASE), by
   live debugging and by off-line disassembly.
4. Turn the recovered algorithm into a working password cracker.
5. Discuss speed: CPU/SIMD, GPU/CUDA, FPGA/ASIC trade-offs.

For Sybase there were two hashes to recover:

- The **new** hash (ASE 15.0.2+), marketed as "SHA-256". This was found
  by live debugging: a memory breakpoint on a known SHA-256 constant
  led to the final hashing instructions and call stack. The official
  Sybase documentation described the format inaccurately; the real
  algorithm is the subject of `sybase_sha256.html` (section 5 below).

- The **old** hash, **SYB-PROP** (ASE <= 12.5 / 15.0.0 / 15.0.1), is the
  main subject of this README.

### How SYB-PROP was recovered

Old Sybase versions were not available, and ASE 15.0.5 did not allow
SYB-PROP for new passwords. The work-around was to downgrade a 15.0.5
installation to 15.0.0/15.0.1, where old hashes still appeared.

Debugging near the SHA-256 code found another call whose output was
64 bytes, of which the **last 28 bytes** became the stored old hash.
Off-line analysis with IDA (the binary still had symbols) reduced the
system to two functions:

```text
password -- meta_keysch() --> 64 bytes -- meta_encrypt() --> 64 bytes
                                                              |
                                                     last 28 bytes
                                                              |
                                                            hash
```

The block cipher inside was identified as **FEAL** (Fast Data
Encipherment Algorithm, NTT 1987, a DES replacement candidate built
on a Feistel network). The parameters matched **FEAL-8**:

- key: 8 bytes
- key schedule: 32 bytes (16 x 16-bit subkeys)
- block: 8 bytes
- rounds: 8

The plaintexts turned out to be slices of a joke string constant
embedded in the Sybase binary:

```text
Q:Whydidtheflydanceonthejar?A:Becausethelidsaidtwisttoopen.HaHa!
```

### The bug

Reconstruction from the published FEAL-8 specification (Bruce
Schneier, "Applied Cryptography"; Menezes/van Oorschot/Vanstone,
"Handbook of Applied Cryptography": Algorithm 7.94 for the cipher,
Algorithm 7.95 for its key schedule, Example 7.99 for test vectors)
did not match
Sybase: fixed key + fixed input gave different outputs, and only the
first 4 bytes of the key schedule agreed.

The cause: in FEAL's key processing, Sybase's implementation **omits
one update step**. In the classic reference C code the key schedule
keeps a state word `D` that must be replaced by `A` on every iteration
(`D = A;`). In Sybase that update never happens, so `D` stays 0
forever. In Handbook notation: `U(i-3)` is never updated and remains 0.

Effect, verified against the published FEAL-8 test vector
(key `0123456789ABCDEF`, plaintext `0000000000000000`):

```text
correct FEAL-8 (Handbook of Applied Cryptography, Ex. 7.99):
  ciphertext = ceef2c86f2490752

Sybase / PoC FEAL-8 (with //D = A; commented out):
  ciphertext = 7f5bd642206cb280

Restoring the single line D = A; makes the PoC output match the
specification exactly; removing it reproduces Sybase.
```

So SYB-PROP is not standard FEAL-8. It is a Sybase variant whose key
schedule diverges from the specification after the first 4 subkey
bytes. FEAL-8 was already considered broken by differential and
linear cryptanalysis; the Sybase deviation makes it additionally
incompatible with every conforming FEAL-8 implementation, which is
why the reconstruction initially failed.

Security lesson of the talk: reverse engineering a proprietary hash
is feasible, and "security by obscurity" does not protect it.

---

## 2. The French follow-up: NES Security Lab

On 14 June 2013, the NES Security Lab (Frank Benhamou and Gregory
Terrien) published, in French:

"Test de dureté des mots de passe sur des bases de données SYBASE
(SYB-PROP hash)" — password-strength testing on Sybase databases.

Original URL (now dead; nes.fr redirects to SERMA):
http://www.nes.fr/securitylab/?p=1128

Archived copy:
https://web.archive.org/web/20140925011512/http://www.nes.fr/securitylab/?p=1128

### What NES did

The context was a client engagement: a company (in a banking-like
environment) still ran many Sybase 12.5 databases for compatibility
and, after repeated audit findings about password policy, wanted a
tool to test password strength on those databases quickly and simply.

NES's article:

1. Starts from Marcell Major's Hacktivity 2010 slides, which it
   credits explicitly and repeatedly ("l'analyse entièrement
   réalisée par Marcel Majorr" [sic]), and uses the slides'
   screenshots.
2. Re-explains the Sybase password workflow and the two functions
   `meta_keysch()` and `meta_encrypt()`.
3. Recodes both functions in C, using a public FEAL-8 implementation
   found on the Internet.
4. Hits **the same problem** Major had hit: the recomputed hashes did
   not match hashes produced by a real Sybase database.
5. Applies Major's finding: Sybase made a mistake in FEAL-8 by
   omitting a step, so the public FEAL-8 source must be modified in
   `SetKey()` before it reproduces Sybase.
6. With that fix, recomputes SYB-PROP hashes from cleartext passwords
   and builds a small **John the Ripper module** for SYB-PROP
   (dictionary mode; modelled on Major's Sybase SHA-256 John module).
7. Publishes the complete source in an annex: `feal8.h`, `feal8.c`
   ("with the little special Sybase modification"), the SYB-PROP
   implementation itself, and the John module.

### From NES to John the Ripper

Dhiru Kholia took that material and integrated it into the public
John the Ripper "jumbo" source tree in November 2013. The header of
`SybasePROP_fmt_plug.c` says:

```text
All credits for reversing this algorithm go to Marcel Major, Frank
Benhamou and Gregory Terrien. Dhiru Kholia just glued together the
bits (as usual!).
```

and cites both the NES article and the Hacktivity archive.

So the provenance chain is:

```text
Marcell Major (Hacktivity 2010, SYB-PROP_PoC)
        |
        v
NES Security Lab (Benhamou / Terrien): recode + JtR module + article
        |
        v
Dhiru Kholia: integration into openwall/john (bleeding-jumbo)
        |
        v
Today: src/SybasePROP_fmt_plug.c + src/syb-prop_repro_plug.c
       + src/feal8_plug.c in the public John the Ripper repo
```

In other words, the John the Ripper SYB-PROP code is **not** a new,
independent implementation. It is Major's `syb-prop_repro.cpp` with
mechanical porting changes:

- the Windows/MSVC `srand()`/`rand()` dependency is replaced by an
  explicit reimplementation of the MSVC CRT generator
  (`seed = seed * 0x343FD + 0x269EC3`, returning
  `(seed >> 16) & 0x7FFF`), so the same salts are produced on Linux;
- FEAL global state is moved into a per-thread context struct so
  OpenMP cracking is thread-safe;
- functions are renamed (`feal_SetKey`, `feal_Encrypt`) and marked
  inline/static;
- JimF's May 2014 big-endian fix in `f()` (this PoC does not have
  it — see the portability note above);
- `EXPANDED_PWDLEN` is raised from 57 to 64 in `syb-prop_repro.h`
  (harmless: the extra padded bytes are never read).

The buggy key schedule is preserved on purpose: `feal8_plug.c` still
contains the line `//D = A ;` commented out. A "correct" FEAL-8 would
not crack a single real Sybase hash.

Usage after building John the Ripper from
https://github.com/openwall/john :

```text
john --format=Sybase-PROP hashes.txt
```

---

## 3. SYB-PROP, explained

SYB-PROP takes a cleartext password and a 1-byte seed and produces a
28-byte hash. The stored value is:

```text
stored = seed || 0x05 || hash(28 bytes)
         1 byte   1 byte

example: 0xd405c8a83114cf59fe510d92c7e90c37f2741e0a04f70af14d9bd8a21f46
          ^ ^ ^--------------------------------------------------^
          | |                    28-byte hash
          | +-- 0x05: "SYB-PROP" type indicator
          +---- seed byte (here 0xd4), input to srand()
```

At a high level, the password is first stretched into 64 bytes of
key material (`meta_keysch`), and that material is then used as a
series of FEAL-8 keys to encrypt the fixed joke string
(`meta_encrypt`). The hash is the tail of that encryption.

```text
                         SYB-PROP
                         ========

 password                seed (1 byte, stored with the hash)
    |                         |
    |                         +--> srand(seed) --+--> rand() salt bytes
    |                                              (one per round)
    v                                              |
 expand to 57 bytes,                               |
 pad with 0x1D                                     |
    |                                              |
    +------------+---------------------------------+
                 v
          meta_keysch()          builds 64 bytes of key material
                 |               in 8 blocks of 8 bytes:
                 |                 blocks 1-2: FEAL-8 encryptions
                 |                 blocks 3-8: salt-mixed blocks
                 v
          64 bytes: K1 K2 K3 K4 K5 K6 K7 K8   (8 bytes each)
                 |
                 v
          meta_encrypt()         encrypts the joke string in a
                 |               CBC-like chain, using K1..K8 in
                 |               turn as FEAL-8 keys
                 v
          64 bytes of ciphertext
                 |
                 +--> discard first 36 bytes, keep last 28 bytes
                 |
                 v
          hash (28 bytes)  --> stored as seed || 0x05 || hash
```

Verification (and cracking) is simply: take a candidate password,
recompute the above with the stored seed, compare the 28 bytes.

### Step 1: expand the password

The password is copied into a 57-byte buffer; the rest is filled
with the byte `0x1D`:

```text
"almafa4" -> 61 6c 6d 61 66 61 34 1d 1d 1d ... 1d   (57 bytes)
              a  l  m  a  f  a  4  ^^^^^^^^^^^^^^^^
                                   0x1D padding
```

Call this buffer XP (expanded password).

Caution: the PoC's `ccat_pad_repro()` copies `strlen(password)`
bytes into this 57-byte buffer with no length check, so it must
only be called with passwords of at most 57 bytes (real ASE
passwords are at most 30 characters). Passing a longer password
overflows the buffer. This limitation of the original
proof-of-concept code is documented here, not silently fixed, so
the code stays faithful to the published reproduction.

### Step 2: the seed and the pseudo-random salt bytes

The seed is a single byte, originally derived from the system time.
It is stored in clear in the hash (first byte), so it is not secret.

The code calls `srand(seed)` once, then draws one fresh byte per
round from the C library generator:

```text
salt_byte = (rand() >> 8) % 0xFF
```

Important reproduction detail: in the original PoC this is the
**Microsoft Visual C++** `rand()`. The John the Ripper port spells
that generator out explicitly so results are identical on any OS:

```text
state = state * 0x343FD + 0x269EC3
rand() = (state >> 16) & 0x7FFF
```

All "randomness" in SYB-PROP is therefore derived deterministically
from the single stored seed byte. There are only 256 possible seeds.

### Step 3: meta_keysch — build 64 bytes of key material

`meta_keysch` works in 8 blocks of 8 bytes and produces 64 bytes,
call them R1..R8. Two helper operations repeat:

**Salt mixing** (`syb_apply_salt_byte`): mixes one salt byte into an
8-byte input block. Note the quirk: byte 1 is the hub — bytes 2..7
are all XORed with byte 1, they are not chained one after another.

```text
input block:        p0   p1   p2   p3   p4   p5   p6   p7
salt byte:          s
                    |    |    |    |    |    |    |    |
out0 = s  XOR p0 ---+    |    |    |    |    |    |    |
out1 = out0 XOR p1 ------+----+----+----+----+----+---- (hub)
out_i = out1 XOR p_i            for i = 2..7
```

**XOR chaining** (`syb_XOR`): an 8-byte block is XORed byte-by-byte
with another 8-byte block taken from XP (or from a previous result).

Round by round:

```text
block 1:
  key   = MIX(salt1, XP[0..7])
  R1    = FEAL8_encrypt(key, joke[seed % 0x30 .. +7])

block 2:
  buf   = R1 XOR XP[1..8]
  key   = MIX(salt2, buf)
  R2    = FEAL8_encrypt(key, joke[seed % 0x30 + 1 .. +8])

blocks 3..8 (k = 3..8):
  buf   = R(k-1) XOR XP[(k-1)*8 - 7 .. ]   (next window of XP)
  Rk    = MIX(salt_k, buf)                  (no FEAL here:
                                             the mixed block itself
                                             is the result)
```

Only the first two blocks pass through FEAL-8; blocks 3..8 are just
the salt-mixed blocks. The joke slice used in blocks 1-2 starts at
offset `seed % 0x30` (0-47) inside the joke string, so the seed also
selects which part of the joke is encrypted.

### Step 4: FEAL-8 (Sybase variant)

FEAL-8 encrypts one 8-byte block under an 8-byte key:

```text
SetKey(key):   derive 16 subkeys (16 bits each) with the FK function
               *** Sybase variant: the D = A update is missing,
               *** so subkeys after the first 4 bytes differ from
               *** the published FEAL-8 specification
Encrypt(block): 8 Feistel rounds using the f function, with extra
               subkey XORs before the first and after the last round
Decrypt:       same structure, subkeys in reverse order
               (not used by SYB-PROP, which only encrypts)
```

Both `f` and `FK` are built from the byte functions
`S0(x,y) = ROT2(x + y)` and `S1(x,y) = ROT2(x + y + 1)`, where ROT2
is a 2-bit left rotation of a byte. The only non-linear operation in
FEAL is addition modulo 256 — one reason FEAL fell to cryptanalysis.

### Step 5: meta_encrypt — encrypt the joke, keep the tail

`meta_encrypt` takes the 64 bytes from `meta_keysch` as eight
consecutive FEAL-8 keys and encrypts the joke string block by block
in a CBC-like chain (each block is XORed with the previous
ciphertext before encryption):

```text
joke blocks:   J1        J2              J3                  J8
                |         |               |                   |
keys:          K1        K2              K3                  K8
                v         v               v                   v
C1 = FEAL_K1(J1)
C2 = FEAL_K2(J2 XOR C1)
C3 = FEAL_K3(J3 XOR C2)
...
C8 = FEAL_K8(J8 XOR C7)

output = C1 C2 C3 C4 C5 C6 C7 C8        (64 bytes)
hash   = last 28 bytes of output        (tail of C5, plus C6..C8)
```

### Pseudocode

```text
function syb_prop(password, seed):
    XP = password padded with 0x1D to 57 bytes
    srand(seed)                                   # MSVC CRT rand
    meta = meta_keysch(seed, XP)                  # 64 bytes, sec. 3
    out  = meta_encrypt(meta)                     # 64 bytes, sec. 5
    return out[36..63]                            # last 28 bytes

stored value = seed || 0x05 || syb_prop(password, seed)
```

### Why SYB-PROP is weak

- FEAL-8 itself is cryptanalytically broken (differential/linear
  attacks), independent of the Sybase bug.
- The Sybase key-schedule bug deviates further from the designed
  cipher.
- The seed is 1 byte, stored in clear: only 256 variants, and every
  per-round "salt" byte is a deterministic function of it.
- It is a single fast pass: no iteration count, no real work factor.
  The John the Ripper module benchmarks in the hundreds of thousands
  of candidates per second per core.
- Identical passwords with the same seed always give identical
  hashes, and passwords are effectively processed through an 8-byte
  block structure over a 57-byte expanded buffer.

---

## 4. Which John the Ripper module cracks which hash

- SYB-PROP (this README, ASE < 15.0.2, `seed || 0x05 || hash`):
  https://github.com/openwall/john/blob/bleeding-jumbo/src/SybasePROP_fmt_plug.c
  Supporting files in the same directory: `syb-prop_repro_plug.c`,
  `syb-prop_repro.h`, `feal8_plug.c`, `feal8.h`.
  Run: `john --format=Sybase-PROP hashes.txt`

- SHA-256-based ASE hash (ASE >= 15.0.2, `0xc007 || salt || hash`,
  next section):
  https://github.com/openwall/john/blob/bleeding-jumbo/src/SybaseASE_fmt_plug.c
  Run: `john --format=SybaseASE hashes.txt`

Both live in the public repo https://github.com/openwall/john
(`bleeding-jumbo` branch, `src/` directory).

---

## 5. The other Sybase hash: the SHA-256 format in sybase_sha256.html

`sybase_sha256.html` (by Laszlo Toth and Marcell Major) describes the
hash that replaced SYB-PROP. It is a different algorithm — do not
confuse the two:

```text
SYB-PROP:   ASE < 15.0.2    stored: seed(1) || 0x05 || hash(28)
SHA-256:    ASE >= 15.0.2   stored: 0xc007 || salt(8) || hash(32)
```

Context from the article: ASE before 15.0.2 stored passwords with
SYB-PROP in the `syslogins` table. From 15.0.2 a SHA-256-based format
is used, but old SYB-PROP hashes can still be accepted in newer
versions unless the "allow password downgrade" configuration
parameter is set to zero. The Sybase System Administration Guide
described the new format at a high level, but following the guide
literally does not reproduce the stored hashes; the article gives
the corrected, byte-exact algorithm.

### The algorithm

For a password such as `test12`:

```text
1. Convert the password to UTF-16 big-endian
      "test12" -> 00 74 00 65 00 73 00 74 00 31 00 32
                     t     e     s     t     1     2

2. Append zero bytes until the buffer is 510 bytes long
      buffer = UTF-16BE(password) || 00 00 00 ...        (510 bytes)

3. Append the 8-byte salt  ->  518 bytes total
      buffer = [510 bytes above] || salt(8 bytes)

4. hash = SHA-256(buffer)                               (32 bytes)

5. Store:  0xc007 || salt(8 bytes) || hash(32 bytes)
```

Diagram:

```text
 password
    |
    v
 UTF-16BE encoding
    |
    v
 +--------------------------------------------------+----------+
 | password bytes, zero-padded to 510 bytes         | salt (8) |
 +--------------------------------------------------+----------+
    |                                                    518 bytes
    v
 SHA-256
    |
    v
 hash (32 bytes)

 stored in syslogins:
 +--------+---------------+------------------------------------+
 | 0xc007 | salt (8)      | hash (32)                          |
 | 2 bytes|               |                                    |
 +--------+---------------+------------------------------------+
```

### Worked example from the article

```text
password:  test12
salt:      4f9cc8c0d55d9803
SHA-256:   b0c0816e127f2a56ee080230af5b4ce3da1f3d9fcc5449fcfcf3fb
           9595eb8ea6
stored:    0xc0074f9cc8c0d55d9803b0c0816e127f2a56ee080230af5b4ce3
           da1f3d9fcc5449fcfcf3fb9595eb8ea6
             ^^^^ ^---------------^ ^---------------------------^
             c007 salt             SHA-256 of the 518-byte buffer
```

Notes:

- The two constant bytes `0xc007` mark this format, just as `0x05`
  in the second stored byte marks SYB-PROP.
- The salt is 8 real random bytes stored in clear next to the hash;
  unlike SYB-PROP's 1-byte seed, it is not expanded into the password
  by a PRNG — it is simply appended after the zero padding.
- The padding target (510 bytes) and the total input length
  (518 bytes) are the details the official guide got wrong or left
  ambiguous; getting them byte-exact is what makes reproduction work.
- Verification/cracking: rebuild the 518-byte buffer for a candidate
  password with the stored salt, run SHA-256, compare 32 bytes.

### Crackers for this format

- Major's original proof-of-concept cracker for this format was
  `sybcrack` (dictionary and brute-force modes, multithreaded with
  pthreads, SHA-256 from OpenSSL; based on Laszlo Toth's
  `woraauthbf`). It is not included in this repository; the
  maintained equivalent is the John the Ripper module below.
- In John the Ripper this format is `SybaseASE`:
  https://github.com/openwall/john/blob/bleeding-jumbo/src/SybaseASE_fmt_plug.c
  Run: `john --format=SybaseASE hashes.txt`

Weaknesses, for completeness: a single SHA-256 pass with an 8-byte
salt is fast and has no work factor, so it is also cheap to brute
force by modern standards — it is a plain hash, not a password KDF.

---

## 6. References

Plain URLs:

- This directory's presentation:
  Hacktivity2010_WritingOwnPasswordCracker.pdf (local file)
- NES Security Lab article (archived):
  https://web.archive.org/web/20140925011512/http://www.nes.fr/securitylab/?p=1128
- NES article, original (dead):
  http://www.nes.fr/securitylab/?p=1128
- John the Ripper repository:
  https://github.com/openwall/john
- John the Ripper, SYB-PROP module:
  https://github.com/openwall/john/blob/bleeding-jumbo/src/SybasePROP_fmt_plug.c
- John the Ripper, Sybase ASE (SHA-256) module:
  https://github.com/openwall/john/blob/bleeding-jumbo/src/SybaseASE_fmt_plug.c
- John the Ripper, supporting SYB-PROP code:
  https://github.com/openwall/john/blob/bleeding-jumbo/src/syb-prop_repro_plug.c
  https://github.com/openwall/john/blob/bleeding-jumbo/src/feal8_plug.c
- Handbook of Applied Cryptography, FEAL (Algorithm 7.94/7.95,
  test vectors in Example 7.99):
  https://ebrary.net/134522/computer_science/feal

Files in this repository: `SYB-PROP_PoC/` (Major's SYB-PROP
reproduction, section 3) and `sybase_sha256.html` (Toth & Major,
SHA-256 format, section 5).

---

## 7. Scope and caution

This material documents a historic, publicly presented reverse
engineering result for obsolete Sybase password formats. It is kept
for research, audit and password-strength testing of systems you own
or are authorised to test. Sybase ASE 12.5 / 15.0.x and both hash
formats described here are long obsolete; do not rely on either of
them to protect anything today.
