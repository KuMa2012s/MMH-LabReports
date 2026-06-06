# Lab 1 Report Guide - Symmetric Encryption with Crypto++

## 1. Muc tieu va yeu cau cham diem

Lab 1 can chung minh ban co the dung Crypto++ de xay dung mot CLI tool ma hoa doi xung an toan, co kiem thu dung vector chuan, co chan cac cach dung sai, va co benchmark nghiem tuc.

Trong bao cao, can bam cac nhom diem:

| Hang muc | Diem | Can the hien trong bao cao |
| --- | ---: | --- |
| Correctness & KATs | 25 | Ket qua NIST SP 800-38A, GCM, CCM; bang PASS/FAIL |
| Security hygiene | 15 | IV/nonce, AEAD tag, fail-closed, ECB warning, nonce reuse |
| UX & I/O design | 10 | CLI usage, file/text input, hex/base64/raw output |
| Performance methodology | 20 | Bang benchmark, mean/median/stddev/95% CI, bieu do |
| Cross-platform build | 10 | Windows + Linux build log/screenshot |
| Report quality | 20 | Giai thich thiet ke, phan tich bao mat, bai hoc |

## 2. Cau truc project nen co

Nen to chuc folder nhu sau:

```text
Lab01/
  CMakeLists.txt
  README.md
  src/
    main.cpp
    cli.cpp
    aes_tool.cpp
    encoding.cpp
    file_io.cpp
    nonce_registry.cpp
  include/
    cli.hpp
    aes_tool.hpp
    encoding.hpp
    file_io.hpp
    nonce_registry.hpp
  tests/
    CMakeLists.txt
    test_aes.cpp
    test_negative.cpp
  vectors/
    nist_38a.json
    nist_gcm.json
    nist_ccm.json
  benchmarks/
    bench_aes.cpp
    results_windows.csv
    results_linux.csv
  docs/
    Lab01_Report.docx or Lab01_Report.pdf
    images/
      cli_encrypt_gcm.png
      kat_pass_summary.png
      negative_tests.png
      benchmark_throughput.png
      benchmark_latency.png
      windows_build.png
      linux_build.png
```

## 3. Chuc nang phai lam trong tool

Ten tool de xuat: `aestool`.

Lenh toi thieu:

```bash
aestool encrypt --mode gcm --key key.bin --in msg.txt --out ct.bin
aestool decrypt --mode gcm --key key.bin --in ct.bin --out msg.dec.txt
aestool encrypt --mode cbc --key-hex <hex> --iv <ivfile> --in msg.bin --out ct.bin
aestool --kat vectors/nist_38a.json
aestool bench --mode gcm --size 1048576 --runs 30
```

Mode bat buoc:

| Mode | Loai | IV/nonce | Can luu y |
| --- | --- | --- | --- |
| ECB | Block | Khong | In WARNING, chan file > 16 KiB neu khong co `--allow-ecb` |
| CBC | Block | 16 byte IV | Can padding, khong co integrity |
| OFB | Stream-like | 16 byte IV | Khong can padding |
| CFB | Stream-like | 16 byte IV | Khong can padding |
| CTR | Stream | 16 byte nonce/counter | Cam nonce reuse cung key |
| XTS | Disk mode | tweak/sector | Khong co integrity |
| CCM | AEAD | nonce dung do dai hop le | Co AAD, tag verification |
| GCM | AEAD | nen 12 byte nonce | Co AAD, tag verification |

## 4. Misuse prevention can the hien

Can viet ro tool da chan cac loi dung sai sau:

| Loi dung sai | Cach xu ly mong muon |
| --- | --- |
| Chon ECB | In canh bao ro rang |
| ECB voi file > 16 KiB | Tu choi, tru khi co `--allow-ecb` |
| IV sai do dai | Tu choi encrypt/decrypt |
| Thieu IV/nonce | Tu sinh bang `CryptoPP::AutoSeededRandomPool` |
| CTR/GCM/CCM dung lai key + nonce | Tu choi encrypt |
| AEAD tag sai | Khong ghi plaintext, tra loi loi fail-closed |
| Input malformed | Khong crash, khong xuat du lieu nguy hiem |

De don gian hoa bao cao, nen dung sidecar JSON cho moi ciphertext:

```json
{
  "alg": "AES-256-GCM",
  "mode": "gcm",
  "key_id": "sha256(key)",
  "nonce": "hex...",
  "aad": "hex...",
  "tag": "hex..."
}
```

Luu y: `key_id` khong nen la key that; chi nen la hash/fingerprint de phat hien reuse.

## 5. Test va bang can dua vao bao cao

### 5.1 Known Answer Tests

Can co bang:

| Test suite | Mode | So test | Ket qua |
| --- | --- | ---: | --- |
| NIST SP 800-38A | CBC | n | PASS |
| NIST SP 800-38A | CFB | n | PASS |
| NIST SP 800-38A | OFB | n | PASS |
| NIST SP 800-38A | CTR | n | PASS |
| NIST GCM | GCM | n | PASS |
| NIST CCM | CCM | n | PASS |

Anh nen chup:

- Man hinh chay `aestool --kat vectors/nist_38a.json`
- Man hinh tong ket PASS/FAIL
- Neu co `ctest`, chup `100% tests passed`

### 5.2 Negative tests

Can co bang:

| Test | Ket qua mong doi | Ket qua thuc te |
| --- | --- | --- |
| Sai key khi decrypt GCM | Authentication failed, khong tao plaintext | PASS |
| Sua ciphertext GCM | Authentication failed | PASS |
| Sua tag GCM/CCM | Decryption refused | PASS |
| Sai IV length | Reject input | PASS |
| Sua ciphertext CBC | Plaintext hong, khong phat hien duoc | PASS |
| Nonce reuse GCM | Reject encryption | PASS |

Anh nen chup:

- Loi tag verification failed
- Loi invalid IV length
- Loi nonce reuse detected

## 6. Benchmark can lam

Payload sizes bat buoc:

```text
1 KB, 4 KB, 16 KB, 256 KB, 1 MB, 8 MB
```

Mode nen benchmark:

```text
ECB, CBC, CFB, OFB, CTR, GCM, CCM, XTS
```

Thong ke can tinh:

```text
mean, median, standard deviation, 95% confidence interval
throughput MB/s, latency ms/op
```

Bang mau:

| OS | Mode | Size | Mean MB/s | Median MB/s | StdDev | 95% CI | Latency ms/op |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Windows 11 | GCM | 1 MB | ... | ... | ... | ... | ... |
| Ubuntu LTS | GCM | 1 MB | ... | ... | ... | ... | ... |

Bieu do nen dua vao:

- Throughput theo payload size cho tat ca mode
- Latency theo payload size
- So sanh AEAD vs non-AEAD
- So sanh Windows vs Linux neu co
- Tag overhead cua GCM/CCM

## 7. Khung bao cao de viet

### 1. Objective

Viet ngan gon: Lab 1 xay dung `aestool` bang Crypto++, ho tro AES modes, AEAD, IV/nonce handling, KAT, negative tests va benchmark.

### 2. Environment

Bang can co:

| Item | Windows | Linux |
| --- | --- | --- |
| OS | Windows 10/11 | Ubuntu LTS |
| CPU | ... | ... |
| RAM | ... | ... |
| Compiler | MSVC/MinGW | GCC/Clang |
| Crypto++ version | ... | ... |
| CMake version | ... | ... |

Anh nen chup:

- `cmake --build .` thanh cong tren Windows
- `cmake --build .` thanh cong tren Linux

### 3. Design and Implementation

Nen trinh bay:

- CLI design va cac command chinh
- Cach doc input binary-safe va UTF-8 text
- Cach xu ly key tu `--key` va `--key-hex`
- Cach auto-generate IV/nonce
- Format sidecar JSON/header
- Cach AEAD tach ciphertext va tag
- Cach registry phat hien key + nonce reuse

Anh nen ve:

- So do pipeline: input -> key/iv validation -> Crypto++ filter -> output/header
- So do AEAD: plaintext + AAD -> ciphertext + tag; decrypt verify tag truoc khi ghi plaintext

### 4. Correctness Validation

Nen trinh bay:

- Nguon vector: NIST SP 800-38A, NIST GCM, NIST CCM
- Format JSON vector
- Ket qua PASS/FAIL
- Mot vi du vector voi key/iv/plaintext/ciphertext rut gon

### 5. Negative Testing

Nen trinh bay bang negative tests va giai thich fail-closed:

- AEAD fail thi khong ghi plaintext
- Non-AEAD khong phat hien tampering, day la gioi han bao mat cua mode
- IV length sai bi reject truoc khi goi Crypto++

### 6. Performance Evaluation

Nen trinh bay:

- Method: warm-up 1-2s, 1000 operations/block, lap N >= 30
- Metric: throughput, latency, mean/median/stddev/95% CI
- Bang ket qua va bieu do
- Nhan xet: GCM co overhead tag nhung co integrity; CTR/OFB/CFB la stream-like; CBC bi anh huong padding/serial dependency; OS scheduling va file I/O co the lam sai khac

### 7. Security Analysis

Bat buoc phan tich:

- Vi sao ECB lo pattern va khong nen dung
- CBC co padding oracle risk neu thong bao loi sai cach
- CTR nonce reuse gay two-time pad
- GCM bat buoc nonce unique
- CCM/GCM cung cap confidentiality + integrity
- XTS phu hop disk encryption nhung khong co integrity
- Key storage risk va gioi han cua implementation

### 8. Conclusion and Lessons Learned

Nen ket luan:

- AEAD nen la mac dinh an toan hon cho file encryption
- KAT giup xac minh dung thuat toan, negative tests giup xac minh an toan khi loi
- Benchmark can thong ke, khong chi chup mot lan
- Nonce lifecycle la phan quan trong nhat cua symmetric encryption engineering

### Appendix

Nen dua:

- CLI examples
- Build logs
- KAT summary
- Unit test output
- Self-grade rubric
- Academic integrity statement

## 8. Checklist truoc khi nop Lab 1

- [ ] Co `CMakeLists.txt`, build out-of-source duoc
- [ ] Co README huong dan Windows va Linux
- [ ] Ho tro day du AES modes: ECB, CBC, OFB, CFB, CTR, XTS, CCM, GCM
- [ ] Co `--key`, `--key-hex`, input file/text, output file/encoding
- [ ] Co AEAD AAD va tag verification
- [ ] Co auto-generate IV/nonce va sidecar/header
- [ ] Co chan ECB misuse va nonce reuse
- [ ] Co KAT runner JSON
- [ ] Co unit tests va negative tests
- [ ] Co benchmark day du payload sizes
- [ ] Co bang thong ke va bieu do
- [ ] Co anh build/test/CLI/benchmark trong report
- [ ] Co phan security analysis va limitations
- [ ] Co self-grade va academic integrity statement
