
---

## İlk İnceleme



Programı ilk olarak PowerShell üzerinden doğrudan çalıştırdığımda şu ekranla karşılaştım:

```text
Hold on, getting ready...
You have 10 seconds between keystrokes to enter the password: 
```


IDA programın fonksiyonlarını incelediğimde program girdiyi metin akışından değil, doğrudan ReadConsoleInputW ile alıyordu.

 ![[Pasted image 20261002142654.png]]
  
Ardından bu tanıtıcıyı (`hObject`) kullanan çağıran fonksiyonları inceledim:
   * `sub_140134000`: `PeekConsoleInputA(hObject, ...)` çağırarak bekleyen tuş olayını denetliyordu (`_kbhit`).
   * ![[Pasted image 20261002142722.png]]
   * `sub_14013408C`: `ReadConsoleInputW(hObject, ...)` çağırarak doğrudan fiziksel tuş paketini okuyordu (`_getch`).
   * ![[Pasted image 20261002142801.png]]


10 karakterlik parolalarla denemeler yaparken programın `sub_14009A860` konteyner ayrıştırıcısına, oradan XChaCha20-Poly1305 (`sub_140121360`), Ed25519 ve SHA-256 (`sub_140098470`) gibi ağır kriptografik fonksiyonlara daldığını frida ile görmüştüm.

### Kripto Labirentinin Tespiti: 

10 karakterlik bir parola verildiğinde programın arka planda hangi kripto fonksiyonlarını tetiklediğini dinamik olarak kanıtlamak için `crack_dynamic.py` scriptini yapay zekaya yazdırdım.



* **Script Çıktısı 
  ```text
  [*] Spawned PID, feeding password: 'AAAAAAAAAA'
    [INPUT] char='A' idx=1 ... idx=10
    [XXH3] input len=10 hex=41414141414141414141 -> result=0x5c7b39...
    [SHA256] input len=8 -> output=59df2c01... (32 baytlık türetilmiş anahtar)
    [XCHACHA] ciphertext_len=5472 key_len=32 key=59df2c01...
    [XCHACHA] ret=-1 (FAIL)
    [OUTPUT] Incorrect password
  ```
 
Yani  Program 10 karakterlik parolayı alıyor, `XXH3` ve `SHA-256` ile karmaşık bir anahtar türetiyor (Key Derivation) ve bu anahtarla binary içerisine gömülü 5472 baytlık devasa bir şifreli paketi (`XChaCha20-Poly1305`) açmayı deniyordu. Anahtar uyuşmayınca `ret = -1 (FAIL)` dönüyor ve hata mesajı basılıyordu. 


Bu kripto labirentinin nereden tetiklendiğini bulmak için kontrol akışının başladığı `0x140079BFE` adresindeki dallanmayı incelediğimde bir şey farkettim.

Programın `0x140079BF9` adresinde `0xA2` çöp baytı var ve IDA bu çöp baytı `mov ds:10798348CE21A07Bh, al` olarak yanlış yorumlamaktadır. Bu byte ı noplayıp (0x90) ile değiştirip adresi U tuşu ile çözülüp C tuşuna basıldığında gerçek yönerge açığa çıkıyor
![[Pasted image 20261002143533.png]]



* C++ MSVC derleyicisinde bir `std::string` nesnesinde `[rcx + 10h]` ofseti stringin karakter sayısını tutuyormuş. bunu chatgpt ile derin sohbetlerim esnasında öğrendim.
* Eğer parola 5 karakterden farklıysa jz atlaması gerçekleşmiyor; program XChaCha20/SHA256 kripto labirentine giriyordu.
* Fakat parola **tam 5 karakter** girildiğinde, `jz` koşulu sağlanıyor; program tüm bu kriptografik labirenti atlayıp doğrudan `0x14007A012` adreine gidiyordu

### İnputun İzlenmesi: 

5 karakterlik girdi verildiğinde oluşan istisnaları ve registerları görmek için `test_5char_trace.py` scriptini yazdırdım:

* **Ne İşe Yarar?**  
  5 karakterlik bir parola verildiğinde (`AAAAA\r`) programın kripto labirentini atlayıp doğrudan dahili doğrulayıcıya girdiğini kanıtlar. Frida ile `sub_140085BA0` VEH fonksiyonuna kanca atar, `~a1` bitwise NOT maskesini kaldırarak `PCONTEXT` yapısını okur ve tetiklenen istisnalardaki `RIP` ile CPU yazmaçlarını adım adım kaydeder.

* **Script Çıktısı:**
  ```text
  [*] Prompt detected! Feeding 5-char password 'AAAAA\r'...
  [*] Fed 5 keys!
  [CHECKING]
    [STEP #001] RIP=0x7a26d rax=0x41 rcx=0x0 rdx=0x2159ada0000 rbx=0x0
    [STEP #002] RIP=0x7a280 rax=0x28a rcx=0x145 rdx=0x2159ada0000 rbx=0x0
    [STEP #003] RIP=0x7a288 rax=0x2bb rcx=0x145 rdx=0x2159ada0000 rbx=0x0
    [STEP #004] RIP=0x7a438 rax=0x0 rcx=0x0 rdx=0x2159ada0000 rbx=0x0
  [*] Process exited with code 4294967295
  ```

Bu çıktı, 5 karakterde akışın doğrudan `0x7A260`'taki dahili doğrulayıcıya girdiğini ve karşılaştırma uyuşmayınca `0x7A438` hata bloğuna sıçradığını kesinleştirdi. Böylece asıl hedef doğrulama kodunun `0x7A000` bölgesi olduğunu tespit ettim.

---

## İstisna Tabanlı Sanal Makinenin (VEH) Çözülmesi

5 karakterlik kontrol koduna girdiğimde kodun içinde `0x3F`, `0x60`, `0x1F`, `0xD4` gibi geçersiz x64 opcode'ları yer aldığını gördüm. Normal şartlarda bu komutlar programı çökertecekken program akmaya devam ediyordu.

### VEH Trambolini (`sub_140085BA0`):
Program başlangıcında `AddVectoredExceptionHandler` ile kaydedilen istisna yöneticisini (`sub_140085BA0`) incelediğimde bir trambolin keşfettim:
![[Pasted image 20261002144216.png]]
v13 = ~a1; // PEXCEPTION_POINTERS parametresi NOT (~a1) işlemiyle ters çevrilmiş!

#### PCONTEXT` Yapısı Nedir ?
Windows işletim sisteminde bir program çalışırken beklenmedik bir exception)meydana geldiğinde (örneğin CPU geçersiz bir opcode ile karşılaştığında `0xC000001D`), Windows çekirdeği o iş parçacığınıdondurur.

Dondurduğu anda işlemcinin (CPU) tüm durumunu bir C yapısına kaydeder. İşte bu yapıya Windows SDK'da **`CONTEXT`**, bunun işaretçisine (pointer) ise **`PCONTEXT`** (`typedef CONTEXT *PCONTEXT;`) denir. Bu yapının içinde:
* `pCtx->Rip`: İstisna anında çalışan komutun tam bellek adresi.
* `pCtx->Rax, Rbx, Rcx, Rdx...`: O anki tüm veri yazmaçları.
* `pCtx->Rsp`: Yığının (stack) o anki adresi.
* `pCtx->EFlags`: Karşılaştırma ve durum bayrakları (Zero Flag, Carry Flag vb.) yer alır.

Bu crackme'de sanal makine doğrudan bu yapının alanlarını değiştirerek `pCtx->Rax` değerine `100` ekleyip `pCtx->Rip` değerini bir sonraki geçerli komuta atlatarak gerçekleştirilir.

#### 2. `bitwise NOT` (~a1) Maskesi ve Kurulan Tuzak:
Normal bir Windows VEH fonksiyonunda ilk parametre (`a1`) doğrudan geçerli bir `PEXCEPTION_POINTERS` işaretçisidir. Ancak bu exe de bu parametreyi bitwise NOT (`~`) işlemiyle ters çevirmiştir.
Ida ilk parametreyi (`a1`) `PEXCEPTION_POINTERS` yapısı olarak tanıyamaz. `v13 = ~a1` gibi anlamsız bir işlem gördüğü için altındaki `*(v13 + 8)` yapısını sıradan bir matematik hesabı sanır ve tüm struct çözümlemesini bozar.



## std::map Keşfi ve Bellekten Taranması: 

VEH fonksiyonunu (`sub_140085BA0`) incelediğimde, programın illegal opcode ile her çöküşünde `pCtx->Rip` adresini alıp `.data` bölümündeki **`0x140162AE0`** göstericisi üzerinde bir arama (`while (!node->is_nil)`) döngüsüne soktuğunu gördüm.

### Red-Black Tree (`std::map`) Nedir?
C++ derleyicilerinde (MSVC), `std::map<Key, Value>` arka planda dengeli bir binary arama ağacı olarak derlenir. Düğüm yapısı şöyledir:
* `node + 0x00`: `_Left` 
* `node + 0x08`: `_Parent` 
* `node + 0x10`: `_Right` 
* `node + 0x18`: `_Color` 
* `node + 0x19`: `_Isnil` 
* `node + 0x20`: **Key** (Arama Anahtarı $\to$ `pCtx->Rip` adresi)
* `node + 0x28`: **Value** (Gizlenmiş gerçek komut verisi göstericisi)

### Ağacın Taranması: `dump_vm_tree.py`
Ağaç heap üzerinde dinamik oluşturulduğu için içinde kaç eleman olduğunu ve hangi komutları barındırdığını öğrenmek amacıyla `dump_vm_tree.py` betiğini yazdırdım:

  `0x140162AE0` adresindeki kök düğümden başlayarak ağacın tüm düğümlerini bellekten dolaşır ve düğüm verilerini `vm_tree_dump.json` dosyasına döker.

* **Betik Çıktısı:**
  ```text
  [+] Total VM Nodes in Tree: 1638
  [+] Saved to vm_tree_dump.json
    RIP=0x7a0c5    data=c5 a0 07 40 01 00 00 00 | val=80 d5 5b 90 f7 7f 00 00
    RIP=0x7a0d1    data=d1 a0 07 40 01 00 00 00 | val=c0 d5 5b 90 f7 7f 00 00
    RIP=0x7a0f2    data=f2 a0 07 40 01 00 00 00 | val=00 d6 5b 90 f7 7f 00 00
    RIP=0x7a0fc    data=fc a0 07 40 01 00 00 00 | val=40 d6 5b 90 f7 7f 00 00
    RIP=0x7a11b    data=1b a1 07 40 01 00 00 00 | val=80 d6 5b 90 f7 7f 00 00
    RIP=0x7a129    data=29 a1 07 40 01 00 00 00 | val=c0 d6 5b 90 f7 7f 00 00
    RIP=0x7a148    data=48 a1 07 40 01 00 00 00 | val=00 d7 5b 90 f7 7f 00 00
    RIP=0x7a152    data=52 a1 07 40 01 00 00 00 | val=40 d7 5b 90 f7 7f 00 00
    RIP=0x7a280    data=80 a2 07 40 01 00 00 00 | val=80 d7 5b 90 f7 7f 00 00
    RIP=0x7a288    data=88 a2 07 40 01 00 00 00 | val=c0 d7 5b 90 f7 7f 00 00
  ```

Böylece programın içinde tam **1638 adet** sahte çökme noktası ve bunlara karşılık gelen 1638 adet gizli işlem yerleştirildiğini keşfettim.

---

## Sanal Makineden Gerçek Opcode ve Sabitlerin Kurtarılması: 

`vm_tree_dump.json` dosyasında doğrulayıcı aralığındaki (`0x7A000` - `0x7A450`) düğümlerin işaret ettiği gerçek x64 baytlarını bellekten çekmek ve disasm etmek için `dump_real_opcodes.py` scriptini yazdırdım:


  Sanal makine düğümlerinin işaret ettiği ham baytları bellekten okur, Capstone ile disasm ederek illegal baytların arkasına gizlenmiş gerçek `ADD` ve `CMP` işlemlerini çıkarır.

* **Betik Çıktısı:**
  ```text
  RIP=0x7a280  raw=[48 83 c0 64]        disasm: add rax, 0x64;       (+100)
  RIP=0x7a288  raw=[48 3d fb 03 00 00]  disasm: cmp rax, 0x3fb;      (== 1019)
  RIP=0x7a148  raw=[48 05 c8 00 00 00]  disasm: add rax, 0xc8;       (+200)
  RIP=0x7a152  raw=[48 3d f7 04 00 00]  disasm: cmp rax, 0x4f7;      (== 1271)
  RIP=0x7a11b  raw=[48 81 c1 2c 01 00]  disasm: add rcx, 0x12c;      (+300)
  RIP=0x7a129  raw=[48 81 f9 37 04 00]  disasm: cmp rcx, 0x437;      (== 1079)
  RIP=0x7a0f2  raw=[48 05 90 01 00 00]  disasm: add rax, 0x190;      (+400)
  RIP=0x7a0fc  raw=[48 3d b6 03 00 00]  disasm: cmp rax, 0x3b6;      (== 950)
  RIP=0x7a0c5  raw=[48 05 f4 01 00 00]  disasm: add rax, 0x1f4;      (+500)
  RIP=0x7a0d1  raw=[48 3d 91 00 00 00]  disasm: cmp rax, 0x91;       (== 145)
  ```

Böylece sanal makineneye gizlenen toplama sabitleri ($+100, +200, +300, +400, +500$) ve karşılaştırma sayıları ($1019, 1271, 1079, 950, 145$) kurtarıldı.

---

## Kodun Kurtarılması ve Matematiksel Doğrulama Modelinin Çözülmesi

Sanal makineden toplama ($+100 \dots +500$) ve karşılaştırma ($1019 \dots 145$) işlemlerini kurtarmıştık; fakat parolanın 5 karakterinin bu sayılarla nasıl işlendiği (çarpma, XOR vb.) halen PE dosyasının içindeydi.

test_5char_trace.py scripti ile parolanın matematiksel olarak doğrulandığı yerin **`0x7A015` ile `0x7A7B4`** aralığı olduğunu zaten görmüştük. Ida ile analiz etmeye ne kadar çalışsamda hiçbir şekilde başaramadım. Bende o adres aralığıın dump ını aldım ve sonunda.bin olarak kaydettim. Daha sonra trace_character_math.py scripti ile Capstone Engine disassembler kullanarak matematiksel işlemleri kurtaran bir script yazdırdım.



* **Script Çıktısı:**
  ```text
  =================== c4 (index 4) (0x14007A0B9) ===================
    0x14007A0BA: 488d0c40         lea      rcx, [rax + rax*2]
    0x14007A0BE: 488d0449         lea      rax, [rcx + rcx]       ; * 6
    0x14007A0CB: 48351f040000     xor      rax, 0x41f

  =================== c3 (index 3) (0x14007A0E9) ===================
    0x14007A0EB: 486bc007         imul     rax, rax, 7            ; * 7
    0x14007A0F8: 4883f049         xor      rax, 0x49

  =================== c2 (index 2) (0x14007A111) ===================
    0x14007A113: 48c1e003         shl      rax, 3                 ; * 8
    0x14007A122: 4881f1d3000000   xor      rcx, 0xd3

  =================== c1 (index 1) (0x14007A13F) ===================
    0x14007A141: 488d04c0         lea      rax, [rax + rax*8]     ; * 9
    0x14007A14E: 4883f058         xor      rax, 0x58

  =================== c0 (index 0) (0x14007A275) ===================
    0x14007A277: 488d0c80         lea      rcx, [rax + rax*4]
    0x14007A27B: 488d0449         lea      rax, [rcx + rcx]       ; * 10
    0x14007A284: 4883f031         xor      rax, 0x31
  ```

### Denklemlerin Tersine Çevrilmesi:


* **Karakter 0 (`c[0]`):**
  $$((c_0 \times 10) + 100) \oplus 0x31 = 1019 \implies 1019 \oplus 0x31 = 970 \implies c_0 = \frac{970 - 100}{10} = 87 \implies \mathbf{'W'}$$

* **Karakter 1 (`c[1]`):**
  $$((c_1 \times 9) + 200) \oplus 0x58 = 1271 \implies 1271 \oplus 0x58 = 1199 \implies c_1 = \frac{1199 - 200}{9} = 111 \implies \mathbf{'o'}$$

* **Karakter 2 (`c[2]`):**
  $$((c_2 \times 8) + 300) \oplus 0xD3 = 1079 \implies 1079 \oplus 0xD3 = 1252 \implies c_2 = \frac{1252 - 300}{8} = 119 \implies \mathbf{'w'}$$

* **Karakter 3 (`c[3]`):**
  $$((c_3 \times 7) + 400) \oplus 0x49 = 950 \implies 950 \oplus 0x49 = 1023 \implies c_3 = \frac{1023 - 400}{7} = 89 \implies \mathbf{'Y'}$$

* **Karakter 4 (`c[4]`):**
  $$((c_4 \times 6) + 500) \oplus 0x41F = 145 \implies 145 \oplus 0x41F = 1166 \implies c_4 = \frac{1166 - 500}{6} = 111 \implies \mathbf{'o'}$$

---
Ve şifre WowYo
![[Pasted image 20261002150424.png]]