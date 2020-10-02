# CSAW CTF Quals 2020 Writeup
## 心得
第一次寫線上CTF，只寫出一題水題+一題送分題，其他水題都差臨門一腳，看了writeup差點吐血，尤其是modus_operandi那題沒發現有binary的感覺真的好可惜，感覺就是嚴重經驗不足
原本想main web的題目，結果最後都在解crypto
下次線上賽的目標希望可以把web跟crypto的水題都刷完，為金盾賽做點準備
## web
### widthless
#### 題目:
Welcome to web! Let's start off with something kinda funky :)
http://web.chal.csaw.io:5018

#### 解法:
用F12查看html後找到這段註解:
```html
<!-- zwsp is fun! -->
```
查了一下zwsp是Zero width space，可以在網頁中藏東西
之後使用zwsp-steg這個node package來做解密
>https://github.com/offdev/zwsp-steg-js

code如下: (中間的空白是zwsp)
```javascript=
const ZwspSteg = require('zwsp-steg');
let decoded = ZwspSteg.decode('
    

​​​​‎‏‎​​​​‌‍‏​​​​‎‍‏​​​​‎‍‍​​​​‏‏​​​​​‏‎‌​​​​‎​‍​​​​‍‏‍​​​​‎​‎​​​​‌‏‎​​​​‎‍‎​​​​‏‏‍​​​​‍‏‏​​​​‏​‍​​​​‎​‍​​​​‍​‌​​​​‏‍‌​​​​‍‍‌​​​​‌‍‏');

console.log(decoded);
```
解完得到
>YWxtMHN0XzJfM3o=

看起來很像base64編碼，解碼後得到
>alm0st_2_3z

網頁有個輸入框，原本以為可以做sql之類的，結果是輸zwsp解密文字的
輸入alm0st_2_3z之後就會噴出
>/ahsdiufghawuflkaekdhjfaldshjfvbalerhjwfvblasdnjfbldf/<pwd>

通了半天想說那串英文是什麼加密還編碼，突然想通就是加到url上面，然後pwd就是alm0st_2_3z，也就是
>http://web.chal.csaw.io:5018/ahsdiufghawuflkaekdhjfaldshjfvbalerhjwfvblasdnjfbldf/alm0st_2_3z

這個網站也包含zwsp加密，但是把網站轉成txt後貼到我上面的code會無法解密，應該是一堆換行的關係，所以我就卡死了==

比賽完看了別人的writeup之後找到了正確的code
```python
import requests as req
import zwsp_steg

addr = 'http://web.chal.csaw.io:5018/ahsdiufghawuflkaekdhjfaldshjfvbalerhjwfvblasdnjfbldf/alm0st_2_3z'
r = req.get(addr).text
decoded = zwsp_steg.decode(r)
print(decoded)
```
解完會得到
>5f756e6831645f6d3

轉成ascii得到
>u_unh1d_m3

一樣輸到box裡面，噴出下面這行
>/19s2uirdjsxbh1iwudgxnjxcbwaiquew3gdi/<pwd1>/<pwd2>

同上加到url變成
>http://web.chal.csaw.io:5018/19s2uirdjsxbh1iwudgxnjxcbwaiquew3gdi/alm0st_2_3z/u_unh1d_m3

最後取得flag
>flag{gu3ss_u_f0und_m3}
## rev
### baby_mult
#### 題目:
Welcome to reversing! Prove your worth and get the flag from this neat little program!
>program.txt

打開長這樣:
>85, 72, 137, 229, 72, 131, 236, 24, 72, 199, 69, 248, 79, 0, 0, 0, 72, 184, 21, 79, 231, 75, 1, 0, 0, 0, 72, 137, 69, 240, 72, 199, 69, 232, 4, 0, 0, 0, 72, 199, 69, 224, 3, 0, 0, 0, 72, 199, 69, 216, 19, 0, 0, 0, 72, 199, 69, 208, 21, 1, 0, 0, 72, 184, 97, 91, 100, 75, 207, 119, 0, 0, 72, 137, 69, 200, 72, 199, 69, 192, 2, 0, 0, 0, 72, 199, 69, 184, 17, 0, 0, 0, 72, 199, 69, 176, 193, 33, 0, 0, 72, 199, 69, 168, 233, 101, 34, 24, 72, 199, 69, 160, 51, 8, 0, 0, 72, 199, 69, 152, 171, 10, 0, 0, 72, 199, 69, 144, 173, 170, 141, 0, 72, 139, 69, 248, 72, 15, 175, 69, 240, 72, 137, 69, 136, 72, 139, 69, 232, 72, 15, 175, 69, 224, 72, 15, 175, 69, 216, 72, 15, 175, 69, 208, 72, 15, 175, 69, 200, 72, 137, 69, 128, 72, 139, 69, 192, 72, 15, 175, 69, 184, 72, 15, 175, 69, 176, 72, 15, 175, 69, 168, 72, 137, 133, 120, 255, 255, 255, 72, 139, 69, 160, 72, 15, 175, 69, 152, 72, 15, 175, 69, 144, 72, 137, 133, 112, 255, 255, 255, 184, 0, 0, 0, 0, 201

判斷應該是machine code後轉成hex，然後試著用disassembler轉成組語，轉完之後發現有夠難看就卡死了==

比賽完看writeup發現跟shellcode一樣丟到c裡面去跑就好了，然後用gdb看stack就會找到flag
code如下:
```cpp
#include<stdio.h>
#include<string.h>

main()
{
  unsigned char code[] = "\x55\x48\x89\xe5\x48\x83\xec\x18\x48\xc7\x45\xf8\x4f\x00\x00\x00\x48\xb8\x15\x4f\xe7\x4b\x01\x00\x00\x00\x48\x89\x45\xf0\x48\xc7\x45\xe8\x04\x00\x00\x00\x48\xc7\x45\xe0\x03\x00\x00\x00\x48\xc7\x45\xd8\x13\x00\x00\x00\x48\xc7\x45\xd0\x15\x01\x00\x00\x48\xb8\x61\x5b\x64\x4b\xcf\x77\x00\x00\x48\x89\x45\xc8\x48\xc7\x45\xc0\x02\x00\x00\x00\x48\xc7\x45\xb8\x11\x00\x00\x00\x48\xc7\x45\xb0\xc1\x21\x00\x00\x48\xc7\x45\xa8\xe9\x65\x22\x18\x48\xc7\x45\xa0\x33\x08\x00\x00\x48\xc7\x45\x98\xab\x0a\x00\x00\x48\xc7\x45\x90\xad\xaa\x8d\x00\x48\x8b\x45\xf8\x48\x0f\xaf\x45\xf0\x48\x89\x45\x88\x48\x8b\x45\xe8\x48\x0f\xaf\x45\xe0\x48\x0f\xaf\x45\xd8\x48\x0f\xaf\x45\xd0\x48\x0f\xaf\x45\xc8\x48\x89\x45\x80\x48\x8b\x45\xc0\x48\x0f\xaf\x45\xb8\x48\x0f\xaf\x45\xb0\x48\x0f\xaf\x45\xa8\x48\x89\x85\x78\xff\xff\xff\x48\x8b\x45\xa0\x48\x0f\xaf\x45\x98\x48\x0f\xaf\x45\x90\x48\x89\x85\x70\xff\xff\xff\xb8\x00\x00\x00\x00\xc9";
  int (*ret)() = (int(*)())code;

  ret();
}
```
flag:
>flag{sup3r_v4l1d_pr0gr4m}
## crypto
### Perfect Secrecy
#### 題目：
Alice sent over a couple of images with sensitive information to Bob, encrypted with a pre-shared key. It is the most secure encryption scheme, theoretically...
image1.png image2.png
#### 解法：
上網爬下文就找到解法了
就是簡單把兩張圖做XOR
用下面的指令就可以得到藏起來的訊息
```
compare image1.png image2.png -compose src diff.png
```
圖片訊息中包含一段base64編碼：
>ZmxhZ3swbjNfdDFtM19QQGQhfQ==

解碼取得flag
>flag{0n3_t1m3_P@d!}

### modus_operandi
#### 題目
Can't play CSAW without your favorite block cipher!

nc crypto.chal.csaw.io 5001

#### 解法
連過去後會噴訊息叫你輸plaintext，輸完會噴ciphertext問你是用AES的ECB還是CBC加密的
因為會問很多次，我用pwntools寫了個腳本回問題
```python
from pwn import *
conn = remote('crypto.chal.csaw.io',5001)
for i in range(176):
    print(i)
    conn.recvuntil('Enter plaintext:')
    conn.sendline('abcdefghijklmnopabcdefghijklmnop')
    line = conn.recvuntil('?')
    cipher = line.decode('utf-8').split('\n')[1].replace('Ciphertext is:  ','')
    if cipher[0:32] == cipher[32:64]:
        conn.sendline('ECB')
    else:
        conn.sendline('CBC')
print(conn.recvall().decode('utf-8'))
```
原本以為最後會告訴你flag是什麼，沒想到回答完176次就結束了，然後我猜了半天還是沒想到怎麼做

看了writeup才發現flag就是你回答的東西，ECB是0，CBC是1
把得到的binary轉成ascii就會得到flag
>flag{ECB_re@lly_sUck$}

