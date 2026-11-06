# Köprü

Türkiye hattında Discord masaüstü istemcisi için yerel köprü. VPN değildir. Trafiğin başka bir sunucuya gitmez, IP adresin gizlenmez.

İki şeyi dener:

1. **DNS.** İsimleri işletmeciye sormaz. Cloudflare ve Google DNS-over-HTTPS kullanır. İstersen Windows DNS’ini `1.1.1.1` yapar; eski adresler yedeklenir, tek tuşla geri gelir.
2. **TLS parçalama.** `127.0.0.1` üzerinde bir SOCKS5 açar, Discord’u `--proxy-server=socks5://127.0.0.1:1080` ile başlatır ve giden ClientHello’yu sunucu adının ortasından iki parçaya böler. Bazı hatlarda SNI filtresi tam adı göremez.

## Kurulum

[Baslat.bat](Baslat.bat) ve [Kopru.ps1](Kopru.ps1) aynı klasörde kalsın. `Baslat.bat` dosyasına çift tıkla.

DNS kutusunu kullanacaksan penceredeki **Yönetici olarak aç** yeterli. Köprünün kendisi yönetici istemez.

## Sınır

- Ses (RTC) UDP’dir. Sohbet düzelip mikrofon takılı kalabilir.
- Parçalama, paketleri çekirdekte bölen GoodbyeDPI / zapret kadar güçlü değildir. İşletmeci segmentleri birleştiriyorsa yetmeyebilir.
- Yetmezse obfuscation’lı bir VPN (trafik normal HTTPS gibi görünsün) hâlâ daha sağlam yoldur.
- Discord’a karşı kimliğini gizlemez. Hesabın yine senin hesabındır.

## Lisans

MIT
