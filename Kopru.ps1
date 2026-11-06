# Köprü 1.0 — Discord için yerel DNS + TLS köprüsü.
# VPN değildir. Trafiği başka sunucuya taşımaz, IP gizlemez.
# Windows PowerShell 5.1 ile çalışır. Baslat.bat üzerinden aç.

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$cs = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

public class KopruLog {
    static readonly object Gate = new object();
    static readonly Queue<string> Q = new Queue<string>();
    public static void Write(string s) {
        string line = DateTime.Now.ToString("HH:mm:ss") + "  " + s;
        lock (Gate) {
            Q.Enqueue(line);
            while (Q.Count > 500) Q.Dequeue();
        }
    }
    public static string[] Drain() {
        lock (Gate) {
            string[] a = Q.ToArray();
            Q.Clear();
            return a;
        }
    }
}

public class KopruEngine {
    class CacheItem { public IPAddress Ip; public DateTime Exp; }
    readonly object _cacheLock = new object();
    readonly Dictionary<string, CacheItem> _cache = new Dictionary<string, CacheItem>();
    readonly Dictionary<string, byte> _seen = new Dictionary<string, byte>();
    TcpListener _listener;
    int _active;

    public int Port { get; set; }
    public int SplitDelayMs { get; set; }
    public bool SplitSni { get; set; }
    public bool Listening { get; private set; }
    public int ActiveCount { get { return _active; } }

    public KopruEngine() {
        Port = 1080;
        SplitDelayMs = 40;
        SplitSni = true;
        try {
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072 | (SecurityProtocolType)768 | SecurityProtocolType.Tls;
        } catch { }
        ServicePointManager.Expect100Continue = false;
    }

    public string Start() {
        try {
            _listener = new TcpListener(IPAddress.Loopback, Port);
            _listener.Start();
            Listening = true;
            Thread t = new Thread(new ThreadStart(AcceptLoop));
            t.IsBackground = true;
            t.Start();
        KopruLog.Write("dinleniyor 127.0.0.1:" + Port + " (SOCKS5 + HTTP)");
            return null;
        } catch (Exception ex) {
            Listening = false;
            return ex.Message;
        }
    }

    public void Stop() {
        Listening = false;
        try { if (_listener != null) _listener.Stop(); } catch { }
        KopruLog.Write("durdu");
    }

    void AcceptLoop() {
        while (Listening) {
            TcpClient c = null;
            try { c = _listener.AcceptTcpClient(); }
            catch { if (!Listening) break; continue; }
            Thread t = new Thread(new ParameterizedThreadStart(Handle));
            t.IsBackground = true;
            t.Start(c);
        }
    }

    [System.Runtime.InteropServices.DllImport("wininet.dll", SetLastError = true)]
    static extern bool InternetSetOption(System.IntPtr hInternet, int dwOption, System.IntPtr lpBuffer, int dwBufferLength);

    public static void RefreshWinInet() {
        try {
            InternetSetOption(System.IntPtr.Zero, 39, System.IntPtr.Zero, 0);
            InternetSetOption(System.IntPtr.Zero, 37, System.IntPtr.Zero, 0);
        } catch { }
    }

    static void Infinite(Socket sock) {
        try {
            sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 0);
            sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendTimeout, 0);
        } catch {
            try {
                sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 300000);
                sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendTimeout, 300000);
            } catch { }
        }
    }

    void Handle(object state) {
        TcpClient client = (TcpClient)state;
        Interlocked.Increment(ref _active);
        string hostLabel = "?";
        bool replied = false;
        try {
            client.NoDelay = true;
            NetworkStream stream = client.GetStream();
            try { stream.ReadTimeout = 20000; } catch { }
            int first = stream.ReadByte();
            if (first < 0) return;
            string host;
            int port;
            bool socks = first == 5;
            bool okHead;
            if (socks) okHead = ReadSocks(stream, out host, out port);
            else okHead = ReadHttpConnect(stream, first, out host, out port);
            if (!okHead) return;
            hostLabel = host + ":" + port;

            IPAddress ip = ResolveHost(host);
            lock (_seen) {
                if (!_seen.ContainsKey(hostLabel)) {
                    _seen[hostLabel] = 1;
                    KopruLog.Write(hostLabel + " -> " + ip);
                }
            }

            TcpClient remote = new TcpClient();
            remote.NoDelay = true;
            IAsyncResult ar = remote.BeginConnect(ip, port, null, null);
            if (!ar.AsyncWaitHandle.WaitOne(8000)) {
                try { remote.Close(); } catch { }
                throw new IOException("zaman asimi");
            }
            remote.EndConnect(ar);
            Infinite(remote.Client);
            Infinite(client.Client);

            if (socks) {
                stream.Write(new byte[] { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 }, 0, 10);
            } else {
                byte[] ok = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
                stream.Write(ok, 0, ok.Length);
            }
            replied = true;
            Pump(client, remote, stream, remote.GetStream(), port);
        } catch (Exception ex) {
            KopruLog.Write("hata " + hostLabel + " — " + ex.Message);
            if (!replied) {
                try {
                    NetworkStream stream = client.GetStream();
                    stream.Write(new byte[] { 5, 5, 0, 1, 0, 0, 0, 0, 0, 0 }, 0, 10);
                } catch { }
            }
        } finally {
            try { client.Close(); } catch { }
            Interlocked.Decrement(ref _active);
        }
    }

    bool ReadSocks(NetworkStream stream, out string host, out int port) {
        host = "?";
        port = 0;
        int nmet = stream.ReadByte();
        if (nmet < 1) return false;
        ReadExact(stream, nmet);
        stream.Write(new byte[] { 5, 0 }, 0, 2);
        byte[] head = ReadExact(stream, 4);
        if (head[0] != 5 || head[1] != 1) {
            stream.Write(new byte[] { 5, 7, 0, 1, 0, 0, 0, 0, 0, 0 }, 0, 10);
            return false;
        }
        if (head[3] == 1) {
            byte[] ipb = ReadExact(stream, 4);
            byte[] pb = ReadExact(stream, 2);
            host = new IPAddress(ipb).ToString();
            port = (pb[0] << 8) | pb[1];
        } else if (head[3] == 3) {
            int len = stream.ReadByte();
            if (len < 1) throw new IOException("bos ad");
            byte[] name = ReadExact(stream, len);
            byte[] pb = ReadExact(stream, 2);
            host = Encoding.ASCII.GetString(name);
            port = (pb[0] << 8) | pb[1];
        } else if (head[3] == 4) {
            byte[] ipb = ReadExact(stream, 16);
            byte[] pb = ReadExact(stream, 2);
            host = new IPAddress(ipb).ToString();
            port = (pb[0] << 8) | pb[1];
        } else {
            throw new IOException("adres tipi");
        }
        return true;
    }

    bool ReadHttpConnect(NetworkStream stream, int first, out string host, out int port) {
        host = "?";
        port = 443;
        MemoryStream ms = new MemoryStream();
        ms.WriteByte((byte)first);
        byte[] one = new byte[1];
        while (ms.Length < 16000) {
            int r = stream.Read(one, 0, 1);
            if (r <= 0) return false;
            ms.WriteByte(one[0]);
            if (ms.Length >= 4) {
                byte[] cur = ms.ToArray();
                int n = cur.Length;
                if (cur[n - 4] == 13 && cur[n - 3] == 10 && cur[n - 2] == 13 && cur[n - 1] == 10) break;
            }
        }
        string text = Encoding.ASCII.GetString(ms.ToArray());
        int lineEnd = text.IndexOf("\r\n");
        if (lineEnd < 0) lineEnd = text.Length;
        string line = text.Substring(0, lineEnd);
        int sp1 = line.IndexOf(' ');
        int sp2 = sp1 < 0 ? -1 : line.IndexOf(' ', sp1 + 1);
        if (sp1 < 0 || sp2 < 0) return false;
        string target = line.Substring(sp1 + 1, sp2 - sp1 - 1);
        int colon = target.LastIndexOf(':');
        if (colon > 0) {
            host = target.Substring(0, colon);
            int parsed;
            if (int.TryParse(target.Substring(colon + 1), out parsed)) port = parsed;
        } else {
            host = target;
        }
        return host.Length > 0;
    }

    void Pump(TcpClient client, TcpClient remote, NetworkStream fromClient, NetworkStream toServer, int port) {
        byte[] hello = ReadAvailableHello(fromClient, client.Client);
        if (hello != null && hello.Length > 0) {
            bool tls = hello[0] == 0x16 && port == 443 && SplitSni && hello.Length > 8;
            if (tls) {
                int recordLen = 5 + ((hello[3] << 8) | hello[4]);
                if (recordLen > hello.Length || recordLen < 6) recordLen = hello.Length;
                int cut = FindSniSplit(hello, recordLen);
                if (cut < 1 || cut >= hello.Length) cut = Math.Min(2, hello.Length - 1);
                toServer.Write(hello, 0, cut);
                toServer.Flush();
                if (SplitDelayMs > 0) Thread.Sleep(SplitDelayMs);
                if (cut < hello.Length) toServer.Write(hello, cut, hello.Length - cut);
            } else {
                toServer.Write(hello, 0, hello.Length);
            }
            toServer.Flush();
        }
        Thread a = new Thread(delegate() { Copy(fromClient, toServer); });
        Thread b = new Thread(delegate() { Copy(toServer, fromClient); });
        a.IsBackground = true;
        b.IsBackground = true;
        a.Start();
        b.Start();
        a.Join();
        b.Join();
        try { remote.Close(); } catch { }
    }

    static void Copy(NetworkStream a, NetworkStream b) {
        byte[] buf = new byte[16384];
        try {
            while (true) {
                int r = a.Read(buf, 0, buf.Length);
                if (r <= 0) break;
                b.Write(buf, 0, r);
                b.Flush();
            }
        } catch { }
        try { a.Close(); } catch { }
        try { b.Close(); } catch { }
    }

    static byte[] ReadAvailableHello(NetworkStream s, Socket sock) {
        try { s.ReadTimeout = 8000; } catch { }
        MemoryStream ms = new MemoryStream();
        byte[] tmp = new byte[8192];
        try {
            int r = s.Read(tmp, 0, tmp.Length);
            if (r <= 0) return null;
            ms.Write(tmp, 0, r);
            byte[] cur = ms.ToArray();
            if (cur.Length >= 5 && cur[0] == 0x16) {
                int need = 5 + ((cur[3] << 8) | cur[4]);
                if (need > 20000) need = 20000;
                while (cur.Length < need) {
                    r = s.Read(tmp, 0, tmp.Length);
                    if (r <= 0) break;
                    ms.Write(tmp, 0, r);
                    cur = ms.ToArray();
                }
            }
        } catch (Exception) {
            if (ms.Length == 0) throw;
        } finally {
            Infinite(sock);
        }
        return ms.ToArray();
    }

    static int FindSniSplit(byte[] buf, int n) {
        try {
            if (n < 11 || buf[0] != 0x16) return 2;
            int idx = 5;
            if (buf[idx] != 0x01) return 2;
            idx += 4;
            idx += 2 + 32;
            if (idx >= n) return 2;
            int sidLen = buf[idx];
            idx += 1 + sidLen;
            if (idx + 2 > n) return 2;
            int csLen = (buf[idx] << 8) | buf[idx + 1];
            idx += 2 + csLen;
            if (idx + 1 > n) return 2;
            int compLen = buf[idx];
            idx += 1 + compLen;
            if (idx + 2 > n) return 2;
            int extLen = (buf[idx] << 8) | buf[idx + 1];
            idx += 2;
            int extEnd = idx + extLen;
            if (extEnd > n) extEnd = n;
            while (idx + 4 <= extEnd) {
                int et = (buf[idx] << 8) | buf[idx + 1];
                int el = (buf[idx + 2] << 8) | buf[idx + 3];
                idx += 4;
                if (et == 0 && el > 5 && idx + el <= n) {
                    int p = idx + 2;
                    if (p + 3 <= n && buf[p] == 0) {
                        int nameLen = (buf[p + 1] << 8) | buf[p + 2];
                        p += 3;
                        if (nameLen > 2 && p + nameLen <= n) return p + (nameLen / 2);
                    }
                }
                if (el < 0) break;
                idx += el;
            }
        } catch { }
        return 2;
    }

    IPAddress ResolveHost(string host) {
        IPAddress parsed;
        if (IPAddress.TryParse(host, out parsed)) return parsed;
        lock (_cacheLock) {
            CacheItem hit;
            if (_cache.TryGetValue(host, out hit) && hit.Exp > DateTime.UtcNow) return hit.Ip;
        }
        string[] urls = new string[] {
            "https://cloudflare-dns.com/dns-query?name=" + Uri.EscapeDataString(host) + "&type=A",
            "https://dns.google/resolve?name=" + Uri.EscapeDataString(host) + "&type=A"
        };
        foreach (string url in urls) {
            try {
                string json = HttpGet(url);
                IPAddress found = FirstIp(json);
                if (found != null) {
                    lock (_cacheLock) {
                        CacheItem item = new CacheItem();
                        item.Ip = found;
                        item.Exp = DateTime.UtcNow.AddMinutes(2);
                        _cache[host] = item;
                    }
                    return found;
                }
            } catch (Exception ex) {
                KopruLog.Write("DoH " + host + " — " + ex.Message);
            }
        }
        IPAddress[] list = Dns.GetHostAddresses(host);
        foreach (IPAddress a in list) {
            if (a.AddressFamily == AddressFamily.InterNetwork) return a;
        }
        throw new IOException("isim cozulmedi");
    }

    static string HttpGet(string url) {
        HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
        req.Timeout = 6000;
        req.Proxy = new WebProxy();
        req.Accept = "application/dns-json";
        req.UserAgent = "Kopru/1.0";
        req.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
        using (HttpWebResponse res = (HttpWebResponse)req.GetResponse())
        using (StreamReader sr = new StreamReader(res.GetResponseStream())) {
            return sr.ReadToEnd();
        }
    }

    static IPAddress FirstIp(string json) {
        MatchCollection ms = Regex.Matches(json, "\"data\"\\s*:\\s*\"(\\d{1,3}(?:\\.\\d{1,3}){3})\"");
        foreach (Match m in ms) {
            IPAddress ip;
            if (IPAddress.TryParse(m.Groups[1].Value, out ip)) return ip;
        }
        return null;
    }

    static byte[] ReadExact(NetworkStream s, int n) {
        byte[] buf = new byte[n];
        int o = 0;
        while (o < n) {
            int r = s.Read(buf, o, n - o);
            if (r <= 0) throw new IOException("baglanti kapandi");
            o += r;
        }
        return buf;
    }

    public string SelfTest() {
        if (!Listening) return "köprü kapalı";
        TcpClient c = new TcpClient();
        try {
            c.Connect(IPAddress.Loopback, Port);
            c.NoDelay = true;
            NetworkStream s = c.GetStream();
            s.ReadTimeout = 12000;
            s.WriteTimeout = 12000;
            s.Write(new byte[] { 5, 1, 0 }, 0, 3);
            if (s.ReadByte() != 5 || s.ReadByte() != 0) return "SOCKS selamı bozuk";
            byte[] name = Encoding.ASCII.GetBytes("discord.com");
            byte[] req = new byte[7 + name.Length];
            req[0] = 5; req[1] = 1; req[2] = 0; req[3] = 3; req[4] = (byte)name.Length;
            Array.Copy(name, 0, req, 5, name.Length);
            req[5 + name.Length] = 0x01;
            req[6 + name.Length] = 0xBB;
            s.Write(req, 0, req.Length);
            byte[] rep = ReadExact(s, 10);
            if (rep[1] != 0) return "TCP çıkamadı, kod " + rep[1];
            RemoteCertificateValidationCallback cb = delegate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors err) {
                return err == SslPolicyErrors.None;
            };
            SslStream ssl = new SslStream(s, false, cb);
            ssl.AuthenticateAsClient("discord.com", null, SslProtocols.Tls12, false);
            return "TLS geçti — discord.com bu hattan açılıyor";
        } catch (Exception ex) {
            return "deneme olmadı — " + ex.Message;
        } finally {
            try { c.Close(); } catch { }
        }
    }
}
'@

$script:engine = $null
$script:appDir = Join-Path $env:LOCALAPPDATA "Kopru"
New-Item -ItemType Directory -Force -Path $script:appDir | Out-Null
$script:ayarPath = Join-Path $script:appDir "ayar.json"
$script:dnsBackup = Join-Path $script:appDir "dns-backup.json"
$script:delays = @{
    "Emin değilim" = 40
    "Türk Telekom" = 20
    "Turkcell"     = 80
    "Vodafone"     = 60
    "TürkNet"      = 25
}

try {
    Add-Type -TypeDefinition $cs -Language CSharp
} catch {
    [System.Windows.Forms.MessageBox]::Show(
        $_.Exception.ToString(),
        "Köprü derlenemedi"
    )
    exit 1
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Ui([string]$m) {
    $line = "{0}  {1}`r`n" -f (Get-Date -Format "HH:mm:ss"), $m
    $script:logBox.AppendText($line)
    $script:logBox.SelectionStart = $script:logBox.TextLength
    $script:logBox.ScrollToCaret()
}

function Save-Ayar {
    $obj = [pscustomobject]@{
        Isp    = [string]$script:isp.SelectedItem
        Dns    = [bool]$script:chkDns.Checked
        Split  = [bool]$script:chkSplit.Checked
        Launch = [bool]$script:chkLaunch.Checked
    }
    $obj | ConvertTo-Json | Set-Content -Path $script:ayarPath -Encoding UTF8
}

function Set-KopruDns {
    if (-not (Test-Admin)) { throw "Yönetici değil. DNS için yeniden aç." }
    $list = @()
    Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
        $v4 = Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $servers = @()
        if ($v4 -and $v4.ServerAddresses) { $servers = @($v4.ServerAddresses) }
        $list += [pscustomobject]@{ Name = $_.Name; Index = $_.ifIndex; Servers = $servers }
    }
    if ($list.Count -eq 0) { throw "Açık ağ kartı yok" }
    $list | ConvertTo-Json -Depth 4 | Set-Content -Path $script:dnsBackup -Encoding UTF8
    foreach ($item in $list) {
        Set-DnsClientServerAddress -InterfaceIndex $item.Index -ServerAddresses @("1.1.1.1", "1.0.0.1")
        Write-Ui ("DNS 1.1.1.1  " + $item.Name)
    }
    & netsh dns add encryption server=1.1.1.1 dohtemplate=https://cloudflare-dns.com/dns-query autoupgrade=yes udpfallback=no 2>&1 | Out-Null
    & netsh dns add encryption server=1.0.0.1 dohtemplate=https://cloudflare-dns.com/dns-query autoupgrade=yes udpfallback=no 2>&1 | Out-Null
    & ipconfig /flushdns | Out-Null
    Write-Ui "DNS yedeklendi. Geri almak için alttaki düğme."
}

function Restore-KopruDns {
    if (-not (Test-Admin)) { throw "Yönetici değil." }
    if (-not (Test-Path $script:dnsBackup)) { throw "Yedek yok. DNS değişmemiş olabilir." }
    $raw = Get-Content -Path $script:dnsBackup -Raw -Encoding UTF8
    $items = @($raw | ConvertFrom-Json)
    foreach ($item in $items) {
        $servers = @($item.Servers | Where-Object { $_ })
        if ($servers.Count -eq 0) {
            Set-DnsClientServerAddress -InterfaceIndex ([int]$item.Index) -ResetServerAddresses
        } else {
            Set-DnsClientServerAddress -InterfaceIndex ([int]$item.Index) -ServerAddresses $servers
        }
        Write-Ui ("DNS geri  " + $item.Name)
    }
    & ipconfig /flushdns | Out-Null
}

function Stop-DiscordClients {
    $roots = @(
        (Join-Path $env:LOCALAPPDATA "Discord"),
        (Join-Path $env:LOCALAPPDATA "DiscordPTB"),
        (Join-Path $env:LOCALAPPDATA "DiscordCanary"),
        (Join-Path $env:LOCALAPPDATA "DiscordDevelopment")
    )
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        $path = $null
        try { $path = $_.Path } catch { return }
        if (-not $path) { return }
        foreach ($root in $roots) {
            if ($path.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
                try { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue } catch { }
                break
            }
        }
    }
    Start-Sleep -Milliseconds 700
}

function Start-DiscordBridge([int]$port) {
    Stop-DiscordClients
    $arg = "--proxy-server=http://127.0.0.1:{0}" -f $port
    foreach ($n in @("Discord", "DiscordPTB", "DiscordCanary", "DiscordDevelopment")) {
        $upd = Join-Path $env:LOCALAPPDATA "$n\Update.exe"
        if (Test-Path $upd) {
            Start-Process -FilePath $upd -ArgumentList @("--processStart", "$n.exe", "--process-start-args", $arg)
            return $n
        }
    }
    return $null
}

function Enable-KopruWinProxy([int]$port) {
    $key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    if (-not $script:proxyBak) {
        $en = 0
        $srv = ""
        $ov = ""
        try { $en = [int](Get-ItemProperty -Path $key -Name ProxyEnable).ProxyEnable } catch { }
        try { $srv = [string](Get-ItemProperty -Path $key -Name ProxyServer).ProxyServer } catch { }
        try { $ov = [string](Get-ItemProperty -Path $key -Name ProxyOverride).ProxyOverride } catch { }
        $script:proxyBak = @{ Enable = $en; Server = $srv; Override = $ov }
    }
    Set-ItemProperty -Path $key -Name ProxyEnable -Value 1
    Set-ItemProperty -Path $key -Name ProxyServer -Value ("127.0.0.1:{0}" -f $port)
    Set-ItemProperty -Path $key -Name ProxyOverride -Value "localhost;127.0.0.1;<local>"
    [KopruEngine]::RefreshWinInet()
    try { & netsh winhttp set proxy ("127.0.0.1:{0}" -f $port) 2>&1 | Out-Null } catch { Write-Ui "WinHTTP atlandı" }
    Write-Ui ("Windows proxy 127.0.0.1:{0} — kapatınca geri alınır" -f $port)
}

function Disable-KopruWinProxy {
    if (-not $script:proxyBak) { return }
    $key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    Set-ItemProperty -Path $key -Name ProxyEnable -Value ([int]$script:proxyBak.Enable)
    if ($script:proxyBak.Server) {
        Set-ItemProperty -Path $key -Name ProxyServer -Value ([string]$script:proxyBak.Server)
    }
    if ($script:proxyBak.Override) {
        Set-ItemProperty -Path $key -Name ProxyOverride -Value ([string]$script:proxyBak.Override)
    }
    $script:proxyBak = $null
    [KopruEngine]::RefreshWinInet()
    try { & netsh winhttp reset proxy 2>&1 | Out-Null } catch { }
    Write-Ui "Windows proxy geri alındı"
}

function Restart-AsAdmin {
    $arg = "-NoProfile -STA -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $arg
    $script:form.Close()
}

$bg = [System.Drawing.Color]::FromArgb(18, 20, 15)
$fg = [System.Drawing.Color]::FromArgb(231, 238, 223)
$muted = [System.Drawing.Color]::FromArgb(141, 152, 127)
$lime = [System.Drawing.Color]::FromArgb(214, 255, 74)
$limeFg = [System.Drawing.Color]::FromArgb(26, 34, 8)
$panel = [System.Drawing.Color]::FromArgb(28, 33, 24)
$ink = [System.Drawing.Color]::FromArgb(12, 14, 10)

$form = New-Object System.Windows.Forms.Form
$script:form = $form
$form.Text = "Köprü 1.2"
$form.ClientSize = New-Object System.Drawing.Size(520, 640)
$form.MinimumSize = New-Object System.Drawing.Size(520, 560)
$form.StartPosition = "CenterScreen"
$form.BackColor = $bg
$form.ForeColor = $fg
$form.Font = New-Object System.Drawing.Font("Segoe UI", 10)

$top = New-Object System.Windows.Forms.Panel
$top.Dock = "Top"
$top.Height = 416
$top.BackColor = $bg

$log = New-Object System.Windows.Forms.TextBox
$script:logBox = $log
$log.Multiline = $true
$log.ReadOnly = $true
$log.Dock = "Fill"
$log.ScrollBars = "Vertical"
$log.BackColor = $ink
$log.ForeColor = [System.Drawing.Color]::FromArgb(198, 210, 180)
$log.Font = New-Object System.Drawing.Font("Consolas", 9)
$log.BorderStyle = "None"
$form.Controls.Add($log)
$form.Controls.Add($top)

$title = New-Object System.Windows.Forms.Label
$title.Text = "KÖPRÜ 1.2"
$title.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
$title.ForeColor = $lime
$title.Location = New-Object System.Drawing.Point(20, 14)
$title.AutoSize = $true
$top.Controls.Add($title)

$sub = New-Object System.Windows.Forms.Label
$sub.Text = "Discord için yerel köprü. VPN değil, IP gizlemez."
$sub.ForeColor = $muted
$sub.Location = New-Object System.Drawing.Point(22, 52)
$sub.AutoSize = $true
$top.Controls.Add($sub)

$status = New-Object System.Windows.Forms.Label
$status.Text = "Kapalı"
$status.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$status.ForeColor = $muted
$status.Location = New-Object System.Drawing.Point(22, 84)
$status.Size = New-Object System.Drawing.Size(470, 28)
$top.Controls.Add($status)

$admin = New-Object System.Windows.Forms.Label
if (Test-Admin) { $admin.Text = "Yönetici: evet" } else { $admin.Text = "Yönetici: hayır  —  DNS için gerekli" }
$admin.ForeColor = $muted
$admin.Location = New-Object System.Drawing.Point(22, 114)
$admin.AutoSize = $true
$top.Controls.Add($admin)

$ispLabel = New-Object System.Windows.Forms.Label
$ispLabel.Text = "Operatör"
$ispLabel.ForeColor = $muted
$ispLabel.Location = New-Object System.Drawing.Point(22, 146)
$ispLabel.AutoSize = $true
$top.Controls.Add($ispLabel)

$isp = New-Object System.Windows.Forms.ComboBox
$script:isp = $isp
$isp.DropDownStyle = "DropDownList"
$isp.Location = New-Object System.Drawing.Point(22, 168)
$isp.Size = New-Object System.Drawing.Size(220, 28)
$isp.FlatStyle = "Flat"
$isp.BackColor = $panel
$isp.ForeColor = $fg
[void]$isp.Items.AddRange(@("Emin değilim", "Türk Telekom", "Turkcell", "Vodafone", "TürkNet"))
$isp.SelectedIndex = 0
$top.Controls.Add($isp)

function New-Check([string]$text, [int]$y, [bool]$on) {
    $c = New-Object System.Windows.Forms.CheckBox
    $c.Text = $text
    $c.ForeColor = $fg
    $c.BackColor = $bg
    $c.Location = New-Object System.Drawing.Point(22, $y)
    $c.Size = New-Object System.Drawing.Size(470, 24)
    $c.Checked = $on
    $top.Controls.Add($c)
    return $c
}

$script:chkDns = New-Check "DNS'i Cloudflare yap (1.1.1.1 + DoH, geri alınır)" 210 $true
$script:chkSplit = New-Check "TLS selamını parçala (SNI filtresi)" 238 $true
$script:chkLaunch = New-Check "Discord'u bu köprüyle yeniden başlat" 266 $true

if (Test-Path $script:ayarPath) {
    try {
        $saved = Get-Content $script:ayarPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $idx = $isp.Items.IndexOf([string]$saved.Isp)
        if ($idx -ge 0) { $isp.SelectedIndex = $idx }
        $script:chkDns.Checked = [bool]$saved.Dns
        $script:chkSplit.Checked = [bool]$saved.Split
        $script:chkLaunch.Checked = [bool]$saved.Launch
    } catch { }
}

function New-Btn([string]$text, [int]$x, [int]$y, [int]$w, [bool]$primary) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $text
    $b.Location = New-Object System.Drawing.Point($x, $y)
    $b.Size = New-Object System.Drawing.Size($w, 40)
    $b.FlatStyle = "Flat"
    $b.FlatAppearance.BorderSize = 0
    if ($primary) {
        $b.BackColor = $lime
        $b.ForeColor = $limeFg
    } else {
        $b.BackColor = $panel
        $b.ForeColor = $fg
    }
    $top.Controls.Add($b)
    return $b
}

$btnOn = New-Btn "Köprüyü aç" 22 308 150 $true
$btnDiscord = New-Btn "Discord'u aç" 180 308 150 $false
$btnTest = New-Btn "Dene" 338 308 78 $false
$btnOff = New-Btn "Durdur" 22 354 110 $false
$btnDnsBack = New-Btn "DNS'i geri al" 140 354 140 $false
$btnAdmin = New-Btn "Yönetici olarak aç" 288 354 170 $false
if (Test-Admin) { $btnAdmin.Visible = $false }

$btnOn.Add_Click({
    try {
        Save-Ayar
        if ($script:engine -and $script:engine.Listening) { $script:engine.Stop() }
        $picked = [string]$script:isp.SelectedItem
        $delay = 40
        if ($script:delays.ContainsKey($picked)) { $delay = $script:delays[$picked] }
        $eng = New-Object KopruEngine
        $eng.SplitSni = [bool]$script:chkSplit.Checked
        $eng.SplitDelayMs = $delay
        $started = $false
        foreach ($p in 1080, 1081, 1082, 1083, 1084) {
            $eng.Port = $p
            $err = $eng.Start()
            if (-not $err) { $started = $true; break }
        }
        if (-not $started) { Write-Ui ("Port açılamadı: " + $err); return }
        $script:engine = $eng
        Write-Ui ("Profil " + $picked + ", parcalama " + $delay + " ms")
        try { Enable-KopruWinProxy $eng.Port } catch { Write-Ui $_.Exception.Message }
        if ($script:chkDns.Checked) {
            try { Set-KopruDns } catch { Write-Ui $_.Exception.Message }
        }
        if ($script:chkLaunch.Checked) {
            $which = Start-DiscordBridge $eng.Port
            if ($which) { Write-Ui ($which + " köprüyle açıldı") }
            else { Write-Ui "Discord kurulumu bulunamadı. discord.com/app dene." }
        }
    } catch {
        Write-Ui $_.Exception.Message
    }
})

$btnDiscord.Add_Click({
    if (-not $script:engine -or -not $script:engine.Listening) {
        Write-Ui "Önce köprüyü aç."
        return
    }
    $which = Start-DiscordBridge $script:engine.Port
    if ($which) { Write-Ui ($which + " yeniden açıldı") }
    else { Write-Ui "Discord bulunamadı." }
})

$btnTest.Add_Click({
    if (-not $script:engine -or -not $script:engine.Listening) {
        Write-Ui "Önce köprüyü aç."
        return
    }
    $btnTest.Enabled = $false
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    [System.Windows.Forms.Application]::DoEvents()
    try {
        Write-Ui $script:engine.SelfTest()
    } catch {
        Write-Ui $_.Exception.Message
    } finally {
        $btnTest.Enabled = $true
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
})

$btnOff.Add_Click({
    if ($script:engine) { $script:engine.Stop(); $script:engine = $null }
    else { Write-Ui "Zaten kapalı" }
    try { Disable-KopruWinProxy } catch { Write-Ui $_.Exception.Message }
})

$btnDnsBack.Add_Click({
    try { Restore-KopruDns } catch { Write-Ui $_.Exception.Message }
})

$btnAdmin.Add_Click({ Restart-AsAdmin })

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 400
$timer.Add_Tick({
    $lines = @([KopruLog]::Drain())
    if ($lines.Count -gt 0 -and $lines[0]) {
        $log.AppendText(($lines -join "`r`n") + "`r`n")
        $log.SelectionStart = $log.TextLength
        $log.ScrollToCaret()
    }
    if ($script:engine -and $script:engine.Listening) {
        $status.Text = "Açık   127.0.0.1:{0}    {1} bağlantı" -f $script:engine.Port, $script:engine.ActiveCount
        $status.ForeColor = $lime
    } else {
        $status.Text = "Kapalı"
        $status.ForeColor = $muted
    }
})
$timer.Start()

$form.Add_FormClosing({
    $timer.Stop()
    if ($script:engine) { $script:engine.Stop() }
    try { Disable-KopruWinProxy } catch { }
})

Write-Ui "Sürüm 1.2. Pencerede 1.2 yazmıyorsa eski dosyayı çalıştırıyorsun."
Write-Ui "Hazır. Köprüyü aç, sonra Dene."
Write-Ui "Ses UDP'dir. Sohbet açılıp ses takılırsa operatörü değiştir."
[void]$form.ShowDialog()
