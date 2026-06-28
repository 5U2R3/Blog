# TryHackMe Warzone 1：MirrorBlast関連C2アラートのPCAPトリアージとTrue Positive判定

## はじめに

本記事は、TryHackMe Warzone 1のWriteUpである。

Warzone 1は、SOC Tier 1アナリストの業務に近いシナリオとして、IDS/IPSアラートを起点にPCAPを調査し、検知がTrue Positiveかどうかを判断する演習である。

本記事では、Roomの設問を解きながら、IPアドレス、ドメイン、User-Agent、ファイル名、HTTP通信などの証跡を抽出し、外部脅威インテリジェンスとPCAP上の観測事実を突き合わせる手順を整理する。

本記事の目的は、以下の2点である。

1. SOCアラートトリアージおよびネットワークフォレンジックの学習成果をポートフォリオとして整理すること。
2. Brim/Zui、Wireshark、NetworkMiner、VirusTotalを用いた調査プロセスを復習し、学習内容を定着させること。

| 項目   | 値                                                        |
| :--- | :------------------------------------------------------- |
| Room | Warzone 1                                                |
| URL  | https://tryhackme.com/room/warzoneone                    |
| カテゴリ | Network Forensics                                        |
| OS   | Linux                                                    |
| Tool | Brim/Zui, Wireshark, NetworkMiner, CyberChef, VirusTotal |
| 技術タグ | TA505, MirrorBlast, T1071.001, T1105                     |
| 作成日  | 2026/06/28                                               |

---

## Executive Summary

内部ホスト `172.16.1.102` が、MirrorBlast関連とみられる外部インフラへHTTP通信を行っていた。  
Suricataでは `ET MALWARE MirrorBlast CnC Activity M3` が発火し、HTTP User-Agentには `REBOL View 2.7.8.3.1` が確認された。  
このUser-Agentは、MirrorBlastの既知TTPであるRebol loaderの利用と整合する。  
さらに、関連する外部IPアドレス `185.10.68.235` および `192.36.27.92` から、MSIファイル `filter.msi` および `10opd3r_load.msi` の取得が確認された。  
HTTPペイロード内には、`C:\ProgramData\...` 配下に展開されるとみられるファイルパス文字列も含まれていた。  
以上の観測事実から、本アラートはFalse Positiveではなく、MirrorBlast関連活動と整合するTrue Positiveとして扱うべきである。  
ただし、PCAP単体ではホスト上でのファイル作成、プロセス実行、永続化、権限昇格、横展開までは確定できない。  
そのため、実環境であればEDRログ、Sysmon、Windows Event Log、Amcache、ShimCache、Prefetch、MFT、USN Journalなどのホスト証跡を追加で確認する必要がある。  

---

## 調査方針

本調査では、PCAPを起点として以下の順序で確認を行う。

1. Brim/ZuiでSuricataアラートを抽出し、検知シグネチャ、送信元IP、送信先IPを特定する。
2. HTTPログから、関連する外部IP、Host、URI、User-Agentを抽出する。
3. VirusTotalでPassive DNS、Communicating Files、Community情報を確認し、既知の脅威インフラとの関連を評価する。
4. Wiresharkで該当通信のTCP Streamを確認し、HTTPペイロード、ファイル名、パス文字列、User-Agentなどの証跡を確認する。
5. NetworkMinerでPCAPから再構成されたファイルと送信元IPの対応を確認する。
6. 観測事実を整理し、True PositiveかFalse Positiveかを判定する。

Brim/Zuiを最初に使用する理由は、SuricataアラートとZeekログを高速に検索・集計でき、トリアージの起点となるIPアドレスと通信種別を素早く特定できるためである。

次にVirusTotalを参照する理由は、PCAP上のIPアドレスやドメインだけでは、それが既知の脅威インフラかどうかを判断できないためである。外部脅威インテリジェンスを使い、観測されたIOCが既知キャンペーンや脅威アクターと関連するかを確認する。

最後にWiresharkとNetworkMinerで深掘りする理由は、調査対象の通信が絞り込まれた後にHTTPペイロードや再構成ファイルを確認することで、無関係なトラフィックを追う時間を削減できるためである。

---

## アラートトリアージ、PCAP初期解析、脅威インテリジェンス分析

### What was the alert signature for Malware Command and Control Activity Detected?

IDS/IPSで検知された `"Malware Command and Control Activity Detected"` が、どのシグネチャによって検知されたのかを確認する。

PCAPをBrim/Zuiで読み込み、Suricataのalertイベントを確認する。

```zng
event_type=="alert"
| count() by alert.severity, alert.category, alert.signature
| sort count desc
```

このクエリでは、`event_type=="alert"` によりSuricataのアラートイベントのみを抽出し、`count() by` でseverity、category、signatureの組み合わせごとに集計する。

`sort count desc` により、件数の多い順に並べる。Zed/Zuiの `sort` はデフォルトでは昇順であるため、件数の多い順に確認したい場合は `desc` を明示する。

**Answer:** `ET MALWARE MirrorBlast CnC Activity M3`

シグネチャ名の読み方は以下のとおりである。

* `ET`: Emerging Threatsのルールセットを示す。
* `MALWARE`: マルウェア関連の検知カテゴリを示す。
* `MirrorBlast`: 関連するマルウェアファミリーまたはキャンペーン名を示す。
* `CnC Activity`: Command and Control通信に関連する検知であることを示す。
* `M3`: ルールのバリアントを識別するサフィックスである。

この時点で、内部ホストがMirrorBlast関連のC2通信を行った可能性があるため、該当アラートの送信元・送信先を確認する。

---

### What is the source IP address? Enter your answer in a defanged format.

アラートを発生させた通信の送信元IPアドレスを確認する。

以下のクエリで、アラートシグネチャ、送信元IP、送信先IPを抽出する。

```zng
event_type=="alert"
| cut alert.signature, src_ip, dest_ip
| sort alert.signature, src_ip, dest_ip
| uniq
```

`uniq` は隣接する重複レコードを除去する演算子である。そのため、非隣接の重複を確実に除去するには、事前に `sort` を行う。

**Answer:** `172[.]16[.]1[.]102`

`172.16.0.0/12` はRFC1918で定義されたプライベートIPアドレス空間である。そのため、`172.16.1.102` は組織内部のエンドポイントと判断できる。

defangとは、IPアドレスやURLをそのままコピーしてもクリックや名前解決が発生しないよう、ドット `.` を `[.]` に置き換える表記である。セキュリティレポートやWriteUpでIOCを記載する際に使用される。

---

### What IP address was the destination IP in the alert? Enter your answer in a defanged format.

アラートを発生させた通信の送信先IPアドレスを確認する。

前問と同じクエリ結果の `dest_ip` フィールドから、送信先IPアドレスを特定する。

**Answer:** `169[.]239[.]128[.]11`

`169.239.128.11` はグローバルIPアドレスである。

内部ホスト `172.16.1.102` から外部IPアドレス `169.239.128.11` への通信で、MirrorBlast関連のC2アラートが発火している。この時点では、当該IPをC2サーバと断定するのではなく、「C2通信として検知された外部IP」または「C2疑いIP」として扱うのが適切である。

次のステップとして、このIPアドレスをVirusTotalで調査し、既知の脅威インフラとの関連を確認する。

---

### Inspect the destination IP in VirusTotal. Under Relations > Passive DNS Replication, which domain has the most detections?

Q3で特定した送信先IP `169.239.128.11` をVirusTotalで検索し、`Relations` タブの `Passive DNS Replication` を確認する。

Passive DNSとは、DNSクエリとレスポンスの履歴をパッシブに収集・蓄積した情報である。攻撃者はIPアドレスを再利用しながらドメイン名を切り替えることがあるため、Passive DNSの履歴を確認することで、同一インフラに紐づいた過去のドメインを追跡できる場合がある。

**Answer:** `fidufagios[.]com`

VirusTotal上では、このドメインが当該IPに紐づくPassive DNS項目の中で最も多く検出されている。

ただし、Passive DNSは「過去に名前解決上の関連が観測された」ことを示す情報であり、その時点で当該ドメインが現在もアクティブなC2であることを単独で証明するものではない。現在の有効性を確認するには、DNS履歴、WHOIS、証明書履歴、URLhaus、abuse.ch、ベンダーレポートなどを追加で確認する必要がある。

---

### Still in VirusTotal, under Community, what threat group is attributed to this IP address?

VirusTotalの `Community` タブには、セキュリティリサーチャーやベンダーがIOCに関する文脈情報を投稿している場合がある。

`169.239.128.11` に対するCommunity情報を確認し、このIPアドレスに関連づけられている脅威グループを確認する。

**Answer:** `TA505`

TA505は、MITRE ATT&CKで `G0092` として追跡されている金銭目的のサイバー犯罪グループである。2014年頃から活動が確認されており、マルウェア配布、大規模フィッシング、ランサムウェア関連活動などで知られている。

ただし、VirusTotal Community上の投稿は有用な手がかりである一方、帰属の一次証拠ではない。そのため、実務ではMITRE ATT&CK、ベンダーレポート、マルウェア解析レポート、インフラ重複、TTPの一致など、複数の情報源と照合して評価する必要がある。

本調査では、VirusTotal上のTA505という文脈情報に加え、MirrorBlast、MSIファイル、REBOL View User-Agentといった観測事実が既知TTPと整合しているため、TA505/MirrorBlast関連活動として扱う妥当性が高いと判断する。

---

### What is the malware family?

前問までの調査で特定した文脈から、このキャンペーンまたはマルウェアファミリー名を確認する。

**Answer:** `MirrorBlast`

MirrorBlastは、TA505の活動と関連づけられているマルウェアファミリーまたはローダー／キャンペーン名として扱われる。

Proofpointなどの公開情報では、TA505がMSIファイルを配布し、Rebol loaderやMirrorBlast loaderを利用したキャンペーンを行っていたことが報告されている。

本PCAPでも、以下の観測事実がMirrorBlast関連活動と整合する。

* Suricataシグネチャ `ET MALWARE MirrorBlast CnC Activity M3` の発火
* User-Agent `REBOL View 2.7.8.3.1`
* MSIファイルのダウンロード
* REBOL実行ファイルおよびスクリプトとみられるファイルパス文字列

---

### Do a search in VirusTotal for the domain from question 4. What was the majority file type listed under Communicating Files?

Q4で特定したドメイン `fidufagios.com` をVirusTotalで検索し、`Relations` タブの `Communicating Files` を確認する。

Communicating Filesとは、VirusTotalで過去に分析されたファイルのうち、当該ドメインと通信したことが観測されたファイル群である。ここを確認することで、このドメインがどのようなファイル種別と関連しているかを把握できる。

**Answer:** `Windows Installer`

Windows Installerは、一般に `.msi` ファイルとして扱われるインストーラパッケージ形式である。

TA505/MirrorBlast関連活動ではMSIファイルが配布に利用された事例が報告されており、本設問のVirusTotal情報とも整合する。

ただし、Communicating FilesはVirusTotal上の過去分析結果に基づく関連情報であり、PCAP内のファイルが実際にそのドメインと通信したことを直接証明するものではない。PCAP上のHTTP通信、Host、URI、ファイル名、送信元・送信先IPと突き合わせて評価する必要がある。

---

### Inspect the web traffic for the flagged IP address; what is the user-agent in the traffic?

`169.239.128.11` へのHTTPトラフィックを確認し、通信に使用されたUser-Agentを特定する。

Brim/Zuiで以下のクエリを実行する。

```zng
_path=="http"
| cut id.orig_h, id.resp_h, id.resp_p, method, host, uri, user_agent
| sort id.orig_h, id.resp_h, host, uri, user_agent
| uniq
```

HTTP通信の件数も併せて確認したい場合は、以下のように集計する。

```zng
_path=="http"
| count() by id.orig_h, id.resp_h, host, uri, user_agent
| sort count desc
```

**Answer:** `REBOL View 2.7.8.3.1`

User-AgentはHTTPリクエストヘッダの一つであり、通信元ソフトウェアを識別する文字列である。

`REBOL View 2.7.8.3.1` は、MirrorBlast関連活動の既知TTPと整合する重要な観測事実である。特に、SuricataのMirrorBlast C2シグネチャが発火している通信において、HTTP User-Agentに `REBOL` が含まれている点は、False PositiveではなくTrue Positiveとして評価する上で強い根拠となる。

---

### Retrace the attack; there were multiple IP addresses associated with this attack. What were two other IP addresses? Enter the IP addressed defanged and in numerical order. (format: IPADDR,IPADDR)

攻撃に関連する追加のIPアドレスを特定する。

HTTPログから、内部ホスト `172.16.1.102` が通信した外部IPアドレスを確認する。

```zng
_path=="http"
| count() by id.orig_h, id.resp_h, host
| sort count desc
```

また、内部ホストを絞り込む場合は以下のようにする。

```zng
_path=="http" and id.orig_h==172.16.1.102
| count() by id.resp_h, host, uri, user_agent
| sort count desc
```

既知のC2疑いIP `169.239.128.11` 以外にも、攻撃に関連する外部IPアドレスが確認できる。

**Answer:** `185[.]10[.]68[.]235,192[.]36[.]27[.]92`

この2つのIPアドレスは、後続の設問でMSIファイルのダウンロード元として扱われる。したがって、本記事ではこれらを「追加C2 IP」と断定せず、「関連外部IP」または「MSIダウンロード元IP」と表現する。

数値順で記載する必要があるため、`185[.]10[.]68[.]235,192[.]36[.]27[.]92` の順で回答する。

---

### What were the file names of the downloaded files? Enter the answer in the order to the IP addresses from the previous question. (format: file.xyz,file.xyz)

Q8で特定した2つのIPアドレスからダウンロードされたファイル名を確認する。

NetworkMinerの `Files` タブを使用すると、PCAPから再構成されたファイルと通信先IPアドレスの対応を確認できる。

また、Brim/ZuiのHTTPログでも、URIやfilename相当の情報を確認できる場合がある。

```zng
_path=="http" and (id.resp_h==185.10.68.235 or id.resp_h==192.36.27.92)
| cut ts, id.orig_h, id.resp_h, host, uri, resp_mime_types
| sort ts
```

**Answer:** `filter.msi,10opd3r_load.msi`

IPアドレスの順序に対応して、以下のように整理できる。

| IPアドレス        | 役割           | ファイル名            |
| :------------ | :----------- | :--------------- |
| 185.10.68.235 | MSIダウンロード元IP | filter.msi       |
| 192.36.27.92  | MSIダウンロード元IP | 10opd3r_load.msi |

いずれもMSIファイルであり、VirusTotalのCommunicating Filesで確認したWindows Installerというファイル種別、およびTA505/MirrorBlast関連活動におけるMSI利用のTTPと整合する。

---

### Inspect the traffic for the first downloaded file from the previous question. Two files will be saved to the same directory. What is the full file path of the directory and the name of the two files? (format: C:\path\file.xyz,C:\path\file.xyz)

1件目のダウンロードファイル `filter.msi` に関連する通信をWiresharkで確認する。

Wiresharkで以下のDisplay Filterを設定する。

```text
ip.addr == 185.10.68.235
```

対象パケットを右クリックし、`Follow` → `TCP Stream` を選択する。HTTPペイロード内に、ASCII文字列としてファイルパスが含まれていることを確認する。

**Answer:** `C:\ProgramData\001\arab.bin,C:\ProgramData\001\Action1_arab.exe`

ここで確認できるのは、PCAP内のHTTPペイロードまたは再構成ファイル内に、上記のファイルパス文字列が含まれているという事実である。

PCAP単体では、実際にホスト上でファイルが作成されたか、実行されたかまでは確定できない。そのため、実環境であれば以下のホスト証跡を追加確認する必要がある。

* EDRのファイル作成イベント
* Sysmon Event ID 11: FileCreate
* Sysmon Event ID 1: Process Creation
* Windows Event Log
* Amcache
* ShimCache
* Prefetch
* MFT
* USN Journal

`C:\ProgramData` は、Windowsにおける全ユーザー共通のアプリケーションデータディレクトリである。マルウェアがこのディレクトリを使用する理由としては、標準ユーザー権限でも書き込み可能な場合があり、一般ユーザーが日常的に確認しないパスであるため発見が遅れやすい点が挙げられる。

---

### Now do the same and inspect the traffic from the second downloaded file. Two files will be saved to the same directory. What is the full file path of the directory and the name of the two files? (format: C:\path\file.xyz,C:\path\file.xyz)

2件目のダウンロードファイル `10opd3r_load.msi` に関連する通信をWiresharkで確認する。

Wiresharkで以下のDisplay Filterを設定する。

```text
ip.addr == 192.36.27.92
```

対象パケットを右クリックし、`Follow` → `TCP Stream` を選択する。HTTPペイロード内に、ASCII文字列としてファイルパスが含まれていることを確認する。

**Answer:** `C:\ProgramData\Local\Google\rebol-view-278-3-1.exe,C:\ProgramData\Local\Google\exemple.rb`

`rebol-view-278-3-1.exe` はREBOL Viewの実行ファイルとみられる。これは、Q7で確認したUser-Agent `REBOL View 2.7.8.3.1` と整合する。

`exemple.rb` はREBOLスクリプトファイルとみられる。`rebol-view-278-3-1.exe` がこのスクリプトを読み込み、後続の悪意ある処理を実行する構造が想定される。

ただし、PCAP単体で確認できるのは、HTTPペイロード内にこれらのファイルパス文字列が含まれていることまでである。実際のファイル作成や実行は、ホストベースのフォレンジックで確認する必要がある。

`C:\ProgramData\Local\Google` というパスは、Google関連の正規アプリケーションディレクトリに見せかける意図がある可能性がある。これはMITRE ATT&CKのMasquerading、すなわち `T1036` と関連する可能性がある。ただし、PCAP単体では攻撃者の意図を完全には証明できないため、本記事では「T1036の可能性がある」と表現する。

---

## 攻撃シーケンス再構成

### 観測事実ベースの時系列

PCAP上の通信をもとに、攻撃シーケンスを整理する。

実際のタイムスタンプは、Brim/Zuiの `ts` フィールドまたはWiresharkのTime列を確認して追記する。

| 順序 | 時刻          | 観測内容                       | 送信元          | 送信先            | 確認した証拠                                                               | 解釈                  |
| :- | :---------- | :------------------------- | :----------- | :------------- | :------------------------------------------------------------------- | :------------------ |
| 1  | PCAP上の時刻を追記 | MirrorBlast C2関連アラート       | 172.16.1.102 | 169.239.128.11 | Suricata alert: `ET MALWARE MirrorBlast CnC Activity M3`             | MirrorBlast C2通信疑い  |
| 2  | PCAP上の時刻を追記 | HTTP通信でREBOL User-Agentを確認 | 172.16.1.102 | 169.239.128.11 | `REBOL View 2.7.8.3.1`                                               | MirrorBlast既知TTPと整合 |
| 3  | PCAP上の時刻を追記 | MSIファイル取得                  | 172.16.1.102 | 185.10.68.235  | `filter.msi`                                                         | 追加ペイロード取得           |
| 4  | PCAP上の時刻を追記 | ペイロード内にファイルパス文字列を確認        | -            | -              | `C:\ProgramData\001\arab.bin`, `C:\ProgramData\001\Action1_arab.exe` | 展開先候補の確認            |
| 5  | PCAP上の時刻を追記 | MSIファイル取得                  | 172.16.1.102 | 192.36.27.92   | `10opd3r_load.msi`                                                   | 追加ペイロード取得           |
| 6  | PCAP上の時刻を追記 | ペイロード内にREBOL関連パス文字列を確認     | -            | -              | `rebol-view-278-3-1.exe`, `exemple.rb`                               | REBOL loader構成と整合   |

この表では、「観測事実」と「解釈」を分離している。

観測事実は、PCAP、Suricataアラート、HTTPログ、TCP Stream、NetworkMinerの出力から確認できる内容である。一方、解釈は、それらの証跡を既知TTPや脅威インテリジェンスと照合した評価である。

---

## True Positive判定

本アラートはTrue Positiveと判断する。

根拠は以下である。

### 証拠1：MirrorBlast関連Suricataシグネチャの発火

Suricataで `ET MALWARE MirrorBlast CnC Activity M3` が発火している。

このシグネチャはMirrorBlast関連のC2通信を検知するものであり、HTTP通信上の特徴をもとに検知している。アラート対象が内部ホストから外部IPへの通信である点も、C2通信の疑いを強める。

### 証拠2：内部ホストから外部IPへの通信

アラート対象通信の送信元は内部ホスト `172.16.1.102`、送信先は外部IP `169.239.128.11` である。

内部ホストが、MirrorBlast関連として検知された外部IPへ通信していることは、False Positiveではなく実際の不審通信である可能性を示す。

### 証拠3：REBOL View User-Agentの確認

HTTPログ上で `REBOL View 2.7.8.3.1` のUser-Agentが確認された。

MirrorBlast関連活動ではRebol loaderの利用が報告されているため、このUser-Agentは既知TTPと整合する重要な証跡である。

### 証拠4：MSIファイルのダウンロード

関連外部IP `185.10.68.235` および `192.36.27.92` から、MSIファイル `filter.msi` および `10opd3r_load.msi` の取得が確認された。

TA505/MirrorBlast関連活動では、MSIファイルが配布に使われた事例が報告されている。したがって、MSIファイルの取得は、MirrorBlast関連活動の可能性を補強する。

### 証拠5：HTTPペイロード内のファイルパス文字列

HTTPペイロード内には、以下のパス文字列が含まれていた。

* `C:\ProgramData\001\arab.bin`
* `C:\ProgramData\001\Action1_arab.exe`
* `C:\ProgramData\Local\Google\rebol-view-278-3-1.exe`
* `C:\ProgramData\Local\Google\exemple.rb`

これらは、ペイロードがホスト上に展開しようとするファイルパス、またはインストーラ内で参照されるファイルパスとみられる。

ただし、PCAP単体では実際のファイル作成や実行までは確定できない。実行有無や侵害範囲を判断するには、ホストベースの証跡が必要である。

### 判定

以上より、ネットワーク観測上はMirrorBlast関連活動と整合する複数の証跡が確認できるため、本アラートはFalse PositiveではなくTrue Positiveとして扱うべきである。

実運用であれば、内部ホスト `172.16.1.102` を優先的に隔離し、ホストフォレンジックおよびEDRログ調査へエスカレーションする。

---

## 調査チェーンサマリー

### 調査フローとMITRE ATT&CKマッピング

| フェーズ         | 攻撃者の行動                              | SOCの検出・確認手段                        | MITRE ATT&CK | 確度  |
| :----------- | :---------------------------------- | :--------------------------------- | :----------- | :-- |
| C2通信         | `169.239.128.11` へのHTTP通信           | Suricataアラート、HTTPログ                | T1071.001    | 高   |
| 脅威インテリジェンス照合 | TA505 / MirrorBlastとの関連確認           | VirusTotal, MITRE ATT&CK, ベンダーレポート | -            | 中   |
| 追加ペイロード取得    | MSIファイルのダウンロード                      | NetworkMiner, Wireshark, HTTPログ    | T1105        | 高   |
| スクリプト実行基盤    | REBOL View関連ファイルの確認                 | HTTPペイロード内文字列                      | T1059の可能性    | 中   |
| 偽装           | `C:\ProgramData\Local\Google` パスの利用 | HTTPペイロード内文字列                      | T1036の可能性    | 低〜中 |

ATT&CKマッピングは、観測できた証拠の範囲に応じて確度を分ける必要がある。

`T1071.001` と `T1105` はネットワーク通信から比較的強く評価できる。一方、`T1059` や `T1036` はホスト上での実行や攻撃者の意図を確認する必要があるため、PCAP単体では「可能性」として扱う。

---

## 確認済みIOC一覧

| IOCタイプ               | 値                                                  | 備考                        |
| :------------------- | :------------------------------------------------- | :------------------------ |
| 感染疑い内部ホスト            | 172.16.1.102                                       | アラート送信元                   |
| C2疑いIP / Suricata検知先 | 169.239.128.11                                     | MirrorBlast C2アラートの宛先     |
| 関連ドメイン               | fidufagios.com                                     | VirusTotal Passive DNSで確認 |
| MSIダウンロード元IP         | 185.10.68.235                                      | `filter.msi` の取得元         |
| MSIダウンロード元IP         | 192.36.27.92                                       | `10opd3r_load.msi` の取得元   |
| ダウンロードファイル名          | filter.msi                                         | Windows Installer         |
| ダウンロードファイル名          | 10opd3r_load.msi                                   | Windows Installer         |
| ペイロード内パス文字列          | C:\ProgramData\001\arab.bin                        | 実作成はホスト証跡で確認が必要           |
| ペイロード内パス文字列          | C:\ProgramData\001\Action1_arab.exe                | 実作成はホスト証跡で確認が必要           |
| ペイロード内パス文字列          | C:\ProgramData\Local\Google\rebol-view-278-3-1.exe | REBOL View実行ファイルとみられる     |
| ペイロード内パス文字列          | C:\ProgramData\Local\Google\exemple.rb             | REBOLスクリプトとみられる           |
| User-Agent           | REBOL View 2.7.8.3.1                               | MirrorBlast関連TTPと整合       |
| Suricataシグネチャ        | ET MALWARE MirrorBlast CnC Activity M3             | MirrorBlast C2関連アラート      |

---

## 技術考察と防御

### TA505とMirrorBlastについて

TA505は、MITRE ATT&CKで `G0092` として追跡される金銭目的のサイバー犯罪グループである。2014年頃から活動が確認されており、大規模なメールキャンペーン、マルウェア配布、ランサムウェア関連活動などで知られている。

TA505は時期によって、Dridex、ServHelper、FlawedAmmyy、FlawedGrace、MirrorBlastなど複数のマルウェアやローダーを使い分けてきた。

MirrorBlast関連活動では、MSIファイルの利用、REBOL Viewを用いたスクリプト実行、HTTPベースのC2通信などが報告されている。本PCAPで確認されたSuricataアラート、User-Agent、MSIファイル、REBOL関連ファイルパスは、これらの既知TTPと整合する。

### 今回のPCAPから確認できたこと

今回のPCAPから確認できたことは以下である。

* 内部ホスト `172.16.1.102` から外部IP `169.239.128.11` への通信で、MirrorBlast C2関連アラートが発火した。
* HTTP User-Agentとして `REBOL View 2.7.8.3.1` が確認された。
* 関連外部IP `185.10.68.235` および `192.36.27.92` からMSIファイルが取得された。
* HTTPペイロード内に、`C:\ProgramData\...` 配下のファイルパス文字列が含まれていた。
* VirusTotal上で、関連IP・ドメインがTA505/MirrorBlast文脈と関連づけられていた。

### 今回のPCAPから確認できなかったこと

PCAP単体では、以下の情報は確認できない。

* 初期侵入ベクタ

  * フィッシングメールの本文
  * 添付ファイル
  * クリックされたURL
  * Web経由の初期感染経路
* ホスト上での実行有無

  * MSIが実際に実行されたか
  * `rebol-view-278-3-1.exe` が起動したか
  * `exemple.rb` が実行されたか
* 永続化の有無

  * Run Key
  * Scheduled Task
  * Service作成
  * Startup Folder
* 権限昇格の有無
* ラテラルムーブメントの有無
* 認証情報窃取の有無
* データ窃取の有無

ネットワークフォレンジックは、通信の有無や転送されたデータの一部を確認するには有効である。一方で、ホスト上で実際に何が起きたかを確定するには、EDRログ、Windowsイベントログ、ディスクイメージ、メモリダンプなどが必要である。

---

## 防御推奨事項

### 1. 感染疑いホストの隔離

内部ホスト `172.16.1.102` をネットワークから隔離し、追加通信を防止する。

隔離後、以下の証跡を取得する。

* メモリダンプ
* ディスクイメージ
* EDRイベント
* Windows Event Log
* Sysmonログ
* Prefetch
* Amcache
* ShimCache
* MFT
* USN Journal
* Browser History
* DNS Cache
* Scheduled Tasks
* Services
* Run Key

### 2. IOCのブロック

以下のIOCを、ファイアウォール、Proxy、DNSフィルタリング、EDR、SIEMに登録する。

* `169.239.128.11`
* `185.10.68.235`
* `192.36.27.92`
* `fidufagios.com`
* `REBOL View 2.7.8.3.1`
* `filter.msi`
* `10opd3r_load.msi`

ただし、IPアドレスやドメインは攻撃者によって変更される可能性があるため、IOCブロックだけに依存しない。

### 3. 検知ルールの整備

以下の観点で検知ルールを整備する。

* HTTP User-Agentに `REBOL View` を含む外部通信
* 外部サイトからの `.msi` ファイルダウンロード
* `C:\ProgramData\` 配下への不審な実行ファイル作成
* `C:\ProgramData\Local\Google\` のような正規ベンダーを模倣した不審パス
* MSI実行後の子プロセス生成
* `msiexec.exe` からの不審なプロセス起動
* `rebol-view-278-3-1.exe` の実行
* 拡張子 `.rb` の不審ファイル作成または実行

### 4. SIEMでの相関分析

単一イベントではなく、以下のイベントを相関させる。

| 相関条件                                         | 目的                  |
| :------------------------------------------- | :------------------ |
| IDSアラート + HTTP User-Agent `REBOL`            | MirrorBlast通信の検出    |
| `.msi` ダウンロード + `msiexec.exe` 実行             | MSI経由の感染確認          |
| `msiexec.exe` + `C:\ProgramData\` 配下へのファイル作成 | ペイロード展開確認           |
| REBOL実行ファイル + 外部通信                           | Rebol loaderのC2通信確認 |
| VirusTotal悪性IOC + 内部ホスト通信                    | 既知悪性インフラ通信の検出       |

### 5. 再発防止

再発防止策として、以下を検討する。

* メールセキュリティゲートウェイでのMSI添付・URL配布の制御
* Proxyでの実行ファイルダウンロード制御
* EDRによる `msiexec.exe` の不審な子プロセス監視
* アプリケーション制御による未知MSIの実行制限
* PowerShell、script interpreter、legacy interpreterの実行監視
* DNSフィルタリングと脅威インテリジェンス連携
* SOC PlaybookへのMirrorBlast/TA505調査手順の追加

---

## 学習記録

### Brim/Zuiのクエリについて

今回のRoomでは、Brim/Zuiを用いてSuricataアラートとHTTPログを確認した。

特に以下の操作が有効であった。

* `event_type=="alert"` によるSuricataアラート抽出
* `_path=="http"` によるHTTPログ抽出
* `cut` による必要フィールドの選択
* `count() by` による集計
* `sort count desc` による件数降順ソート
* `sort ... | uniq` による重複除去

`uniq` は隣接重複の除去であるため、再現性を高めるには事前に `sort` を行う必要がある。この点は、ログ調査において重要な注意点である。

### VirusTotalの活用について

VirusTotalでは、以下の観点を確認した。

* Passive DNS
* Communicating Files
* Community
* Detections
* Relations

Passive DNSは、IPアドレスとドメインの過去の関連を確認するうえで有効である。ただし、過去の関連を示す情報であり、現在も当該インフラがアクティブであることを単独で証明するものではない。

Community情報は、リサーチャーやベンダーによる文脈情報を得るうえで有用である。一方で、帰属判断の一次証拠として扱うべきではない。実務では、MITRE ATT&CK、ベンダーレポート、マルウェア解析、インフラ重複、TTPの一致などを総合して判断する必要がある。

### WiresharkとNetworkMinerの役割

Wiresharkは、TCP Streamを追跡し、HTTPペイロードの内容やUser-Agentなどの詳細を確認するのに適している。

NetworkMinerは、PCAPからファイルを再構成し、ファイル名、送信元IP、送信先IPの対応を把握するのに適している。

今回の調査では、Brim/Zuiでスコープを絞り、Wiresharkで詳細確認し、NetworkMinerでファイル対応を確認する流れが有効であった。

### 今後の調査項目

今後の学習課題は以下である。

* Suricataルールの構造と作成方法
* `ET MALWARE MirrorBlast CnC Activity M3` が具体的にどのHTTP条件を検知しているか
* MSIインストーラの静的解析方法
* REBOLスクリプトの静的解析方法
* `exemple.rb` の中身の解析
* Sysmonログを用いたMSI実行後の追跡
* TA505の他キャンペーンとの比較
* MirrorBlast、FlawedGrace、ServHelper、DridexのTTP比較
* PCAP調査からEDR調査へ引き継ぐためのSOC Playbook作成

---

## 参考

| タイトル                                                                              | URL                                                                                                               |
| :-------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------- |
| TryHackMe Warzone 1                                                               | https://tryhackme.com/room/warzoneone                                                                             |
| MITRE ATT&CK TA505 (G0092)                                                        | https://attack.mitre.org/groups/G0092/                                                                            |
| MITRE ATT&CK T1071.001                                                            | https://attack.mitre.org/techniques/T1071/001/                                                                    |
| MITRE ATT&CK T1105                                                                | https://attack.mitre.org/techniques/T1105/                                                                        |
| MITRE ATT&CK T1036                                                                | https://attack.mitre.org/techniques/T1036/                                                                        |
| Emerging Threats Rules                                                            | https://rules.emergingthreats.net/                                                                                |
| EveBox Rules - ET MALWARE MirrorBlast CnC Activity M3                             | https://rules.evebox.org/pub/et/open/2034023                                                                      |
| Brim/Zui Documentation                                                            | https://zui.brimdata.io/docs                                                                                      |
| Zed Language - sort operator                                                      | https://zed.brimdata.io/docs/language/operators/sort/                                                             |
| Zed Language - uniq operator                                                      | https://zed.brimdata.io/docs/language/operators/uniq/                                                             |
| CyberChef                                                                         | https://gchq.github.io/CyberChef/                                                                                 |
| VirusTotal                                                                        | https://www.virustotal.com/                                                                                       |
| Proofpoint - Whatta TA: TA505 Ramps Up Activity, Delivers New FlawedGrace Variant | https://www.proofpoint.com/us/blog/threat-insight/whatta-ta-ta505-ramps-activity-delivers-new-flawedgrace-variant |
