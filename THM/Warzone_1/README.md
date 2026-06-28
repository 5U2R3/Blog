# TryHackMe - Warzone 1  
## はじめに
本記事はTryHackMe Warzone 1のWriteUpです。
Warzone 1はMSSPのTier1 セキュリティアナリストとして働き、  
ネットワークアラートの監視を担当している

| 項目 | 値 |
| :--- | :--- |
| Room | Warzone 1 |
| URL | https://tryhackme.com/room/warzoneone |
| カテゴリ | Network |
| OS | Linux |
| Tool | Brim, Wireshark, CyberChef, VirusTotal,  |
| 技術タグ | TA505, T1071.001, T1105 |
| 作成日 | 2026/06/28 |

## 結論サマリー
内部ホスト（172.16.1.102）が脅威アクターTA505帰属のMirrorBlastキャンペーンのC2インフラと通信し、  
MirrorBlastマルウェアのMSIインストーラを複数ダウンロードした事実をPCAP解析によって確認した。  
そのため、本アラートはTrue Positiveと判定した。  
このシナリオは現実のSOC業務におけるアラートトリアージおよび初動調査フェーズに対応している。  
IDS/IPSの検知シグネチャを起点として、外部脅威インテリジェンスによる帰属の確認とネットワークフォレンジクスによる証拠の確定を組み合わせるワークフローを扱っている。

## 調査方針
アラート発生時のPCAPが提供されます。  
Brimからアラート内容を確認する。  
アラートに紐づく送信元IP、送信先IP、ドメインを収集する。


## アーティファクト分析(アラートトリアージとPCAP初期解析)
### What was the alert signature for Malware Command and Control Activity Detected?
### What is the source IP address? Enter your answer in a defanged format. 
### What IP address was the destination IP in the alert? Enter your answer in a defanged format. 
### Inspect the web traffic for the flagged IP address; what is the user-agent in the traffic?
### Retrace the attack; there were multiple IP addresses associated with this attack. What were two other IP addresses? Enter the IP addressed defanged and in numerical order. (format: IPADDR,IPADDR)
### What were the file names of the downloaded files? Enter the answer in the order to the IP addresses from the previous question. (format: file.xyz,file.xyz)
### Inspect the traffic for the first downloaded file from the previous question. Two files will be saved to the same directory. What is the full file path of the directory and the name of the two files? (format: C:\path\file.xyz,C:\path\file.xyz)
### Now do the same and inspect the traffic from the second downloaded file. Two files will be saved to the same directory. What is the full file path of the directory and the name of the two files? (format: C:\path\file.xyz,C:\path\file.xyz)
## 脅威インテリジェンス分析
### Still in VirusTotal, under Community, what threat group is attributed to this IP address?
### What is the malware family?
### Do a search in VirusTotal for the domain from question 4. What was the majority file type listed under Communicating Files?
## 攻撃シーケンス再構成
## True Positive判定
## 調査チェーンサマリー
## 技術考察と防御
## 学習記録
## 参考
