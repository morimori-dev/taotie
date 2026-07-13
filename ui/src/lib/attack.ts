// MITRE ATT&CK technique ID -> 日本語名の最小マップ（不審イベントで使う技術のみ）。
// 未登録IDは ID をそのまま表示し、URL は ID から生成する。
export const ATTACK_TECHNIQUES: Record<string, string> = {
  T1003: '資格情報ダンプ',
  'T1003.001': 'LSASS メモリ',
  'T1003.003': 'NTDS',
  T1027: '難読化',
  T1036: 'マスカレード',
  T1047: 'WMI',
  T1053: 'スケジュールタスク',
  'T1053.005': 'スケジュールタスク',
  T1055: 'プロセスインジェクション',
  T1059: 'コマンド/スクリプト実行',
  'T1059.001': 'PowerShell',
  'T1059.003': 'Windows コマンドシェル',
  T1070: '痕跡消去',
  'T1070.001': 'Windows イベントログ消去',
  'T1070.004': 'ファイル削除',
  'T1070.006': 'タイムストンプ',
  T1071: 'アプリ層プロトコル C2',
  T1098: 'アカウント操作',
  T1105: 'ツール転送(ダウンロード)',
  T1112: 'レジストリ改ざん',
  T1136: 'アカウント作成',
  'T1136.001': 'ローカルアカウント作成',
  T1197: 'BITS ジョブ',
  T1204: 'ユーザー実行',
  T1218: '署名済バイナリ悪用(LOLBin)',
  'T1218.005': 'Mshta',
  'T1218.010': 'Regsvr32',
  'T1218.011': 'Rundll32',
  T1490: 'シャドウコピー削除',
  T1543: 'サービス作成',
  'T1543.003': 'Windows サービス',
  T1547: '自動起動(永続化)',
  'T1547.001': 'Run キー / スタートアップ',
  T1548: '昇格制御バイパス(UAC)',
  'T1558.003': 'Kerberoasting',
  'T1558.004': 'AS-REP Roasting',
  T1562: '防御回避(無効化)',
  'T1562.001': '防御ツールの無効化',
  T1569: 'システムサービス',
  'T1569.002': 'サービス実行',
};

export function attackName(id: string): string {
  return ATTACK_TECHNIQUES[id] ?? id;
}

// "T1070.001" -> https://attack.mitre.org/techniques/T1070/001/
export function attackUrl(id: string): string {
  const parts = id.trim().toUpperCase().split('.');
  const base = parts[0];
  const sub = parts[1];
  return sub
    ? `https://attack.mitre.org/techniques/${base}/${sub}/`
    : `https://attack.mitre.org/techniques/${base}/`;
}
