// Minimal i18n: a `locale` store, a reactive `t()` translator, and a `fontScale`
// (UI zoom). Translations aim for the idiomatic term used by the native OS/DFIR
// vocabulary in each locale, not a literal word-for-word rendering.
import { writable, derived } from 'svelte/store';

export type Locale = 'ja' | 'en' | 'zh' | 'hi' | 'fr' | 'de';

export const LOCALES: { code: Locale; label: string }[] = [
  { code: 'ja', label: '日本語' },
  { code: 'en', label: 'English' },
  { code: 'zh', label: '中文' },
  { code: 'hi', label: 'हिन्दी' },
  { code: 'fr', label: 'Français' },
  { code: 'de', label: 'Deutsch' }
];

// key -> per-locale string. `ja` is the source of truth / fallback; locales other
// than what is provided fall back to `ja` (see `t`).
const DICT: Record<string, Partial<Record<Locale, string>>> = {
  // --- nav groups ---
  'nav.summary': { ja: 'サマリ', en: 'Summary', zh: '概要', hi: 'सारांश', fr: 'Synthèse', de: 'Übersicht' },
  'nav.events': { ja: 'イベント / 探索', en: 'Events / Explore', zh: '事件 / 检索', hi: 'इवेंट / खोज', fr: 'Événements / Exploration', de: 'Ereignisse / Suche' },
  'nav.detection': { ja: '検知', en: 'Detection', zh: '检测', hi: 'पहचान', fr: 'Détection', de: 'Erkennung' },
  'nav.correlation': { ja: '相関', en: 'Correlation', zh: '关联', hi: 'सहसंबंध', fr: 'Corrélation', de: 'Korrelation' },
  'nav.workflow': { ja: '調査ワークフロー', en: 'Investigation', zh: '调查流程', hi: 'जाँच वर्कफ़्लो', fr: 'Investigation', de: 'Untersuchung' },
  'nav.evidence': { ja: '証跡 / 運用', en: 'Evidence / Ops', zh: '证据 / 运维', hi: 'साक्ष्य / संचालन', fr: 'Preuves / Exploitation', de: 'Nachweise / Betrieb' },
  'nav.settings': { ja: '設定', en: 'Settings', zh: '设置', hi: 'सेटिंग्स', fr: 'Paramètres', de: 'Einstellungen' },

  // --- tabs ---
  'tab.overview': { ja: '概要 / グラフ', en: 'Overview / Charts', zh: '概览 / 图表', hi: 'अवलोकन / चार्ट', fr: "Vue d'ensemble", de: 'Übersicht / Diagramme' },
  'tab.timeline': { ja: 'タイムライン', en: 'Timeline', zh: '时间线', hi: 'टाइमलाइन', fr: 'Chronologie', de: 'Zeitleiste' },
  'tab.risk': { ja: 'リスク', en: 'Risk', zh: '风险', hi: 'जोखिम', fr: 'Risque', de: 'Risiko' },
  'tab.events': { ja: 'イベント一覧', en: 'Events', zh: '事件列表', hi: 'इवेंट सूची', fr: 'Événements', de: 'Ereignisse' },
  'tab.search': { ja: '全文検索', en: 'Full-text search', zh: '全文检索', hi: 'पूर्ण-पाठ खोज', fr: 'Recherche plein texte', de: 'Volltextsuche' },
  'tab.saved_searches': { ja: '保存検索', en: 'Saved searches', zh: '已保存的搜索', hi: 'सहेजी गई खोज', fr: 'Recherches enregistrées', de: 'Gespeicherte Suchen' },
  'tab.hex': { ja: 'Hexビューア', en: 'Hex viewer', zh: 'Hex 查看器', hi: 'हेक्स व्यूअर', fr: 'Visionneuse Hex', de: 'Hex-Editor' },
  'tab.findings': { ja: '不審イベント', en: 'Suspicious events', zh: '可疑事件', hi: 'संदिग्ध इवेंट', fr: 'Événements suspects', de: 'Verdächtige Ereignisse' },
  'tab.ioc': { ja: 'IOC照合', en: 'IOC matching', zh: 'IOC 匹配', hi: 'IOC मिलान', fr: 'Correspondance IOC', de: 'IOC-Abgleich' },
  'tab.defender': { ja: 'Defender', en: 'Defender', zh: 'Defender', hi: 'Defender', fr: 'Defender', de: 'Defender' },
  'tab.answers': { ja: '調査候補', en: 'Answer candidates', zh: '调查候选', hi: 'जाँच सुझाव', fr: "Pistes d'enquête", de: 'Untersuchungshinweise' },
  'tab.correlation': { ja: '横断相関', en: 'Cross-artifact', zh: '横向关联', hi: 'क्रॉस-आर्टिफ़ैक्ट', fr: 'Corrélation croisée', de: 'Übergreifende Korrelation' },
  'tab.chains': { ja: '相関チェーン', en: 'Correlation chains', zh: '关联链', hi: 'सहसंबंध श्रृंखला', fr: 'Chaînes de corrélation', de: 'Korrelationsketten' },
  'tab.graph': { ja: '相関図', en: 'Correlation graph', zh: '关联图', hi: 'सहसंबंध ग्राफ़', fr: 'Graphe de corrélation', de: 'Korrelationsgraph' },
  'tab.triage': { ja: '調査キュー', en: 'Triage queue', zh: '调查队列', hi: 'ट्राइएज कतार', fr: 'File de triage', de: 'Triage-Warteschlange' },
  'tab.bookmarks': { ja: 'ブックマーク', en: 'Bookmarks', zh: '书签', hi: 'बुकमार्क', fr: 'Signets', de: 'Lesezeichen' },
  'tab.evaluation': { ja: 'ケース評価', en: 'Case evaluation', zh: '案件评估', hi: 'केस मूल्यांकन', fr: 'Évaluation du cas', de: 'Fallbewertung' },
  'tab.approvals': { ja: '成果物承認', en: 'Deliverable approvals', zh: '成果审批', hi: 'डिलिवरेबल स्वीकृति', fr: 'Validation des livrables', de: 'Freigaben' },
  'tab.evidence_ledger': { ja: '証拠台帳', en: 'Evidence ledger', zh: '证据台账', hi: 'साक्ष्य रजिस्टर', fr: 'Registre des preuves', de: 'Beweisregister' },
  'tab.files': { ja: 'ファイル管理', en: 'File management', zh: '文件管理', hi: 'फ़ाइल प्रबंधन', fr: 'Gestion des fichiers', de: 'Dateiverwaltung' },
  'tab.coverage': { ja: 'カバレッジ', en: 'Coverage', zh: '覆盖率', hi: 'कवरेज', fr: 'Couverture', de: 'Abdeckung' },
  'tab.audit': { ja: '監査ログ', en: 'Audit log', zh: '审计日志', hi: 'ऑडिट लॉग', fr: "Journal d'audit", de: 'Überwachungsprotokoll' },
  'tab.analyzers': { ja: 'アナライザ履歴', en: 'Analyzer history', zh: '分析器历史', hi: 'एनालाइज़र इतिहास', fr: 'Historique des analyseurs', de: 'Analyseverlauf' },
  'tab.jobs': { ja: 'ジョブ', en: 'Jobs', zh: '作业', hi: 'जॉब', fr: 'Tâches', de: 'Aufträge' },
  'tab.settings': { ja: '設定', en: 'Settings', zh: '设置', hi: 'सेटिंग्स', fr: 'Paramètres', de: 'Einstellungen' },

  // --- artifact subtabs ---
  'artifact.mft': { ja: 'MFT (ファイルシステム)', en: 'MFT (file system)', zh: 'MFT (文件系统)', hi: 'MFT (फ़ाइल सिस्टम)', fr: 'MFT (système de fichiers)', de: 'MFT (Dateisystem)' },
  'artifact.prefetch': { ja: 'Prefetch (実行履歴)', en: 'Prefetch (execution)', zh: 'Prefetch (执行记录)', hi: 'Prefetch (निष्पादन)', fr: "Prefetch (exécution)", de: 'Prefetch (Ausführung)' },
  'artifact.usn': { ja: 'USN (SJ変更履歴)', en: 'USN (change journal)', zh: 'USN (更改日志)', hi: 'USN (चेंज जर्नल)', fr: 'USN (journal des modifications)', de: 'USN (Änderungsjournal)' },
  'artifact.amcache': { ja: 'Amcache (実行痕跡)', en: 'Amcache (execution)', zh: 'Amcache (执行痕迹)', hi: 'Amcache (निष्पादन)', fr: "Amcache (exécution)", de: 'Amcache (Ausführung)' },
  'artifact.srum': { ja: 'SRUM (リソース/通信)', en: 'SRUM (resource/network)', zh: 'SRUM (资源/网络)', hi: 'SRUM (संसाधन/नेटवर्क)', fr: 'SRUM (ressources/réseau)', de: 'SRUM (Ressourcen/Netzwerk)' },
  'artifact.registry': { ja: 'Registry', en: 'Registry', zh: '注册表', hi: 'रजिस्ट्री', fr: 'Registre', de: 'Registrierung' },
  'artifact.text_observation': { ja: '観測ログ', en: 'Observed logs', zh: '观测日志', hi: 'अवलोकित लॉग', fr: 'Journaux observés', de: 'Beobachtete Protokolle' },

  // --- settings panel ---
  'settings.title': { ja: '設定', en: 'Settings', zh: '设置', hi: 'सेटिंग्स', fr: 'Paramètres', de: 'Einstellungen' },
  'settings.language': { ja: '言語', en: 'Language', zh: '语言', hi: 'भाषा', fr: 'Langue', de: 'Sprache' },
  'settings.language.hint': { ja: 'UIの表示言語を切り替えます。', en: 'Change the display language of the UI.', zh: '切换界面的显示语言。', hi: 'UI की प्रदर्शन भाषा बदलें।', fr: "Changer la langue d'affichage de l'interface.", de: 'Die Anzeigesprache der Oberfläche ändern.' },
  'settings.fontsize': { ja: '文字サイズ', en: 'Font size', zh: '字体大小', hi: 'फ़ॉन्ट आकार', fr: 'Taille du texte', de: 'Schriftgröße' },
  'settings.fontsize.hint': { ja: '画面全体の表示倍率を変更します。', en: 'Scale the whole UI up or down.', zh: '整体缩放界面显示。', hi: 'पूरे UI का आकार बड़ा/छोटा करें।', fr: "Agrandir ou réduire toute l'interface.", de: 'Die gesamte Oberfläche vergrößern oder verkleinern.' },
  'settings.size.small': { ja: '小', en: 'Small', zh: '小', hi: 'छोटा', fr: 'Petit', de: 'Klein' },
  'settings.size.normal': { ja: '標準', en: 'Normal', zh: '标准', hi: 'सामान्य', fr: 'Normal', de: 'Normal' },
  'settings.size.large': { ja: '大', en: 'Large', zh: '大', hi: 'बड़ा', fr: 'Grand', de: 'Groß' },
  'settings.size.xlarge': { ja: '特大', en: 'Extra large', zh: '特大', hi: 'बहुत बड़ा', fr: 'Très grand', de: 'Sehr groß' },
  'settings.note': { ja: '設定はこの端末に保存されます。', en: 'Settings are saved on this device.', zh: '设置保存在本机。', hi: 'सेटिंग्स इस डिवाइस पर सहेजी जाती हैं।', fr: 'Les paramètres sont enregistrés sur cet appareil.', de: 'Die Einstellungen werden auf diesem Gerät gespeichert.' },

  // --- triage funnel ---
  'funnel.collection': { ja: '収集', en: 'Collection' },
  'funnel.collection.sub': { ja: '取込イベント総数', en: 'Total ingested events' },
  'funnel.detection': { ja: '検知', en: 'Detection' },
  'funnel.detection.sub': { ja: '検知ヒット総数', en: 'Total detection hits' },
  'funnel.triage': { ja: 'トリアージ', en: 'Triage' },
  'funnel.triage.sub': { ja: '不審イベント種別', en: 'Suspicious event types' },
  'funnel.incident': { ja: 'インシデント', en: 'Incident' },

  // --- intake / progress ---
  'intake.done': { ja: '取り込み完了', en: 'Ingest complete' },
  'intake.loading': { ja: '証跡を読み込み中', en: 'Loading evidence' },
  'intake.ingesting': { ja: '証跡を取り込み中', en: 'Ingesting evidence' },
  'intake.parsing': { ja: '証跡を解析中', en: 'Parsing evidence' },
  'intake.scanning': { ja: 'ファイルを走査しています', en: 'Scanning files' },

  // --- hex viewer ---
  'hex.err.offset': { ja: 'オフセットが不正です (10進 または 0x.. で指定)', en: 'Invalid offset (use decimal or 0x..)' },
  'hex.searching': { ja: '検索中…', en: 'Searching…' },
  'hex.no_more_match': { ja: 'これ以降に一致なし', en: 'No further matches' },
  'hex.no_match': { ja: '一致なし', en: 'No match' },

  // --- case management ---
  'case.err.root_required': { ja: 'ケースルートを指定してください', en: 'Specify a case root' },
  'case.err.name_required': { ja: 'ケース名を指定してください', en: 'Specify a case name' },
  'case.hint.enter_root': { ja: 'ファイル管理タブでケースルートを入力してください', en: 'Enter a case root in the File management tab' },
  'case.err.picker_tauri_only': { ja: 'ケース作成のフォルダ選択はTauriアプリで利用してください。ブラウザ表示ではファイル管理タブのケースルート入力を使ってください。', en: 'Folder selection for case creation is only available in the Tauri app. In the browser, use the case-root input in the File management tab.' },
  'case.create_cancelled': { ja: 'ケース作成をキャンセルしました', en: 'Case creation cancelled' },
  'case.opened_existing': { ja: '既存ケースを開きました', en: 'Opened existing case' },
  'case.created': { ja: 'ケースを作成しました', en: 'Case created' },

  // --- common errors ---
  'err.open_case_first': { ja: '先にケースを作成または開いてください', en: 'Create or open a case first' },

  // --- reload ---
  'reload.reloaded': { ja: '現在の表示を再読み込みしました。', en: 'Reloaded the current view. ' },
  'reload.jobs_started': { ja: '分析ジョブを開始', en: 'Analysis jobs started' },
  'reload.readmodel_fresh': { ja: '分析read modelは最新です', en: 'Analysis read models are up to date' },

  // --- clear workspace ---
  'clear.confirm.head': { ja: 'ケースフォルダだけをクリアします。', en: 'This clears only the case folder.' },
  'clear.confirm.target': { ja: '対象', en: 'Target' },
  'clear.confirm.body': { ja: 'raw / inventory / lake / read_models / indexes / meta を削除します。取り込み元の元データは削除しません。', en: 'Deletes raw / inventory / lake / read_models / indexes / meta. The original source data is not deleted.' },
  'clear.done': { ja: 'ケースフォルダをクリアしました', en: 'Cleared the case folder' },
  'clear.root_removed': { ja: '（空になったケースルートも削除）', en: ' (also removed the now-empty case root)' },

  // --- ingest ---
  'ingest.err.path_required': { ja: '取り込むローカルパスを入力してください', en: 'Enter a local path to ingest' },
  'ingest.prefix.localpath': { ja: 'ローカルパス', en: 'Local path: ' },
  'ingest.prefix.folder': { ja: 'フォルダ', en: 'Folder: ' },
  'ingest.scanning_target': { ja: '取り込み対象を走査中', en: 'Scanning ingest target' },
  'ingest.ingesting': { ja: '取り込み中', en: 'Ingesting' },
  'ingest.rebuilding_index': { ja: '取り込み後の表示用インデックスを再構築中', en: 'Rebuilding display index after ingest' },
  'ingest.complete': { ja: '取り込み完了', en: 'Ingest complete' },
  'ingest.folder_cancelled': { ja: 'フォルダ取り込みをキャンセルしました', en: 'Folder ingest cancelled' },
  'ingest.rebuild_display': { ja: '表示用インデックスを再構築中', en: 'Rebuilding display index' },

  // --- common words ---
  'common.type': { ja: '種別', en: 'Type' },
  'common.user': { ja: 'ユーザー', en: 'User' },
  'common.host': { ja: 'ホスト', en: 'Host' },
  'common.list_all': { ja: '一覧', en: 'All' },
  'common.all': { ja: 'すべて', en: 'All' },
  'common.none': { ja: 'なし', en: 'None' },
  'common.artifact': { ja: 'アーティファクト', en: 'Artifact' },
  'common.save': { ja: '保存', en: 'Save' },
  'common.reload': { ja: '再読み込み', en: 'Reload' },
  'common.reload_short': { ja: '再読込', en: 'Reload' },
  'common.apply': { ja: '適用', en: 'Apply' },
  'common.reset': { ja: 'リセット', en: 'Reset' },
  'common.clear': { ja: 'クリア', en: 'Clear' },
  'common.create': { ja: '作成', en: 'Create' },
  'common.open': { ja: '開く', en: 'Open' },
  'common.delete': { ja: '削除', en: 'Delete' },
  'common.remove_mark': { ja: '解除', en: 'Remove' },
  'common.search': { ja: '検索', en: 'Search' },
  'common.severity': { ja: '重要度', en: 'Severity' },
  'common.count_suffix': { ja: '件', en: '' },
  'common.groups_suffix': { ja: 'グループ', en: 'groups' },
  'common.techniques_suffix': { ja: '技術', en: 'techniques' },
  'common.start_utc': { ja: '開始 (UTC)', en: 'Start (UTC)' },
  'common.end_utc': { ja: '終了 (UTC)', en: 'End (UTC)' },
  'common.fulltext': { ja: '全文検索', en: 'Full-text search' },
  'common.reason': { ja: '理由', en: 'Reason' },
  'common.status': { ja: '状態', en: 'Status' },
  'common.confidence': { ja: '確度', en: 'Confidence' },
  'common.window': { ja: '期間', en: 'Window' },
  'common.partial': { ja: '部分一致', en: 'partial match' },

  // --- view titles / filter summary ---
  'events.title.by_user': { ja: 'イベント一覧 / ユーザー別イベント', en: 'Events / By user' },
  'events.title.all': { ja: 'イベント一覧 / 全イベント', en: 'Events / All events' },
  'filter.search': { ja: '検索', en: 'Search' },
  'filter.quick': { ja: 'クイック', en: 'Quick' },
  'filter.regex_fulltext': { ja: '正規表現で全文検索', en: 'Regex full-text search' },

  // --- verify / approval ---
  'verify.err.bundle_path': { ja: '検証するレポートバンドルのパスを入力してください', en: 'Enter the path of the report bundle to verify' },
  'verify.err.manifest_path': { ja: '検証する保全マニフェストのパスを入力してください', en: 'Enter the path of the custody manifest to verify' },
  'approval.err.target': { ja: '承認対象のpathまたはidを入力してください', en: 'Enter the path or id of the approval target' },

  // --- correlation / risk / search index notices ---
  'corr.large_case_notice': { ja: '大規模ケースのため、タブ表示ではlake全体集計を実行しません。取り込み完了後に横断相関read modelをバックグラウンドで自動生成します。', en: 'This is a large case, so the tab view does not run a full-lake aggregation. The cross-artifact correlation read model is generated automatically in the background after ingest completes.' },
  'risk.readmodel_generating': { ja: '検知/相関分析read modelをバックグラウンドで生成中です', en: 'Generating the detection/correlation read model in the background' },
  'risk.no_findings_yet': { ja: 'ATT&CK technique付きFindingがまだありません。取り込み/再読み込み完了後に検知/相関分析read modelをバックグラウンドで自動生成します。', en: 'No findings with an ATT&CK technique yet. The detection/correlation read model is generated automatically in the background after ingest/reload completes.' },
  'search.index.building': { ja: '全文検索インデックスを構築中です。完了後にもう一度検索してください。', en: 'Building the full-text search index. Search again once it completes.' },
  'search.index.started': { ja: '全文検索インデックスが未構築でした。バックグラウンドで構築を開始しました。完了後にもう一度検索してください。', en: 'The full-text search index was not built. Started building it in the background. Search again once it completes.' },
  'saved.err.name_required': { ja: '保存検索名を入力してください', en: 'Enter a name for the saved search' },

  // --- ATT&CK / charts ---
  'tactic.none': { ja: '(戦術なし)', en: '(no tactic)' },
  'logon.success': { ja: 'ログオン成功', en: 'Logon success' },
  'logon.failure': { ja: 'ログオン失敗', en: 'Logon failure' },

  // --- confidence / severity level words ---
  'level.high': { ja: '高', en: 'High' },
  'level.medium': { ja: '中', en: 'Medium' },
  'level.low': { ja: '低', en: 'Low' },

  // --- finding next actions ---
  'nextaction.credential_access': { ja: '対象ホストの資格情報を無効化/リセットし、LSASS アクセス元プロセスと横展開先を追跡する。', en: 'Disable/reset the credentials on the affected host, and trace the process that accessed LSASS and any lateral-movement destinations.' },
  'nextaction.defense_evasion': { ja: 'ログ消去/防御無効化の直前後のアクティビティを重点確認し、後続ペイロードを特定する。', en: 'Focus on the activity just before and after log clearing / defense disabling, and identify the follow-on payload.' },
  'nextaction.persistence': { ja: '作成アカウント/権限付与/自動起動を棚卸しし、正当性を確認・除去する。', en: 'Inventory created accounts, privilege grants, and autostart entries; verify legitimacy and remove.' },
  'nextaction.execution': { ja: '実行元プロセス・コマンドライン・親プロセスを確認し、配布経路を追跡する。', en: 'Check the originating process, command line, and parent process, and trace the delivery path.' },
  'nextaction.default': { ja: '該当イベントの実行元(host/user/process)を確認し、時系列で前後の関連イベントを追跡する。', en: 'Check the origin of the event (host/user/process) and trace related events before and after it in time.' },

  // --- quick-filter presets (labels only; queries are DSL) ---
  'preset.mft.writable_exec': { ja: 'ユーザー領域の実行系', en: 'User-space executables' },
  'preset.delete_rename': { ja: '削除/リネーム', en: 'Delete/Rename' },
  'preset.timestomp': { ja: '時刻不整合', en: 'Time mismatch' },
  'preset.startup_persistence': { ja: 'Startup/Run痕跡', en: 'Startup/Run artifacts' },
  'preset.lolbin_exec': { ja: 'LOLBin実行', en: 'LOLBin execution' },
  'preset.user_writable_exec': { ja: 'ユーザー領域実行', en: 'User-space execution' },
  'preset.script_exec': { ja: 'スクリプト実行', en: 'Script execution' },
  'preset.with_finding': { ja: '検知付き', en: 'With finding' },
  'preset.destructive': { ja: '削除/破壊的変更', en: 'Destructive changes' },
  'preset.rename_chain': { ja: 'リネーム連鎖', en: 'Rename chain' },
  'preset.exec_file_change': { ja: '実行系ファイル変更', en: 'Executable file changes' },
  'preset.temp_appdata': { ja: 'Temp/AppData変更', en: 'Temp/AppData changes' },
  'preset.user_program': { ja: 'ユーザー領域プログラム', en: 'User-space programs' },
  'preset.admin_lolbin': { ja: '管理/LOLBin', en: 'Admin/LOLBin' },
  'preset.hash_present': { ja: 'Hashあり', en: 'Has hash' },
  'preset.network_dest': { ja: '通信先あり', en: 'Has network destination' },
  'preset.browser_fetch': { ja: 'ブラウザ/取得系', en: 'Browser/fetch tools' },
  'preset.script_network': { ja: 'スクリプト系通信', en: 'Script network activity' },
  'preset.admin_network': { ja: '管理系通信', en: 'Admin-tool network activity' },
  'preset.errors': { ja: 'エラー/失敗', en: 'Errors/failures' },
  'preset.url_ip': { ja: 'URL/IP含む', en: 'Contains URL/IP' },
  'preset.exec_script': { ja: '実行/スクリプト', en: 'Execution/scripts' },
  'preset.transfer_sync': { ja: '転送/同期', en: 'Transfer/sync' },
  'preset.high_plus': { ja: 'High以上', en: 'High and above' },
  'preset.user_writable_area': { ja: 'ユーザー書込領域', en: 'User-writable area' },

  // --- cross-artifact pivots ---
  'pivot.same_file': { ja: '同一ファイル', en: 'Same file' },
  'pivot.same_process': { ja: '同一プロセス', en: 'Same process' },
  'pivot.same_hash': { ja: '同一Hash', en: 'Same hash' },
  'pivot.same_ip': { ja: '同一IP', en: 'Same IP' },
  'pivot.same_url': { ja: '同一URL', en: 'Same URL' },
  'pivot.same_user': { ja: '同一ユーザー', en: 'Same user' },
  'pivot.same_host': { ja: '同一ホスト', en: 'Same host' },

  // --- find bar ---
  'find.placeholder': { ja: 'ページ内を検索', en: 'Search in page' },
  'find.prev': { ja: '前へ (Shift+Enter)', en: 'Previous (Shift+Enter)' },
  'find.next': { ja: '次へ (Enter)', en: 'Next (Enter)' },
  'find.close': { ja: '閉じる (Esc)', en: 'Close (Esc)' },

  // --- sidebar / topbar ---
  'subnav.all_events': { ja: '全イベント', en: 'All events' },
  'subnav.by_user': { ja: 'ユーザー別イベント', en: 'By user' },
  'sidebar.create_case': { ja: '＋ ケースを作成', en: '＋ Create case' },
  'sidebar.enter_case_root': { ja: 'ケースルート入力へ', en: 'Enter case root' },
  'sidebar.ingest_files': { ja: '＋ 証跡ファイルを取り込む', en: '＋ Ingest evidence files' },
  'sidebar.ingest_folder': { ja: '＋ フォルダごと取り込む（再帰）', en: '＋ Ingest a whole folder (recursive)' },
  'nav.back': { ja: '← 戻る', en: '← Back' },
  'hint.start_create_case': { ja: '左下の「ケースを作成」から開始してください', en: "Start from 'Create case' at the bottom left" },

  // --- overview metrics ---
  'ov.metric.files': { ja: 'ファイル数', en: 'Files' },
  'ov.metric.events': { ja: 'イベント数', en: 'Events' },
  'ov.metric.failed': { ja: '解析失敗', en: 'Parse failures' },
  'ov.metric.unsupported': { ja: '未対応', en: 'Unsupported' },

  // --- charts (overview) ---
  'chart.event_timeline': { ja: 'イベント発生タイムライン', en: 'Event timeline' },
  'chart.event_timeline.aria': { ja: 'イベント発生タイムライン (severity 積み上げ)', en: 'Event timeline (severity stacked)' },
  'chart.total': { ja: '計', en: 'total' },
  'chart.legend': { ja: '凡例', en: 'Legend' },
  'chart.triage_funnel': { ja: 'トリアージファネル', en: 'Triage funnel' },
  'funnel.collection_to_incident': { ja: '収集 → インシデント', en: 'Collection → Incident' },
  'funnel.tip.show_all': { ja: '全イベントを表示', en: 'Show all events' },
  'funnel.tip.show_finding': { ja: '検知フラグ付きイベントを表示', en: 'Show events flagged as findings' },
  'funnel.tip.to_suspicious': { ja: '不審イベント一覧へ', en: 'Go to suspicious events' },
  'funnel.tip.retention': { ja: '前段からの残存率', en: 'Retention from the previous stage' },
  'chart.timestomp_scatter': { ja: 'タイムスタンプ矛盾スキャッター', en: 'Timestamp inconsistency scatter' },
  'chart.timestomp_scatter.sub': { ja: '対角線から外れた点 = timestomping 疑い', en: 'Points off the diagonal = suspected timestomping' },
  'scatter.aria': { ja: '$SI 作成時刻 vs $FN 作成時刻', en: '$SI created time vs $FN created time' },
  'chart.click_to_events': { ja: 'クリックで該当イベントへ', en: 'Click to view matching events' },
  'scatter.axis_fn': { ja: '$FILE_NAME 作成 →', en: '$FILE_NAME created →' },
  'scatter.axis_si': { ja: '$STANDARD_INFO 作成 →', en: '$STANDARD_INFO created →' },
  'scatter.suspect': { ja: '偽装疑い', en: 'Suspected forgery' },
  'scatter.consistent': { ja: '整合', en: 'Consistent' },
  'scatter.explain': { ja: 'NTFS の $STANDARD_INFO と $FILE_NAME の作成時刻を全ファイルで突合(乖離1時間超を疑いと判定)。$SI は改変容易・$FN はカーネル管理のため、外れ値は timestomp の痕跡。点数が多い場合は最大1500点を代表抽出。', en: 'Matches the $STANDARD_INFO and $FILE_NAME creation times across all files (a gap over 1 hour is flagged as suspect). Because $SI is easy to tamper with while $FN is kernel-managed, outliers are traces of timestomping. When there are many points, up to 1500 representative points are sampled.' },
  'chart.attack_heatmap': { ja: 'ATT&CK ヒートマップ', en: 'ATT&CK heatmap' },
  'chart.attack_heatmap.sub': { ja: '戦術 × 時刻(UTC 0-23時) · 濃いほど検知が多い', en: 'Tactic × hour (UTC 0-23) · darker = more detections' },
  'chart.hour_suffix': { ja: '時', en: 'h' },
  'chart.process_tree': { ja: 'プロセスツリー', en: 'Process tree' },
  'chart.process_tree.sub': { ja: '親 → 子プロセス (process_created)', en: 'Parent → child process (process_created)' },
  // --- process tree (instance-level) tab ---
  'tab.process_tree': { ja: 'プロセスツリー', en: 'Process tree', zh: '进程树', hi: 'प्रोसेस ट्री', fr: 'Arbre de processus', de: 'Prozessbaum' },
  'ptree.sub': { ja: 'プロセス生成イベントから復元した親子系譜 (Sysmon GUID / PID)', en: 'Spawn ancestry reconstructed from process-creation events (Sysmon GUID / PID)' },
  'ptree.filter': { ja: 'プロセス名・コマンドラインで絞り込み', en: 'Filter by name or command line' },
  'ptree.expand_all': { ja: 'すべて展開', en: 'Expand all' },
  'ptree.collapse_all': { ja: 'すべて折りたたむ', en: 'Collapse all' },
  'ptree.processes': { ja: 'プロセス', en: 'processes' },
  'ptree.roots': { ja: 'ルート', en: 'roots' },
  'ptree.with_finding': { ja: '検知あり', en: 'with detections' },
  'ptree.drill_hint': { ja: 'クリックでこのプロセスのイベントを表示', en: 'Click to view this process in the event list' },
  'ptree.expand': { ja: '展開', en: 'Expand' },
  'ptree.collapse': { ja: '折りたたむ', en: 'Collapse' },
  'ptree.no_process_events': { ja: 'プロセス生成イベント (Sysmon EID1 / Security 4688) が見つかりません', en: 'No process-creation events (Sysmon EID 1 / Security 4688) found' },
  'ptree.truncated': { ja: '上限に達したため先頭のみ表示', en: 'showing the earliest nodes (cap reached)' },
  'ptree.reingest_hint': { ja: 'ツリーが平坦な場合はケースを再取り込みしてください (旧取込にはプロセスIDが含まれません)', en: 'If the tree is flat, re-ingest the case — older ingests lack process identity' },
  'ptree.detail.pid': { ja: 'プロセスID', en: 'Process ID' },
  'ptree.detail.user': { ja: 'ユーザー', en: 'User' },
  'ptree.detail.time': { ja: '実行時刻', en: 'Execution time' },
  'ptree.detail.cmdline': { ja: 'コマンドライン', en: 'Command line' },
  'ptree.detail.image': { ja: 'イメージパス', en: 'Image file path' },
  'ptree.detail.detection': { ja: '検知', en: 'Detection' },
  'ptree.view_events': { ja: '関連イベントを追う', en: 'Hunt for related events' },
  'ptree.select_hint': { ja: 'プロセスを選択すると詳細を表示します', en: 'Select a process to see its details' },
  'chart.fileop': { ja: 'ファイル操作ダイバージング', en: 'File-operation diverging' },
  'chart.fileop.legend': { ja: '作成↑ / 削除↓', en: 'created↑ / deleted↓' },
  'chart.op.created': { ja: '作成', en: 'created' },
  'chart.op.deleted': { ja: '削除', en: 'deleted' },
  'chart.op.renamed': { ja: '改名', en: 'renamed' },
  'chart.op.modified': { ja: '変更', en: 'modified' },
  'chart.logon': { ja: 'ログオン成功 / 失敗', en: 'Logon success / failure' },
  'chart.beacon': { ja: 'ビーコニング間隔ヒストグラム', en: 'Beaconing interval histogram' },
  'chart.beacon.sub_prefix': { ja: '宛先毎の接続間隔', en: 'Connection intervals per destination' },
  'chart.beacon.intervals': { ja: '間隔', en: 'intervals' },
  'chart.beacon.peak': { ja: 'ピーク', en: 'peak' },
  'chart.beacon.top_dest': { ja: '主な宛先', en: 'top destination' },
  'chart.beacon.note': { ja: '単一バケットへの突出は固定間隔ビーコン (C2) の兆候。', en: 'A spike in a single bucket is a sign of a fixed-interval beacon (C2).' },

  // --- empty states (charts) ---
  'empty.timeline': { ja: 'イベントを取り込むと時系列が表示されます', en: 'Ingest events to see the timeline' },
  'empty.funnel': { ja: 'イベントを取り込むとファネルが表示されます', en: 'Ingest events to see the funnel' },
  'empty.mft_scatter': { ja: 'MFT ($SI/$FN 作成時刻) を取り込むと表示されます', en: 'Ingest MFT ($SI/$FN creation times) to display this' },
  'empty.attack_heatmap': { ja: '戦術タグ付きの不審イベントがあると表示されます (enrichment には再取込が必要)', en: 'Shows once there are suspicious events with tactic tags (enrichment requires a re-ingest)' },
  'empty.process_tree': { ja: 'プロセス作成 (4688 / Sysmon 1) を取り込むと表示されます', en: 'Ingest process creation (4688 / Sysmon 1) to display this' },
  'empty.usn': { ja: 'USN ジャーナル ($J) を取り込むと表示されます', en: 'Ingest the USN journal ($J) to display this' },
  'empty.beacon': { ja: 'ネットワーク接続 (Sysmon 3 / FW 5156) を取り込むと表示されます', en: 'Ingest network connections (Sysmon 3 / FW 5156) to display this' },

  // --- donuts / risk breakdown ---
  'chart.breakdown': { ja: '内訳', en: 'breakdown' },
  'chart.type_breakdown': { ja: '種別内訳', en: 'Type breakdown' },
  'chart.risk_breakdown': { ja: 'リスク内訳', en: 'Risk breakdown' },
  'chart.risk_sev_breakdown': { ja: 'リスクの重大度内訳', en: 'Risk severity breakdown' },
  'risk.to_list': { ja: 'リスク一覧へ', en: 'Go to risk list' },
  'empty.risk': { ja: 'リスク集計はありません', en: 'No risk aggregation' },

  // --- case evaluation ---
  'eval.high_unreviewed': { ja: 'High未確認', en: 'High unreviewed' },
  'eval.quality_gate': { ja: '品質ゲート', en: 'Quality gate' },
  'eval.evaluated_at': { ja: '評価日時', en: 'Evaluated at' },
  'eval.objectives': { ja: '目的', en: 'Objectives' },

  // --- answer candidates ---
  'answers.extract': { ja: '候補抽出', en: 'Extract candidates' },
  'answers.gen_job': { ja: '生成ジョブ', en: 'Generation job' },
  'answers.candidates': { ja: '候補', en: 'Candidates' },
  'answers.conf80': { ja: '確度80%以上', en: 'Confidence ≥ 80%' },
  'answers.awaiting_recovery': { ja: '復元待ち', en: 'Awaiting recovery' },
  'answers.th.perspective': { ja: '観点', en: 'Aspect' },
  'answers.th.candidate': { ja: '候補値', en: 'Candidate value' },
  'answers.th.category': { ja: '分類', en: 'Category' },
  'empty.answers': { ja: '調査候補はありません', en: 'No answer candidates' },
  'answers.detail': { ja: '候補詳細', en: 'Candidate detail' },
  'answers.next_check': { ja: '次の確認', en: 'Next check' },
  'answers.evidence_events': { ja: '証拠イベント', en: 'Evidence events' },
  'answers.no_basis_events': { ja: '根拠イベントなし', en: 'No basis events' },
  'answers.evidence_ref': { ja: '証拠ref', en: 'Evidence refs' },
  'answers.no_evidence_ref': { ja: '証拠refなし', en: 'No evidence refs' },
  'answers.missing_steps': { ja: '不足手順', en: 'Missing steps' },
  'answers.no_extra_steps': { ja: '追加手順なし', en: 'No additional steps' },
  'answers.attributes': { ja: '属性', en: 'Attributes' },
  'answers.select_candidate': { ja: '候補を選択してください', en: 'Select a candidate' },

  // --- evidence ledger ---
  'ledger.verify': { ja: '検証', en: 'Verify' },
  'ledger.custody_manifest': { ja: '保全マニフェスト', en: 'Custody manifest' },
  'ledger.verify_manifest': { ja: 'マニフェスト検証', en: 'Verify manifest' },
  'ledger.report_bundle': { ja: 'レポートバンドル', en: 'Report bundle' },
  'ledger.verify_bundle': { ja: 'バンドル検証', en: 'Verify bundle' },
  'ledger.unverified': { ja: '未検証', en: 'Unverified' },
  'approval.record': { ja: '承認記録', en: 'Record approval' },

  // --- file management ---
  'files.case_root': { ja: 'ケースルート', en: 'Case root' },
  'files.case_name': { ja: 'ケース名', en: 'Case name' },
  'files.case_info': { ja: 'ケース情報 / 保全', en: 'Case info / custody' },
  'files.advanced_hide': { ja: '詳細/開発用入力を閉じる', en: 'Hide advanced / dev input' },
  'files.advanced_show': { ja: '詳細/開発用入力を表示', en: 'Show advanced / dev input' },
  'files.virtual_path': { ja: '仮想証跡パス', en: 'Virtual evidence path' },
  'files.virtual_text': { ja: '仮想証跡テキスト', en: 'Virtual evidence text' },
  'files.demo_ingest': { ja: 'デモ取込', en: 'Demo ingest' },
  'files.manual_localpath': { ja: '手入力ローカルパス', en: 'Manual local path' },
  'files.path_ingest': { ja: 'Path取込', en: 'Ingest path' },

  // --- intake status panel ---
  'intake.status': { ja: '取り込み状況', en: 'Ingest status' },
  'intake.final_total': { ja: '最終集計', en: 'Final total' },
  'intake.processing': { ja: '処理中', en: 'Processing' },
  'intake.coverage_by_artifact': { ja: 'アーティファクト別カバレッジ', en: 'Coverage by artifact' },
  'intake.no_coverage': { ja: 'まだカバレッジはありません', en: 'No coverage yet' },
  'intake.running_jobs': { ja: '実行中ジョブ', en: 'Running jobs' },
  'intake.no_running_jobs': { ja: '現在実行中の取り込みジョブはありません', en: 'No ingest jobs running' },
  'intake.recent_files': { ja: '直近ファイル', en: 'Recent files' },
  'intake.no_files': { ja: 'まだファイルはありません', en: 'No files yet' },

  // --- timeline ---
  'timeline.chart': { ja: 'チャート', en: 'Chart' },
  'timeline.heatmap': { ja: 'ヒートマップ', en: 'Heatmap' },
  'timeline.minute': { ja: '分', en: 'Min' },
  'timeline.hour': { ja: '時', en: 'Hour' },
  'timeline.day': { ja: '日', en: 'Day' },
  'timeline.week': { ja: '週', en: 'Week' },
  'timeline.markers': { ja: 'マーカー', en: 'Markers' },
  'timeline.markers.tip': { ja: 'finding/IOC/bookmark を時系列に重畳', en: 'Overlay finding/IOC/bookmark on the timeline' },
  'timeline.search.placeholder': { ja: 'path/hash/ip/action: "move.aspx", ip:… 等', en: 'path/hash/ip/action: "move.aspx", ip:… etc.' },
  'timeline.hint.cap_pre': { ja: '上限', en: 'Reached the cap of' },
  'timeline.hint.cap_post': { ja: 'ビンに達したため最新側のみ表示しています。', en: 'bins; showing only the most recent.' },
  'timeline.hint.agg_a': { ja: 'ビンを', en: 'bins aggregated into' },
  'timeline.hint.agg_b': { ja: '列に集約表示中（棒1本≈', en: 'columns (≈' },
  'timeline.hint.agg_c': { ja: 'ビン）。1本=1ビンで見るには粒度を粗く（時/日/週）するか、フィルタで範囲を絞ってください。', en: 'bins per bar). To see 1 bar = 1 bin, use a coarser granularity (hour/day/week) or narrow the range with filters.' },
  'timeline.dow_suffix': { ja: '曜', en: '' },
  'timeline.heatmap.legend_a': { ja: '曜日 × 時間帯 (UTC) の件数。濃いほど多い（最大', en: 'Counts by day-of-week × hour (UTC). Darker = more (max' },
  'timeline.heatmap.legend_b': { ja: '）。深夜/オフアワーの活動検知に。', en: '). Helps spot late-night / off-hours activity.' },
  'timeline.bins_suffix': { ja: 'ビン', en: 'bins' },
  'timeline.open_all_events': { ja: '全イベントで開く', en: 'Open all events' },
  'timeline.bar_hint': { ja: 'バーをクリックするとその時間帯のイベントを下に表示します。', en: "Click a bar to show that time window's events below." },
  'mark.detection': { ja: '検知', en: 'Detection' },
  'empty.no_match_events': { ja: 'フィルタ条件に一致するイベントがありません', en: 'No events match the filters' },
  'empty.timeline_heatmap': { ja: 'イベントを取り込むとヒートマップが表示されます', en: 'Ingest events to see the heatmap' },
  'empty.no_events_window': { ja: 'この時間帯のイベントはありません', en: 'No events in this time window' },

  // --- events tab ---
  'events.export.tip': { ja: 'エクスポート (CSV / JSONL)', en: 'Export (CSV / JSONL)' },
  'events.export': { ja: 'エクスポート', en: 'Export' },
  'events.download': { ja: 'ダウンロード', en: 'Download' },
  'events.eventid_comma': { ja: 'Event ID (カンマ区切り)', en: 'Event ID (comma-separated)' },
  'events.computer': { ja: 'コンピュータ', en: 'Computer' },
  'events.artifact': { ja: 'アーティファクト', en: 'Artifact' },
  'events.facet_field': { ja: '検索種別', en: 'Facet field' },
  'events.select_candidate': { ja: '候補を選択', en: 'Select a field' },
  'events.facet_value': { ja: '検索値', en: 'Facet value' },
  'events.select_value': { ja: '値を選択', en: 'Select a value' },

  // --- users list ---
  'users.list': { ja: 'ユーザー一覧', en: 'User list' },
  'users.max_risk': { ja: '最大リスク', en: 'Max risk' },
  'users.first_utc': { ja: '初回 (UTC)', en: 'First (UTC)' },
  'users.last_utc': { ja: '最終 (UTC)', en: 'Last (UTC)' },
  'users.user_events': { ja: 'ユーザー別イベント', en: 'User events' },
  'empty.user_events': { ja: 'ユーザーイベントはありません', en: 'No user events' },

  // --- saved searches ---
  'saved.viewer': { ja: '閲覧者', en: 'Viewer' },
  'saved.to_events': { ja: 'イベント一覧', en: 'Event list' },
  'empty.saved_searches': { ja: '保存検索はありません', en: 'No saved searches' },

  // --- full-text search index ---
  'search.start_build_job': { ja: '構築ジョブ開始', en: 'Start build job' },
  'search.not_built': { ja: '未構築', en: 'Not built' },
  'search.build_index': { ja: 'インデックスを構築', en: 'Build index' },
  'empty.search_results': { ja: '検索結果はありません', en: 'No search results' },

  // --- prefetch / artifact panels ---
  'prefetch.analysis': { ja: 'Prefetch分析', en: 'Prefetch analysis' },
  'artifact.preset': { ja: 'プリセット', en: 'Preset' },
  'artifact.finding_only': { ja: 'Findingのみ', en: 'Finding only' },
  'artifact.high_plus': { ja: 'High以上', en: 'High and above' },
  'artifact.loaded': { ja: '表示中', en: 'Loaded' },
  'artifact.more_hidden': { ja: '未表示あり', en: 'More not shown' },

  // --- suspicious events (findings) ---
  'findings.rule_detect': { ja: 'ルール検出 (sigma/ioc/yara)', en: 'Rule detections (sigma/ioc/yara)' },
  'findings.events_label': { ja: 'イベント', en: 'Events' },
  'empty.rule_detect': { ja: 'ルール検出はありません', en: 'No rule detections' },
  'findings.suggest': { ja: 'サジェスト', en: 'Suggestions' },
  'findings.suggest_sub': { ja: 'ヒューリスティック/相関 · 高スコア順', en: 'Heuristic/correlation · by score' },
  'empty.suggest': { ja: 'サジェストはありません', en: 'No suggestions' },
  'findings.detect_events': { ja: '検知イベント', en: 'Detection events' },
  'findings.save_review': { ja: 'レビュー保存', en: 'Save review' },
  'findings.override_sev': { ja: 'Severity上書き', en: 'Override severity' },
  'findings.suppress': { ja: '抑制', en: 'Suppress' },

  // --- finding detail ---
  'finding.detection_logic': { ja: '検知条件', en: 'Detection logic' },
  'finding.fp_notes': { ja: '誤検知の目安', en: 'False-positive notes' },
  'finding.reference': { ja: '参照', en: 'Reference' },
  'finding.affected': { ja: '影響対象', en: 'Affected' },
  'finding.next_action': { ja: '次アクション', en: 'Next action' },
  'finding.related': { ja: '関連', en: 'Related' },
  'finding.score': { ja: 'スコア', en: 'Score' },
  'finding.score.technique': { ja: '手法', en: 'technique' },
  'finding.score.rarity': { ja: '希少度', en: 'rarity' },
  'finding.score.base': { ja: '基点', en: 'base' },
  'finding.suppress_override': { ja: '抑制/上書き', en: 'Suppress/Override' },

  // --- IOC ---
  'ioc.match': { ja: '照合', en: 'Match' },
  'ioc.to_finding': { ja: 'Finding化', en: 'Convert to finding' },
  'ioc.events': { ja: 'IOCイベント', en: 'IOC events' },

  // --- Defender ---
  'defender.aggregate': { ja: 'Defender集約', en: 'Defender aggregate' },
  'defender.events': { ja: 'Defenderイベント', en: 'Defender events' },
  'defender.source': { ja: 'ソース', en: 'Source' },

  // --- Hex viewer ---
  'hex.files': { ja: 'ファイル', en: 'Files' },
  'hex.file': { ja: 'ファイル', en: 'File' },
  'hex.size': { ja: 'サイズ', en: 'Size' },
  'hex.no_files': { ja: 'ファイルがありません（ケースを取り込むと表示されます）。', en: 'No files (they appear once a case is ingested).' },
  'hex.prev': { ja: '前の', en: 'Prev ' },
  'hex.next': { ja: '次の', en: 'Next ' },
  'hex.goto_placeholder': { ja: 'offset (10進 / 0x..)', en: 'offset (decimal / 0x..)' },
  'hex.goto': { ja: '移動', en: 'Go' },
  'hex.search_placeholder': { ja: '検索: 文字列 / HEX (4d 5a)', en: 'Search: string / HEX (4d 5a)' },
  'hex.search_as_hex': { ja: 'HEXバイト列として検索', en: 'Search as a HEX byte sequence' },
  'hex.next_match': { ja: '次へ', en: 'Next' },
  'hex.select_hint': { ja: '左のファイルを選択するとバイト列(hex)を表示します。', en: 'Select a file on the left to view its bytes (hex).' },
  'hex.loading': { ja: '読み込み中…', en: 'Loading…' },
  'hex.more': { ja: '続きあり', en: 'more available' },
  'common.error': { ja: 'エラー', en: 'Error' },

  // --- correlation / chains / graph ---
  'empty.correlation': { ja: '横断相関はありません', en: 'No cross-artifact correlations' },
  'empty.chains': { ja: '相関チェーンはありません', en: 'No correlation chains' },
  'chains.evidence_events': { ja: '根拠イベント', en: 'Evidence events' },

  // --- risk tab ---
  'risk.title': { ja: 'リスク（ATT&CK 技術別）', en: 'Risk (by ATT&CK technique)' },
  'risk.intro': { ja: '検知(finding)を ATT&CK 技術ごとに集約したケースの攻撃面ビューです。重大度の内訳と、技術ごとの件数・初回/最終観測を俯瞰できます。行をクリックすると不審イベント一覧へ移動します。', en: 'An attack-surface view of the case that aggregates findings by ATT&CK technique. It shows the severity breakdown and, per technique, the counts and first/last observations. Click a row to jump to the suspicious events.' },
  'risk.to_suspicious': { ja: '不審イベントへ', en: 'Go to suspicious events' },

  // --- investigation / detail pane ---
  'detail.resize_aria': { ja: '調査ペインの高さを調整', en: 'Adjust the investigation pane height' },
  'detail.pane': { ja: '調査ペイン', en: 'Investigation pane' },
  'detail.bookmark_remove': { ja: 'Bookmark解除', en: 'Remove bookmark' },
  'detail.reload_detail': { ja: '詳細を再読込', en: 'Reload details' },
  'detail.load_detail': { ja: '詳細を読み込む', en: 'Load details' },
  'detail.reload_structure': { ja: '構造を再読込', en: 'Reload structure' },
  'detail.load_structure': { ja: '構造を読み込む', en: 'Load structure' },
  'detail.loading_structure': { ja: '構造オブジェクト / 証拠オフセットを取得中', en: 'Loading structure objects / evidence offsets' },
  'detail.loading_detail': { ja: '詳細を取得中', en: 'Loading details' },
  'detail.lazy_hint': { ja: 'クリック直後は一覧行だけで表示します。必要な詳細だけ読み込みます', en: 'Right after clicking, only the list row is shown; load just the details you need.' },
  'detail.cross_pivot': { ja: '横断ピボット', en: 'Cross pivot' },
  'detail.structure_fields': { ja: '構造フィールド', en: 'Structure fields' },
  'detail.structure_objects': { ja: '構造オブジェクト', en: 'Structure objects' },
  'detail.evidence_offsets': { ja: '証拠オフセット', en: 'Evidence offsets' },
  'detail.surrounding': { ja: '前後のイベント', en: 'Surrounding events' },
  'detail.min_suffix': { ja: '分', en: 'min' },
  'detail.same_host_only': { ja: '同一ホストのみ', en: 'Same host only' }
};

const LOCALE_KEY = 'taotie.locale';
const SCALE_KEY = 'taotie.fontScale';

function readStored<T extends string>(key: string, allowed: readonly T[], fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    if (v && (allowed as readonly string[]).includes(v)) return v as T;
  } catch {
    /* ignore */
  }
  return fallback;
}

export const locale = writable<Locale>(
  readStored(
    LOCALE_KEY,
    LOCALES.map((l) => l.code),
    'ja'
  )
);
locale.subscribe((l) => {
  try {
    localStorage.setItem(LOCALE_KEY, l);
  } catch {
    /* ignore */
  }
});

/** Reactive translator: `$t('tab.overview')`. Unknown keys return the key. */
export const t = derived(locale, ($l) => (key: string): string => {
  const entry = DICT[key];
  if (!entry) return key;
  return entry[$l] ?? entry.ja ?? key;
});

// --- font size (whole-UI zoom, works for the px-based CSS) ---
export type FontScale = 'small' | 'normal' | 'large' | 'xlarge';
export const FONT_SCALES: FontScale[] = ['small', 'normal', 'large', 'xlarge'];
const ZOOM: Record<FontScale, string> = {
  small: '0.9',
  normal: '1',
  large: '1.12',
  xlarge: '1.25'
};

export const fontScale = writable<FontScale>(readStored(SCALE_KEY, FONT_SCALES, 'normal'));
fontScale.subscribe((s) => {
  try {
    localStorage.setItem(SCALE_KEY, s);
  } catch {
    /* ignore */
  }
  if (typeof document !== 'undefined') {
    // `zoom` scales the whole px-based UI proportionally in the WebKit webview.
    (document.documentElement.style as unknown as { zoom: string }).zoom = ZOOM[s];
  }
});
