// Raw-EVTX persistence coverage (Tier-3 false-negative fix).
//
// For the app's own raw .evtx parser, each EventData field is a separate column. The
// persistence rule engine matches against buildEvtxHaystack(row); previously raw-EVTX
// EventData fields (Signed, ImageLoaded, ObjectDN, MemberName, ObjectName, …) were never
// selected into the row, so payloadFilter-gated rules (Sysmon 6/7, AD 5136/5137/5141,
// Security 4657) silently never fired. These tests lock in that they now do.

const test = require("node:test");
const assert = require("node:assert/strict");

const { getPersistenceAnalysis } = require("../electron/analyzers/persistence");

// Stub db: prepare().all() aliases "c<idx> as [alias]" from the SELECT into row props
// (same pattern as persistence.test.js); WHERE/params are ignored.
function makeStub(headers, rows) {
  const colMap = {};
  headers.forEach((h, i) => { colMap[h] = `c${i}`; });
  const rowsByCN = rows.map((r, i) => {
    const out = { _rowid: i + 1 };
    headers.forEach((h) => { out[colMap[h]] = r[h] != null ? String(r[h]) : null; });
    return out;
  });
  function aliasRows(sql) {
    const aliasMatches = [...sql.matchAll(/c(\d+)\s+as\s+\[([a-zA-Z0-9_]+)\]/g)];
    return rowsByCN.map((r) => {
      const out = { _rowid: r._rowid };
      for (const [, idx, alias] of aliasMatches) out[alias] = r[`c${idx}`];
      return out;
    });
  }
  const db = {
    prepare(sql) {
      return {
        get() { return /COUNT\(\*\)/i.test(sql) ? { cnt: rowsByCN.length || 1 } : null; },
        all() {
          if (/^SELECT\s/i.test(sql) && /FROM\s+data/i.test(sql) && /\bas\s+\[/.test(sql)) return aliasRows(sql);
          return [];
        },
      };
    },
  };
  const meta = { db, headers, colMap, tabId: "persist-raw-evtx" };
  const ctx = { applyStandardFilters() {}, ensureIndex() {} };
  return { meta, ctx };
}

function analyzeRaw(headers, rows) {
  const { meta, ctx } = makeStub(headers, rows);
  return getPersistenceAnalysis(meta, { mode: "evtx" }, ctx);
}

const COMMON = { Channel: "", datetime: "2026-03-15T10:00:00Z", Computer: "HOST-A" };
const row = (extra) => ({ ...COMMON, ...extra });

test("raw EVTX: Sysmon EID 6 unsigned driver (BYOVD) now fires", () => {
  const headers = ["EventID", "Channel", "datetime", "Computer", "ImageLoaded", "Signed", "SignatureStatus", "Signer"];
  const result = analyzeRaw(headers, [row({
    EventID: "6", Channel: "Microsoft-Windows-Sysmon/Operational",
    ImageLoaded: "C:\\Windows\\Temp\\evil.sys", Signed: "false", SignatureStatus: "Unavailable", Signer: "",
  })]);
  const item = result.items.find((i) => i.name === "Suspicious Driver Loaded");
  assert.ok(item, "EID 6 unsigned-driver rule must fire on raw EVTX");
  assert.equal(item.category, "Driver Loading");
  assert.equal(item.severity, "critical");
  assert.match(item.details.imageLoaded || "", /evil\.sys/);
  assert.equal(item.details.signed, "false");
});

test("raw EVTX: Sysmon EID 6 signed driver does NOT fire (negative control)", () => {
  const headers = ["EventID", "Channel", "datetime", "Computer", "ImageLoaded", "Signed", "SignatureStatus", "Signer"];
  const result = analyzeRaw(headers, [row({
    EventID: "6", Channel: "Microsoft-Windows-Sysmon/Operational",
    ImageLoaded: "C:\\Windows\\System32\\drivers\\good.sys", Signed: "true", SignatureStatus: "Valid", Signer: "Microsoft Windows",
  })]);
  assert.equal(result.items.find((i) => i.name === "Suspicious Driver Loaded"), undefined,
    "a validly-signed driver must not be flagged");
});

test("raw EVTX: Sysmon EID 7 unsigned DLL load now fires", () => {
  const headers = ["EventID", "Channel", "datetime", "Computer", "ImageLoaded", "Signed", "SignatureStatus", "Image"];
  const result = analyzeRaw(headers, [row({
    EventID: "7", Channel: "Microsoft-Windows-Sysmon/Operational",
    ImageLoaded: "C:\\Users\\v\\AppData\\Local\\Temp\\evil.dll", Signed: "false", SignatureStatus: "Unavailable",
    Image: "C:\\Windows\\System32\\svchost.exe",
  })]);
  const item = result.items.find((i) => i.name === "Unsigned DLL Loaded");
  assert.ok(item, "EID 7 unsigned-DLL rule must fire on raw EVTX");
  assert.match(item.details.imageLoaded || "", /evil\.dll/);
});

test("raw EVTX: Security 5136 AD object modification (SPN / shadow creds) now fires", () => {
  const headers = ["EventID", "Channel", "datetime", "Computer", "ObjectDN", "ObjectClass", "AttributeLDAPDisplayName", "AttributeValue", "OperationType", "SubjectUserName"];
  const result = analyzeRaw(headers, [row({
    EventID: "5136", Channel: "Security",
    ObjectDN: "CN=svc-sql,CN=Users,DC=corp,DC=local", ObjectClass: "user",
    AttributeLDAPDisplayName: "servicePrincipalName", AttributeValue: "HTTP/evil.corp.local",
    OperationType: "%%14674", SubjectUserName: "attacker",
  })]);
  const item = result.items.find((i) => i.name === "AD Object Modified");
  assert.ok(item, "5136 AD persistence rule must fire on raw EVTX");
  assert.equal(item.category, "Domain Persistence");
  assert.match(item.details.attributeName || "", /servicePrincipalName/);
  assert.match(item.details.objectDN || "", /svc-sql/);
});

test("raw EVTX: Security 4657 registry Run-key modification now fires", () => {
  const headers = ["EventID", "Channel", "datetime", "Computer", "ObjectName", "ObjectValueName", "NewValue", "OldValue", "ProcessName", "SubjectUserName"];
  const result = analyzeRaw(headers, [row({
    EventID: "4657", Channel: "Security",
    ObjectName: "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    ObjectValueName: "Updater", NewValue: "C:\\Temp\\evil.exe", OldValue: "(NONE)",
    ProcessName: "C:\\Windows\\System32\\reg.exe", SubjectUserName: "attacker",
  })]);
  const item = result.items.find((i) => i.name === "Registry Value Modified (4657)");
  assert.ok(item, "4657 registry-autorun rule must fire on raw EVTX");
  assert.match(item.details.targetObject || "", /\\Run/);
  assert.match(item.details.newValue || "", /evil\.exe/);
});

test("raw EVTX: Security 4728 group membership extracts MemberName", () => {
  const headers = ["EventID", "Channel", "datetime", "Computer", "TargetUserName", "MemberName", "SubjectUserName"];
  const result = analyzeRaw(headers, [row({
    EventID: "4728", Channel: "Security",
    TargetUserName: "Domain Admins", MemberName: "CN=attacker,CN=Users,DC=corp,DC=local", SubjectUserName: "admin",
  })]);
  const item = result.items.find((i) => i.name === "Member Added to Global Security Group");
  assert.ok(item, "4728 group-membership rule must fire on raw EVTX");
  assert.match(item.details.memberName || "", /attacker/);
  assert.match(item.details.groupName || "", /Domain Admins/);
});
