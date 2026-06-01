const { cleanWrappedField, compactGet, compactGetInt, extractFirstInteger, isChainsawLogonDataset, isHayabusaDataset, parseCompactKeyValues, resolveEventChannel } = require("../evtx-utils");
const { detectConventions, generateConventionFindings } = require("./convention-detector");
const { buildGraphAndChains } = require("./build-graph");
const { detectCredentialAttacks } = require("./detectors/credential-attacks");
const { createEvidenceHelpers } = require("./evidence");
const { createTelemetryTracker } = require("./telemetry");
const { correlateTriageAndCluster } = require("./processing/triage-and-clustering");
const { clusterCampaignsAndEnrich } = require("./processing/campaign-clustering");
const { scoreRdpSessions } = require("./processing/rdp-scoring");
const { aggregateAccounts } = require("./assemble/accounts");
const { computeSysmonRdpAndCoverage } = require("./processing/sysmon-rdp-coverage");
const { detectAdminShareAndExecution } = require("./detectors/admin-share-and-execution");
const { runProcessServiceScan } = require("./detectors/process-service-scan");
const {
  EXCLUDED_IPS,
  SERVICE_RE,
  SESSION_ONLY_EVENTS,
  RDP_EVENT_DESC,
  DC_PAT: _DC_PAT,
  SRV_PAT: _SRV_PAT,
  MGMT_SRC_PAT: _MGMT_SRC_PAT,
  SEV_ORDER: sevOrder,
  TELEMETRY_CATEGORIES,
  PRIVILEGED_NAME_RE,
} = require("./constants");

/**
 * Lateral Movement analysis — extracted from TimelineDB.getLateralMovement().
 *
 * @param {object} meta   - Database handle: {db, headers, colMap, tabId}
 * @param {object} options - Analysis options (eventIds, excludeLocalLogons, etc.)
 * @param {object} ctx    - Helper methods from TimelineDB instance:
 *   { applyStandardFilters, cleanWrappedField, compactGet, compactGetInt,
 *     ensureIndex, extractFirstInteger, isChainsawLogonDataset,
 *     isHayabusaDataset, lmPreviewCache, parseCompactKeyValues,
 *     resolveEventChannel }
 * @returns {object} Analysis results: { nodes, edges, chains, rdpSessions, findings, ... }
 */
function getLateralMovement(meta, options = {}, ctx) {
    if (!meta) return { nodes: [], edges: [], chains: [], stats: {}, columns: {}, error: "No database" };

    const {
      sourceCol: userSourceCol, targetCol: userTargetCol,
      userCol: userUserCol, logonTypeCol: userLogonTypeCol,
      eventIdCol: userEventIdCol, tsCol: userTsCol, domainCol: userDomainCol,
      syntheticTargetHost = "",
      eventIds = ["4624","4625","4634","4647","4648","4672","4769","4771","4776","4778","4779","5140","5145","1149","20","21","22","23","24","25","32","33","34","35","39","40"],
      excludeLocalLogons = true,
      excludeServiceAccounts = true,
      maxRows = 500000,
      disabledDetectors = [],
      rmmMode = "all",
      scanLimits = {},
      scanPageSize = 5000,
      requireMicrosoftSignature = false,
    } = options;
    const _disabledSet = new Set(disabledDetectors);

    const detect = (patterns) => {
      for (const pat of patterns) {
        const found = meta.headers.find((h) => pat.test(h));
        if (found) return found;
      }
      return null;
    };

    // Detect EvtxECmd format (KAPE output): RemoteHost, PayloadData1-6
    const isEvtxECmd = meta.headers.some((h) => /^RemoteHost$/i.test(h)) && meta.headers.some((h) => /^PayloadData1$/i.test(h));
    const isHayabusa = isHayabusaDataset(meta);
    const isChainsaw = isChainsawLogonDataset(meta);
    const detailsCol = isHayabusa ? detect([/^Details$/i]) : null;
    const extraCol = isHayabusa ? detect([/^ExtraFieldInfo$/i]) : null;
    // Detect raw EVTX TerminalServices logs (LocalSessionManager/RemoteConnectionManager)
    // These have Address/Param3 as source IP, User/Param1 as user, SessionID as session
    const isRawEvtx = !isEvtxECmd && !isHayabusa && !isChainsaw
      && meta.headers.some(h => /^datetime$/i.test(h)) && meta.headers.some(h => /^Provider$/i.test(h));
    const isTermSvcEvtx = isRawEvtx && (
      meta.headers.some(h => /^SessionID$/i.test(h)) || meta.headers.some(h => /^Param1$/i.test(h))
    );

    const columns = {
      source:      userSourceCol    || detect([/^IpAddress$/i, /^SourceNetworkAddress$/i, /^SourceAddress$/i, /^Source_Network_Address$/i, /^RemoteHost$/i, ...(isChainsaw ? [/^source_ip$/i] : []), ...(isTermSvcEvtx ? [/^Address$/i, /^Param3$/i] : [])]) || detailsCol,
      workstation: detect([/^WorkstationName$/i, /^Workstation_Name$/i, /^SourceHostname$/i, /^SourceComputerName$/i, ...(isChainsaw ? [/^workstation_name$/i] : [])]),
      target:      userTargetCol    || detect([/^Computer$/i, /^ComputerName$/i, /^computer_name$/i, /^Hostname$/i]),
      // EvtxECmd column priority: prefer PayloadData1 ("Target: DOMAIN\\User") over the
      // raw UserName column. EvtxECmd's UserName is the *Subject* (initiator) of the event,
      // which for service/system-context logons is literally "-\\-" — picking it leaves the
      // standard parser unable to extract a username and accounts aggregation collapses.
      // PayloadData1 carries the *Target* user we actually want to graph by.
      user:        userUserCol      || detect([/^TargetUserName$/i, /^Target_User_Name$/i, ...(isEvtxECmd ? [/^PayloadData1$/i] : []), /^UserName$/i, ...(isChainsaw ? [/^target_username$/i] : []), ...(isTermSvcEvtx ? [/^User$/i, /^Param1$/i] : [])]) || detailsCol,
      // EvtxECmd-only fallback: when PayloadData1 doesn't carry a "Target:" prefix
      // (e.g. 4672 PrivilegeList rows), look at UserName which often holds
      // "DOMAIN\\user (SID)" — strip the SID suffix and use that.
      _userNameFallback: isEvtxECmd ? detect([/^UserName$/i]) : null,
      logonType:   userLogonTypeCol || detect([/^LogonType$/i, /^Logon_Type$/i, ...(isChainsaw ? [/^logon_type$/i] : []), ...(isEvtxECmd ? [/^PayloadData2$/i] : [])]) || detailsCol,
      eventId:     userEventIdCol   || detect([/^EventID$/i, /^event_id$/i, /^eventid$/i, /^EventId$/, ...(isChainsaw ? [/^id$/i] : [])]),
      ts:          userTsCol        || detect([/^datetime$/i, /^UtcTime$/i, /^TimeCreated$/i, /^timestamp$/i, ...(isChainsaw ? [/^system_time$/i] : [])]),
      domain:      userDomainCol    || detect([/^TargetDomainName$/i, /^Target_Domain_Name$/i, /^SubjectDomainName$/i, ...(isTermSvcEvtx ? [/^Param2$/i] : [])]) || extraCol || detailsCol,
      // 4778 session reconnect columns (RDP lateral movement — attacker hostname/IP)
      clientName:    detect([/^ClientName$/i, /^Client_Name$/i]),
      clientAddress: detect([/^ClientAddress$/i, /^Client_Address$/i, /^ClientIP$/i]),
      // 5140/5145 share access columns
      shareName: detect([/^ShareName$/i, /^Share_Name$/i]),
      relativeTargetName: detect([/^RelativeTargetName$/i, /^Relative_Target_Name$/i]),
      // EvtxECmd extra columns for value parsing
      _remoteHost: isEvtxECmd ? detect([/^RemoteHost$/i]) : null,
      _payloadData1: isEvtxECmd ? detect([/^PayloadData1$/i]) : null,
      _payloadData2: isEvtxECmd ? detect([/^PayloadData2$/i]) : null,
      _payloadData3: isEvtxECmd ? detect([/^PayloadData3$/i]) : null,
      _payloadData4: isEvtxECmd ? detect([/^PayloadData4$/i]) : null,
      _payloadData5: isEvtxECmd ? detect([/^PayloadData5$/i]) : null,
      _channel: detect([/^Channel$/i, /^SourceName$/i, /^Provider$/i]),
      // SubStatus for 4625 failure reason (may be in dedicated column or PayloadData)
      subStatus: detect([/^SubStatus$/i, /^Sub_Status$/i]),
      ticketEncryptionType: detect([/^TicketEncryptionType$/i, /^Ticket_Encryption_Type$/i]),
      serviceName: detect([/^ServiceName$/i, /^Service_Name$/i, /^TargetServiceName$/i]),
      ticketOptions: detect([/^TicketOptions$/i, /^Ticket_Options$/i]),
      // 4768 pre-authentication type — PreAuthType=0 is the defining AS-REP roasting signal
      preAuthType: detect([/^PreAuthType$/i, /^Pre_Auth_Type$/i, /^Pre-Authentication-Type$/i]),
      details: detailsCol,
      extra: extraCol,
    };
    columns._isEvtxECmd = isEvtxECmd;
    columns._isHayabusa = isHayabusa;
    columns._isChainsaw = isChainsaw;
    columns._syntheticTarget = !columns.target && (syntheticTargetHost || isChainsaw) ? (syntheticTargetHost || "LOCAL_HOST") : "";

    if (!columns.source && !columns.workstation) return { nodes: [], edges: [], chains: [], stats: {}, columns, error: "Cannot detect source host column (IpAddress, WorkstationName, or RemoteHost)" };
    if (!columns.target && !columns._syntheticTarget) return { nodes: [], edges: [], chains: [], stats: {}, columns, error: "Cannot detect target host column (Computer)" };

    const db = meta.db;
    const params = [];
    const whereConditions = [];

    if (columns.eventId && eventIds.length > 0) {
      const safeEid = meta.colMap[columns.eventId];
      if (safeEid) {
        whereConditions.push(`${safeEid} IN (${eventIds.map(() => "?").join(",")})`);
        params.push(...eventIds);
      }
    }

    ctx.applyStandardFilters(options, meta, whereConditions, params);

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

    const selectParts = ["data.rowid as _rowid"];
    for (const [key, colName] of Object.entries(columns)) {
      if (colName && meta.colMap[colName]) selectParts.push(`${meta.colMap[colName]} as [${key}]`);
    }

    const orderCol = columns.ts ? meta.colMap[columns.ts] : null;
    const orderClause = orderCol ? `ORDER BY ${orderCol} ASC` : "ORDER BY data.rowid ASC";

    try {
      // Multi-source mode: rows are pre-queried and normalized by multi-source.js
      let rows;
      if (options._prequeriedRows) {
        rows = options._prequeriedRows;
      } else {
        // Ensure indexes on key columns to speed up WHERE + ORDER BY
        if (columns.eventId) ctx.ensureIndex(meta.tabId, columns.eventId);
        if (columns.ts) ctx.ensureIndex(meta.tabId, columns.ts);

        // Invalidate stale preview cache for this tab (analysis params may have changed)
        if (ctx.lmPreviewCache) {
          const prefix = JSON.stringify(meta.tabId) + ",";
          for (const k of ctx.lmPreviewCache.keys()) { if (k.startsWith("[" + prefix)) ctx.lmPreviewCache.delete(k); }
        }

        const sql = `SELECT ${selectParts.join(", ")} FROM data ${whereClause} ${orderClause} LIMIT ${maxRows}`;
        rows = db.prepare(sql).all(...params);
      }

      // EXCLUDED_IPS, SERVICE_RE, SESSION_ONLY_EVENTS, RDP_EVENT_DESC → ./constants

      const edgeMap = new Map();
      const hostSet = new Map();
      const timeOrdered = [];
      const rdpEvents = []; // collect all events for RDP session correlation
      const privLogonEvents = []; // 4672 occurrences { userKey, host, ts } for scoped-admin correlation
      const { _makeEvidenceRef, _dedupeEvidenceRefs, _rowEvidenceRef, _refsFromEvents, _refsFromHits, _rowidsFromRefs, _attachEvidenceRefs } = createEvidenceHelpers(meta);
      // Telemetry trackers (per-host / per-user / dataset-wide counts) → ./telemetry
      const { hostTelemetry, userEventCounts, userEventCountsScoped, userEventOriginalName, datasetEventCounts, userFirstSuccessTs, _bumpHostTelemetry, _bumpUserEvent, _bumpUserEventScoped, _bumpDatasetEvent } = createTelemetryTracker();

      const _normLmHost = (value) => cleanWrappedField(value).replace(/^\\\\/, "").replace(/^[A-Z]+\/+/i, "").toUpperCase();
      // IP-to-hostname resolution map — populated when EvtxECmd "WorkstationName (IpAddress)" provides both
      const _ipToHostname = new Map(); // IP -> hostname (from events where both are present)

      // === Parse events -> graph + RDP sessions + chains + convention outliers -> ./build-graph.js ===
      const _spine = buildGraphAndChains({ rows, columns, meta, options, db, edgeMap, hostSet, timeOrdered, rdpEvents, _ipToHostname, isEvtxECmd, isHayabusa, _dedupeEvidenceRefs, _rowEvidenceRef, _refsFromEvents, _rowidsFromRefs, _bumpHostTelemetry, _bumpUserEvent, _bumpUserEventScoped, _bumpDatasetEvent, _normLmHost, excludeLocalLogons, excludeServiceAccounts, privLogonEvents });
      const rdpSessions = _spine.rdpSessions;
      const chains = _spine.chains;
      const findings = _spine.findings;
      let fid = _spine.fid;
      const _outlierHosts = _spine._outlierHosts;
      const _computerHosts = _spine._computerHosts;
      const _conventionOutliers = _spine._conventionOutliers;
      const detectOutlier = _spine.detectOutlier;

      // === Process/service/task scan + per-detector emitters (incl. Cobalt Strike) → detectors/process-service-scan.js ===
      const _scanResult = runProcessServiceScan({ columns, meta, db, isHayabusa, timeOrdered, scanLimits, scanPageSize, _bumpDatasetEvent, _normLmHost, _bumpHostTelemetry, requireMicrosoftSignature, findings, _disabledSet, rmmMode, _outlierHosts, hostSet, fid });
      fid = _scanResult.fid;
      const warnings = _scanResult.warnings;
      const scanStats = _scanResult.scanStats;
      const _scanEidCol = _scanResult._scanEidCol;
      const _usersFromCorrelation = _scanResult._usersFromCorrelation;
      const _sourcesFromCorrelation = _scanResult._sourcesFromCorrelation;
      const _lsassAccessHits = _scanResult._lsassAccessHits;
      const _credTheftCmdHits = _scanResult._credTheftCmdHits;

      // === Admin-share / remote-exec-sequence / service-exec / LSASS / cred-theft detectors → detectors/admin-share-and-execution.js ===
      fid = detectAdminShareAndExecution({ timeOrdered, findings, edgeMap, columns, warnings, chains, meta, _outlierHosts, _dedupeEvidenceRefs, _refsFromHits, _rowidsFromRefs, _attachEvidenceRefs, _usersFromCorrelation, _sourcesFromCorrelation, _disabledSet, _lsassAccessHits, _credTheftCmdHits, fid }).fid;

      const _splitEntityList = (value) => String(value || "")
        .split(",")
        .map((v) => v.trim().toUpperCase())
        .filter(Boolean);
      const _parseLmTs = (value) => {
        if (!value) return null;
        const d = new Date(String(value).replace("T", " ").replace("Z", ""));
        return isNaN(d) ? null : d.getTime();
      };
      const _refsForFindingWindow = (finding) => {
        const fromMs = _parseLmTs(finding?.timeRange?.from);
        const toMs = _parseLmTs(finding?.timeRange?.to) ?? fromMs;
        const sources = new Set(_splitEntityList(finding?.source));
        const targets = new Set(_splitEntityList(finding?.target));
        const filterHosts = new Set((finding?.filterHosts || []).map((h) => String(h || "").trim().toUpperCase()).filter(Boolean));
        const filterEids = new Set((finding?.filterEids || []).map(String));
        const refs = [];
        for (const evt of timeOrdered) {
          if (refs.length >= 5000) break;
          if (filterEids.size > 0 && !filterEids.has(String(evt.eventId))) continue;
          const evtMs = _parseLmTs(evt.ts);
          if (fromMs != null && evtMs != null && evtMs < fromMs) continue;
          if (toMs != null && evtMs != null && evtMs > toMs) continue;
          const evtSource = String(evt.source || "").trim().toUpperCase();
          const evtTarget = String(evt.target || "").trim().toUpperCase();
          if (sources.size > 0 && !sources.has(evtSource)) continue;
          if (targets.size > 0 && !targets.has(evtTarget)) continue;
          if (sources.size === 0 && targets.size === 0 && filterHosts.size > 0 && !filterHosts.has(evtSource) && !filterHosts.has(evtTarget)) continue;
          refs.push(...(evt.evidenceRefs || []));
        }
        return _dedupeEvidenceRefs(refs);
      };
      const _normalizeFindingEvidenceRefs = () => {
        for (const f of findings) {
          const refs = [];
          if (Array.isArray(f.evidenceRefs)) refs.push(...f.evidenceRefs);
          if (Array.isArray(f.itemRowids) && meta.tabId !== "__multi_source__") {
            for (const rowId of f.itemRowids) refs.push({ tabId: meta.tabId, rowId });
          }
          refs.push(..._refsForFindingWindow(f));
          _attachEvidenceRefs(f, refs);
        }
      };
      _normalizeFindingEvidenceRefs();

      // === Finding correlation + triage + execution-session/incident clustering → processing/triage-and-clustering.js ===
      const { _findingPairs, _chainEdges, executionSessions, incidents } = correlateTriageAndCluster({ findings, chains, timeOrdered, _outlierHosts, _dedupeEvidenceRefs, _rowidsFromRefs });
      // === Campaign clustering + edge/chain enrichment + pivot/operator/anomalous-hostname findings → processing/campaign-clustering.js ===
      const _ccResult = clusterCampaignsAndEnrich({ incidents, findings, chains, edgeMap, timeOrdered, hostSet, _chainEdges, _findingPairs, _outlierHosts, _conventionOutliers, _computerHosts, detectOutlier, _dedupeEvidenceRefs, _rowidsFromRefs, fid });
      const campaigns = _ccResult.campaigns;
      fid = _ccResult.fid;
      // === RDP scoring: episode clustering + session suspicion + concurrent-RDP detection → processing/rdp-scoring.js ===
      fid = scoreRdpSessions({ timeOrdered, edgeMap, rdpSessions, _findingPairs, _outlierHosts, findings, fid }).fid;

      // === Credential-attack detectors (Kerberoasting / AS-REP / DCSync) → detectors/credential-attacks.js ===
      fid = detectCredentialAttacks({ db, meta, columns, isEvtxECmd, disabledSet: _disabledSet, findings, warnings, fid });

      // === Sysmon EID13 CLIENTNAME + session grouping + telemetry coverage → processing/sysmon-rdp-coverage.js ===
      const _r14 = computeSysmonRdpAndCoverage({ db, meta, columns, options, hostSet, _outlierHosts, findings, warnings, isHayabusa, _scanEidCol, _dedupeEvidenceRefs, _rowEvidenceRef, _rowidsFromRefs, _normalizeFindingEvidenceRefs, rdpSessions, hostTelemetry, datasetEventCounts, _conventionOutliers, fid });
      fid = _r14.fid;
      const groupedSessions = _r14.groupedSessions;
      const hostCoverage = _r14.hostCoverage;
      const datasetEventCountsObj = _r14.datasetEventCountsObj;
      const datasetCoverage = _r14.datasetCoverage;
      const coverageWarnings = _r14.coverageWarnings;

      // === Accounts Aggregation → assemble/accounts.js ===
      const accounts = aggregateAccounts({ timeOrdered, rdpSessions, findings, userEventCounts, userEventCountsScoped, userEventOriginalName, _outlierHosts, privLogonEvents, userFirstSuccessTs });

      return {
        nodes: [
          // Nodes from logon graph (hostSet)
          ...[...hostSet.entries()].map(([id, info]) => {
            const outlierReason = detectOutlier(id);
            const convOutlier = _conventionOutliers.get(id);
            return {
              id, label: id, eventCount: info.eventCount,
              isSource: info.isSource, isTarget: info.isTarget,
              isBoth: info.isSource && info.isTarget,
              isOutlier: !!outlierReason || !!convOutlier, outlierReason: outlierReason || (convOutlier ? convOutlier.reason : ""),
              conventionOutlier: !!convOutlier, conventionReason: convOutlier ? convOutlier.reason : "",
              telemetry: hostCoverage.get(id) || null,
            };
          }),
          // Isolated nodes: convention outliers from Computer column that aren't in the logon graph
          ...[..._conventionOutliers.entries()]
            .filter(([id]) => !hostSet.has(id))
            .map(([id, info]) => {
              const ch = _computerHosts.find(c => c.host === id);
              return {
                id, label: id, eventCount: ch ? ch.eventCount : 0,
                isSource: false, isTarget: false, isBoth: false,
                isOutlier: true, outlierReason: info.reason,
                conventionOutlier: true, conventionReason: info.reason,
                isolated: true, // flag for frontend positioning
                telemetry: hostCoverage.get(id) || null,
              };
            }),
        ],
        edges: [...edgeMap.values()].map((e) => ({
          ...e, users: [...e.users], logonTypes: [...e.logonTypes], clientNames: [...e.clientNames], clientAddresses: [...e.clientAddresses],
          eventBreakdown: Object.fromEntries(e.eventBreakdown), shareNames: [...(e.shareNames || [])],
          evidenceRefs: _dedupeEvidenceRefs(e.evidenceRefs || []),
          itemRowids: _rowidsFromRefs(e.evidenceRefs || []),
        })),
        chains,
        rdpSessions,
        groupedSessions,
        accounts,
        findings,
        incidents,
        campaigns,
        executionSessions,
        stats: {
          totalEvents: timeOrdered.length, uniqueHosts: hostSet.size,
          uniqueUsers: new Set(timeOrdered.map((e) => e.user).filter(Boolean)).size,
          uniqueConnections: edgeMap.size,
          failedLogons: [...edgeMap.values()].reduce((s, e) => s + (e.hasFailures ? 1 : 0), 0),
          longestChain: chains.length > 0 ? chains[0].hops : 0,
          chainCount: chains.length,
          rdpSessionCount: rdpSessions.length,
          adminSessions: rdpSessions.filter((s) => s.hasAdmin).length,
          suspiciousSessions: rdpSessions.filter((s) => (s.suspicionScore || 0) >= 25).length,
          findingsCount: findings.length,
          criticalFindings: findings.filter((f) => f.severity === "critical").length,
          incidentCount: incidents.length,
          executionSessionCount: executionSessions.length,
          campaignCount: campaigns.length,
          accountCount: accounts.length,
          suspiciousAccounts: accounts.filter(a => (a.suspicionScore || 0) >= 25).length,
          datasetEnd: timeOrdered.length > 0 ? timeOrdered[timeOrdered.length - 1].ts : null,
        },
        warnings, scanStats,
        coverage: {
          dataset: datasetCoverage,
          datasetEventCounts: datasetEventCountsObj,
          warnings: coverageWarnings,
          categories: TELEMETRY_CATEGORIES.map(c => ({ id: c.id, label: c.label, eids: c.eids, critical: c.critical })),
        },
        columns, error: null,
      };
    } catch (e) {
      return { nodes: [], edges: [], chains: [], findings: [], incidents: [], campaigns: [], executionSessions: [], groupedSessions: [], stats: {}, warnings: [], scanStats: {}, columns, error: e.message };
    }
}

module.exports = { getLateralMovement };
