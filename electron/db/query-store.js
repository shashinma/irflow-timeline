/**
 * Query/filter methods mixed into TimelineDB.
 */
class QueryStoreMethods {
  queryRows(tabId, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { rows: [], totalFiltered: 0 };

    const {
      offset = 0,
      limit = -1,
      sortCol = null,
      sortDir = "asc",
      searchTerm = "",
      searchMode = "mixed",
      searchCondition = "contains",
      columnFilters = {},
      checkboxFilters = {},
      bookmarkedOnly = false,
      tagFilter = null,
      groupCol = null,
      groupValue = undefined,
      groupFilters = [],
      dateRangeFilters = {},
      advancedFilters = [],
    } = options;

    const db = meta.db;
    const params = [];
    let whereConditions = [];

    // ── Standard filters (column, checkbox, date range, bookmarks, tags, advanced, search) ──
    this._applyStandardFilters(options, meta, whereConditions, params);

    // ── Group filter (single - legacy) — queryRows-specific ──
    if (groupCol && groupValue !== undefined) {
      const safeCol = meta.colMap[groupCol];
      if (safeCol) {
        whereConditions.push(`${safeCol} = ?`);
        params.push(groupValue);
      }
    }

    // ── Multi-level group filters — queryRows-specific ──────
    for (const gf of groupFilters) {
      const safeCol = meta.colMap[gf.col];
      if (safeCol) {
        whereConditions.push(`${safeCol} = ?`);
        params.push(gf.value);
      }
    }

    const whereClause =
      whereConditions.length > 0
        ? `WHERE ${whereConditions.join(" AND ")}`
        : "";

    // ── Count total filtered rows (cached by filter signature) ──
    const filterSig = whereClause + "|" + JSON.stringify(params);
    let totalFiltered;
    if (meta._countCache && meta._countCache.sig === filterSig) {
      totalFiltered = meta._countCache.cnt;
    } else if (whereClause === "" && Number.isFinite(meta.rowCount)) {
      // No filters → the count is the whole table, already known from import. Skip the
      // full COUNT(*) scan that otherwise freezes the open for 10-40s on a 100M+ row
      // table (the data table is append-only — rows are never deleted — so rowCount holds).
      totalFiltered = meta.rowCount;
      meta._countCache = { sig: filterSig, cnt: totalFiltered };
    } else {
      const countSql = `SELECT COUNT(*) as cnt FROM data ${whereClause}`;
      totalFiltered = db.prepare(countSql).get(...params).cnt;
      meta._countCache = { sig: filterSig, cnt: totalFiltered };
    }

    // ── Sort ───────────────────────────────────────────────────
    let orderClause = "ORDER BY data.rowid";
    if (sortCol) {
      if (sortCol === "__vt__") {
        // Virtual VT column — sort by verdict tag priority (malicious first in ASC)
        const dir = sortDir === "desc" ? "DESC" : "ASC";
        orderClause = `ORDER BY COALESCE((SELECT MIN(CASE tag WHEN 'VT: Malicious' THEN 1 WHEN 'VT: Suspicious' THEN 2 WHEN 'VT: Clean' THEN 3 ELSE 4 END) FROM tags WHERE tags.rowid = data.rowid AND tag LIKE 'VT:%'), 5) ${dir}, data.rowid ASC`;
      } else {
        const safeCol = meta.colMap[sortCol];
        if (safeCol) {
          // Lazy-build index on first sort for this column
          this._ensureIndex(tabId, sortCol);
          const dir = sortDir === "desc" ? "DESC" : "ASC";
          // Timestamp columns checked first (takes priority over numeric — prevents
          // false-positive numeric detection from breaking timestamp sorting)
          if (meta.tsColumns.has(sortCol)) {
            orderClause = `ORDER BY sort_datetime(${safeCol}) ${dir}`;
          } else if (meta.numericColumns.has(sortCol)) {
            orderClause = `ORDER BY CAST(${safeCol} AS REAL) ${dir}`;
          } else {
            orderClause = `ORDER BY ${safeCol} COLLATE NOCASE ${dir}`;
          }
        }
      }
    }

    // ── Fetch window ───────────────────────────────────────────
    // Defensive cap: SQLite treats LIMIT -1 (the legacy default) as "no limit", so a
    // missing/invalid limit would stream the entire — possibly 100M-row — result set into
    // memory and OOM the process. Every real caller passes an explicit positive window
    // (including the intentional "load all in group" path), so an explicit non-negative
    // limit is honored as-is; only a missing/invalid one falls back to a bounded default.
    const effectiveLimit = Number.isInteger(limit) && limit >= 0 ? limit : 10000;
    const colList = meta.safeCols.map((c) => c.safe).join(", ");
    const querySql = `SELECT data.rowid as _rowid, ${colList} FROM data ${whereClause} ${orderClause} LIMIT ? OFFSET ?`;
    const queryParams = [...params, effectiveLimit, offset];

    const rawRows = db.prepare(querySql).all(...queryParams);

    // Map back to original column names — tight loop, no closures
    const colCount = meta.safeCols.length;
    const rows = new Array(rawRows.length);
    for (let r = 0; r < rawRows.length; r++) {
      const raw = rawRows[r];
      const row = { __idx: raw._rowid };
      for (let c = 0; c < colCount; c++) {
        row[meta.safeCols[c].original] = raw[meta.safeCols[c].safe] ?? "";
      }
      rows[r] = row;
    }

    // Get bookmark + tag data for fetched rows in batches
    // (SQLite max variable limit is ~32766, so batch large sets)
    const rowIds = rawRows.map((r) => r._rowid);
    const bookmarkedSet = new Set();
    const rowTags = {};
    const BATCH = 5000;
    for (let i = 0; i < rowIds.length; i += BATCH) {
      const batch = rowIds.slice(i, i + BATCH);
      const placeholders = batch.map(() => "?").join(",");
      try {
        const combined = db.prepare(
          `SELECT rowid, 'b' as t, '' as tag FROM bookmarks WHERE rowid IN (${placeholders})` +
          ` UNION ALL SELECT rowid, 't', tag FROM tags WHERE rowid IN (${placeholders})`
        ).all(...batch, ...batch);
        for (const r of combined) {
          if (r.t === "b") bookmarkedSet.add(r.rowid);
          else { if (!rowTags[r.rowid]) rowTags[r.rowid] = []; rowTags[r.rowid].push(r.tag); }
        }
      } catch (e) {
        // Fail gracefully — return rows without bookmark/tag decoration
      }
    }

    return {
      rows,
      totalFiltered,
      totalRows: meta.rowCount,
      bookmarkedRows: [...bookmarkedSet],
      rowTags,
    };
  }

  /**
   * Apply global search conditions to a WHERE clause.
   * Handles FTS, regex, and column-specific search uniformly.
   */
  _applySearch(searchTerm, searchMode, meta, whereConditions, params, searchCondition = "contains") {
    if (!searchTerm.trim()) return;

    // Fuzzy search — uses custom fuzzy_match() SQLite function
    if (searchCondition === "fuzzy" && searchMode !== "regex") {
      const terms = searchMode === "exact" ? [searchTerm.trim()] : searchTerm.trim().split(/\s+/).filter(Boolean);
      const joinOp = searchMode === "or" ? " OR " : " AND ";
      const termConditions = terms.map((term) => {
        const colConds = meta.safeCols.map((c) => {
          params.push(term);
          return `fuzzy_match(${c.safe}, ?)`;
        });
        return `(${colConds.join(" OR ")})`;
      });
      whereConditions.push(`(${termConditions.join(joinOp)})`);
      return;
    }

    // Non-default conditions bypass FTS — use direct SQL LIKE/=
    if (searchCondition !== "contains" && searchMode !== "regex") {
      const terms = searchMode === "exact" ? [searchTerm.trim()] : searchTerm.trim().split(/\s+/).filter(Boolean);
      const joinOp = searchMode === "or" ? " OR " : " AND ";
      const termConditions = terms.map((term) => {
        const colConds = meta.safeCols.map((c) => {
          if (searchCondition === "startswith") { params.push(`${term}%`); return `${c.safe} LIKE ?`; }
          if (searchCondition === "like") { params.push(term); return `${c.safe} LIKE ?`; }
          if (searchCondition === "equals") { params.push(term); return `${c.safe} = ?`; }
          params.push(`%${term}%`); return `${c.safe} LIKE ?`;
        });
        return `(${colConds.join(" OR ")})`;
      });
      whereConditions.push(`(${termConditions.join(joinOp)})`);
      return;
    }

    if (searchMode === "regex") {
      // Concatenate all columns with separator and run single REGEXP — avoids
      // pushing N identical params and N separate REGEXP calls per row.
      const concat = meta.safeCols.map((c) => `COALESCE(${c.safe},'')`).join(" || ' ' || ");
      whereConditions.push(`(${concat}) REGEXP ?`);
      params.push(searchTerm.trim());
      return;
    }

    // ── Contains-mode search (the default): use LIKE substring matching for
    // consistency with column filters and column-qualified `Col:value` searches.
    //
    // Previously this path used FTS5 phrase queries, but FTS5's whole-token
    // semantics produced false negatives for substrings embedded in larger
    // alphanumeric tokens (issue #8): e.g. `b4ckd00r` would not match a row
    // containing `crackb4ckd00r` because unicode61 indexes the latter as a
    // single token. Column filter `LIKE %b4ckd00r%` matched correctly, so the
    // global search was inconsistent with the rest of the filtering UI.
    //
    // LIKE on a concatenated column expression is slower than FTS on very
    // large datasets, but DFIR analysts need correct substring semantics —
    // partial IOC matches must work. Mixed-mode operators (+, -, "phrase",
    // Col:value) are translated to LIKE conditions per token below.
    const concat = meta.safeCols.map((c) => `COALESCE(${c.safe},'')`).join(" || ' ' || ");

    // FTS5 trigram prefilter: when the trigram index is ready, narrow candidate rows by the
    // required >=3-char substrings via an indexed MATCH, then let the LIKE conditions above
    // re-confirm exact semantics. For a >=3-char substring, trigram MATCH "x" is equivalent
    // to a per-column LIKE %x% (the concat's ' ' separators prevent cross-column substrings),
    // so the prefilter is a safe SUPERSET and the LIKE re-check guarantees correctness. Terms
    // <3 chars can't be trigram-indexed, so they fall through to LIKE alone. This restores
    // the index speed lost when the default search moved to substring-LIKE (issue #8).
    const _addFtsPrefilter = (requiredTerms, joiner = " AND ") => {
      if (!meta.ftsReady) return;
      const terms = (requiredTerms || []).filter((t) => typeof t === "string" && t.length >= 3);
      if (terms.length === 0) return;
      const matchQuery = terms.map((t) => `"${t.replace(/"/g, '""')}"`).join(joiner);
      whereConditions.push(`data.rowid IN (SELECT rowid FROM data_fts WHERE data_fts MATCH ?)`);
      params.push(matchQuery);
    };

    if (searchMode === "exact") {
      whereConditions.push(`(${concat}) LIKE ?`);
      params.push(`%${searchTerm.trim()}%`);
      _addFtsPrefilter([searchTerm.trim()]);
      return;
    }

    if (searchMode === "or" || searchMode === "and") {
      const terms = searchTerm.trim().split(/\s+/).filter(Boolean);
      if (terms.length === 0) return;
      const joinOp = searchMode === "or" ? " OR " : " AND ";
      const conds = terms.map(() => `(${concat}) LIKE ?`);
      whereConditions.push(`(${conds.join(joinOp)})`);
      for (const t of terms) params.push(`%${t}%`);
      // AND: every term is required → prefilter on the >=3-char subset. OR: only safe when
      // EVERY term is trigram-indexable (>=3 chars), else a <3-char term's rows would be
      // wrongly excluded by the prefilter (it must remain a superset of the LIKE result).
      if (searchMode === "and") _addFtsPrefilter(terms);
      else if (terms.every((t) => t.length >= 3)) _addFtsPrefilter(terms, " OR ");
      return;
    }

    // Mixed mode — parse tokens (+include, -exclude, "phrase", Col:value, bare)
    // and translate each to a LIKE condition. Preserves all the operator
    // semantics that the FTS path used to handle.
    const tokens = [];
    const tokenRegex = /"([^"]+)"|(\S+)/g;
    let mt;
    while ((mt = tokenRegex.exec(searchTerm)) !== null) {
      tokens.push(mt[1] != null ? { kind: "phrase", value: mt[1] } : { kind: "raw", value: mt[2] });
    }

    const sqlParts = [];
    // Positive substrings that EVERY matching row must contain (tokens are ANDed below).
    // Excludes -negations. Used to build the FTS trigram prefilter (a safe superset).
    const requiredTerms = [];
    for (const tok of tokens) {
      if (tok.kind === "phrase") {
        sqlParts.push(`(${concat}) LIKE ?`);
        params.push(`%${tok.value}%`);
        requiredTerms.push(tok.value);
        continue;
      }
      const v = tok.value;
      // Column-qualified `Col:value` — direct LIKE on the matched column
      const colonIdx = v.indexOf(":");
      if (colonIdx > 0 && !v.startsWith("-") && !v.startsWith("+")) {
        const colPart = v.substring(0, colonIdx);
        const valPart = v.substring(colonIdx + 1);
        if (valPart) {
          const matchCol = meta.headers.find((h) => h.toLowerCase() === colPart.toLowerCase());
          const safeCol = matchCol ? meta.colMap[matchCol] : null;
          if (safeCol) {
            sqlParts.push(`${safeCol} LIKE ?`);
            params.push(`%${valPart}%`);
            // The value must appear in a specific column, so it appears in the row →
            // including it as a required term keeps the prefilter a valid superset.
            requiredTerms.push(valPart);
            continue;
          }
        }
      }
      if (v.startsWith("-")) {
        const term = v.slice(1);
        if (term) {
          sqlParts.push(`NOT ((${concat}) LIKE ?)`);
          params.push(`%${term}%`);
        }
        continue;
      }
      if (v.startsWith("+")) {
        const term = v.slice(1);
        if (term) {
          sqlParts.push(`(${concat}) LIKE ?`);
          params.push(`%${term}%`);
          requiredTerms.push(term);
        }
        continue;
      }
      // Bare term
      sqlParts.push(`(${concat}) LIKE ?`);
      params.push(`%${v}%`);
      requiredTerms.push(v);
    }

    if (sqlParts.length > 0) {
      whereConditions.push(`(${sqlParts.join(" AND ")})`);
      _addFtsPrefilter(requiredTerms);
    }
  }

  // ── Shared filter helpers (used by queryRows, preview*, getLateralMovement, etc.) ──

  _applyColumnFilters(columnFilters, meta, whereConditions, params) {
    for (const [cn, fv] of Object.entries(columnFilters)) {
      if (!fv) continue;
      if (cn === "__tags__") {
        whereConditions.push(`data.rowid IN (SELECT rowid FROM tags WHERE tag LIKE ?)`);
        params.push(`%${fv}%`);
        continue;
      }
      if (cn === "__vt__") {
        whereConditions.push(`data.rowid IN (SELECT rowid FROM tags WHERE tag LIKE 'VT:%' AND tag LIKE ? COLLATE NOCASE)`);
        params.push(`%${fv}%`);
        continue;
      }
      const sc = meta.colMap[cn];
      if (!sc) continue;
      whereConditions.push(`${sc} LIKE ?`);
      params.push(`%${fv}%`);
    }
  }

  _applyCheckboxFilters(checkboxFilters, meta, whereConditions, params) {
    for (const [cn, values] of Object.entries(checkboxFilters)) {
      if (!values || values.length === 0) continue;
      if (cn === "__vt__") {
        const ph = values.map(() => "?").join(",");
        whereConditions.push(`data.rowid IN (SELECT rowid FROM tags WHERE tag IN (${ph}))`);
        params.push(...values);
        continue;
      }
      const sc = meta.colMap[cn];
      if (!sc) continue;
      const hasNull = values.some((v) => v === null || v === "");
      const nonNull = values.filter((v) => v !== null && v !== "");
      const parts = [];
      if (hasNull) parts.push(`(${sc} IS NULL OR ${sc} = '')`);
      if (nonNull.length === 1) { parts.push(`${sc} = ?`); params.push(nonNull[0]); }
      else if (nonNull.length > 1) { parts.push(`${sc} IN (${nonNull.map(() => "?").join(",")})`); params.push(...nonNull); }
      whereConditions.push(parts.length > 1 ? `(${parts.join(" OR ")})` : parts[0]);
    }
  }

  _applyDateRangeFilters(dateRangeFilters, meta, whereConditions, params) {
    for (const [cn, range] of Object.entries(dateRangeFilters)) {
      const sc = meta.colMap[cn];
      if (!sc) continue;
      if (range.from) { whereConditions.push(`${sc} >= ?`); params.push(range.from); }
      if (range.to) { whereConditions.push(`${sc} <= ?`); params.push(range.to); }
    }
  }

  _applyBookmarkFilter(bookmarkedOnly, whereConditions) {
    if (bookmarkedOnly) {
      whereConditions.push(`data.rowid IN (SELECT rowid FROM bookmarks)`);
    }
  }

  _applyTagFilter(tagFilter, whereConditions, params) {
    if (tagFilter === "__any__") {
      whereConditions.push(`data.rowid IN (SELECT DISTINCT rowid FROM tags)`);
    } else if (Array.isArray(tagFilter) && tagFilter.length > 0) {
      const ph = tagFilter.map(() => "?").join(",");
      whereConditions.push(`data.rowid IN (SELECT rowid FROM tags WHERE tag IN (${ph}))`);
      params.push(...tagFilter);
    } else if (tagFilter && typeof tagFilter === "string") {
      whereConditions.push(`data.rowid IN (SELECT rowid FROM tags WHERE tag = ?)`);
      params.push(tagFilter);
    }
  }

  _normalizeRowIdFilter(rowIdFilter) {
    if (!Array.isArray(rowIdFilter)) return null;
    const ids = [];
    const seen = new Set();
    for (const value of rowIdFilter) {
      const id = Number(value);
      if (!Number.isSafeInteger(id) || id <= 0 || seen.has(id)) continue;
      seen.add(id);
      ids.push(id);
    }
    return ids;
  }

  _applyRowIdFilter(rowIdFilter, whereConditions) {
    const ids = this._normalizeRowIdFilter(rowIdFilter);
    if (!ids) return;
    if (ids.length === 0) {
      whereConditions.push("0");
      return;
    }

    // Source row IDs are sanitized integers, so inline them to avoid SQLite's
    // variable limit when a rule has many matches.
    const chunks = [];
    const CHUNK_SIZE = 5000;
    for (let i = 0; i < ids.length; i += CHUNK_SIZE) {
      chunks.push(`data.rowid IN (${ids.slice(i, i + CHUNK_SIZE).join(",")})`);
    }
    whereConditions.push(chunks.length === 1 ? chunks[0] : `(${chunks.join(" OR ")})`);
  }

  /**
   * Apply the standard set of filters to a WHERE clause.
   * Centralizes the filter logic shared by queryRows, exportQuery,
   * getColumnStats, getHistogramData, and all analysis methods.
   */
  _applyStandardFilters(options, meta, whereConditions, params) {
    const {
      columnFilters = {}, checkboxFilters = {},
      bookmarkedOnly = false, tagFilter = null,
      dateRangeFilters = {}, advancedFilters = [],
      searchTerm = "", searchMode = "mixed", searchCondition = "contains",
      rowIdFilter = null,
    } = options;
    this._applyRowIdFilter(rowIdFilter, whereConditions);
    this._applyColumnFilters(columnFilters, meta, whereConditions, params);
    this._applyCheckboxFilters(checkboxFilters, meta, whereConditions, params);
    this._applyDateRangeFilters(dateRangeFilters, meta, whereConditions, params);
    this._applyBookmarkFilter(bookmarkedOnly, whereConditions);
    this._applyTagFilter(tagFilter, whereConditions, params);
    this._applyAdvancedFilters(advancedFilters, meta, whereConditions, params);
    if (searchTerm.trim()) {
      this._applySearch(searchTerm, searchMode, meta, whereConditions, params, searchCondition);
    }
  }

  /**
   * Apply advanced multi-condition filters (Edit Filter feature).
   * Groups conditions by AND/OR logic with correct SQL precedence:
   *   A AND B OR C AND D  →  (A AND B) OR (C AND D)
   */
  _applyAdvancedFilters(advancedFilters, meta, whereConditions, params) {
    if (!advancedFilters || advancedFilters.length === 0) return;

    // Filter out incomplete conditions
    const valid = advancedFilters.filter((f) => {
      if (!f.column || !f.operator) return false;
      if (f.operator !== "is_empty" && f.operator !== "is_not_empty" && !f.value && f.value !== 0) return false;
      const sc = meta.colMap[f.column];
      return !!sc;
    });
    if (valid.length === 0) return;

    // Build SQL for a single condition
    const buildCondition = (f) => {
      const sc = meta.colMap[f.column];
      switch (f.operator) {
        case "contains":
          params.push(`%${f.value}%`);
          return `${sc} LIKE ?`;
        case "not_contains":
          params.push(`%${f.value}%`);
          return `${sc} NOT LIKE ?`;
        case "equals":
          params.push(f.value);
          return `${sc} = ?`;
        case "not_equals":
          params.push(f.value);
          return `${sc} != ?`;
        case "starts_with":
          params.push(`${f.value}%`);
          return `${sc} LIKE ?`;
        case "ends_with":
          params.push(`%${f.value}`);
          return `${sc} LIKE ?`;
        case "greater_than":
          params.push(f.value);
          return `CAST(${sc} AS REAL) > CAST(? AS REAL)`;
        case "less_than":
          params.push(f.value);
          return `CAST(${sc} AS REAL) < CAST(? AS REAL)`;
        case "is_empty":
          return `(${sc} IS NULL OR ${sc} = '')`;
        case "is_not_empty":
          return `(${sc} IS NOT NULL AND ${sc} != '')`;
        case "regex":
          params.push(f.value);
          return `${sc} REGEXP ?`;
        default:
          params.push(`%${f.value}%`);
          return `${sc} LIKE ?`;
      }
    };

    // Group consecutive AND-linked conditions, join groups with OR
    const groups = [];
    let currentGroup = [buildCondition(valid[0])];

    for (let i = 1; i < valid.length; i++) {
      if (valid[i].logic === "OR") {
        groups.push(currentGroup);
        currentGroup = [buildCondition(valid[i])];
      } else {
        currentGroup.push(buildCondition(valid[i]));
      }
    }
    groups.push(currentGroup);

    // Build final expression
    const expr = groups
      .map((g) => (g.length > 1 ? `(${g.join(" AND ")})` : g[0]))
      .join(" OR ");

    whereConditions.push(groups.length > 1 ? `(${expr})` : expr);
  }

  /**
   * Build search query from search term and mode.
   * Returns { ftsQuery, colConditions } where:
   *   - ftsQuery: FTS5 MATCH string (or null if no FTS terms)
   *   - colConditions: array of { sql, param } for column-specific Col:value filters
   */
  _buildSearchQuery(searchTerm, searchMode, meta) {
    // Lazy-build FTS index on first search
    this._ensureFts(meta.tabId);
    const result = { ftsQuery: null, colConditions: [] };
    try {
      if (searchMode === "exact") {
        const cleaned = searchTerm.replace(/"/g, "").trim();
        result.ftsQuery = `"${cleaned}"`;
        return result;
      }

      if (searchMode === "or") {
        const terms = searchTerm.trim().split(/\s+/).filter(Boolean);
        result.ftsQuery = terms.map((t) => `"${t.replace(/"/g, "")}"`).join(" OR ");
        return result;
      }

      if (searchMode === "and") {
        const terms = searchTerm.trim().split(/\s+/).filter(Boolean);
        result.ftsQuery = terms.map((t) => `"${t.replace(/"/g, "")}"`).join(" AND ");
        return result;
      }

      // Mixed mode — parse +AND, -EXCLUDE, "phrases", Column:value
      const tokens = [];
      const regex = /"([^"]+)"|(\S+)/g;
      let m;
      while ((m = regex.exec(searchTerm)) !== null) {
        tokens.push(m[1] ? `"${m[1]}"` : m[2]);
      }

      const ftsTerms = [];
      for (const token of tokens) {
        if (token.startsWith('"')) {
          ftsTerms.push(token);
        } else if (token.includes(":")) {
          // Column-specific filter: Col:value → WHERE colSafe LIKE %value%
          const colonIdx = token.indexOf(":");
          const colPart = token.substring(0, colonIdx);
          const valPart = token.substring(colonIdx + 1);
          if (valPart) {
            // Find matching column (case-insensitive)
            const matchCol = meta.headers.find((h) => h.toLowerCase() === colPart.toLowerCase());
            const safeCol = matchCol ? meta.colMap[matchCol] : null;
            if (safeCol) {
              result.colConditions.push({ sql: `${safeCol} LIKE ?`, param: `%${valPart}%` });
            }
          }
        } else if (token.startsWith("-")) {
          const term = token.slice(1);
          if (term) ftsTerms.push(`NOT "${term}"`);
        } else if (token.startsWith("+")) {
          const term = token.slice(1);
          if (term) ftsTerms.push(`"${term}"`);
        } else {
          ftsTerms.push(`"${token}"`);
        }
      }

      if (ftsTerms.length > 0) {
        const hasOperator = tokens.some((t) => t.startsWith("+") || t.startsWith("-"));
        // Default to AND for multi-word (DFIR analysts want all terms to match)
        result.ftsQuery = ftsTerms.join(hasOperator ? " AND " : (ftsTerms.length > 1 ? " AND " : ""));
      }

      return result;
    } catch (e) {
      result.ftsQuery = `"${searchTerm.replace(/"/g, "").trim()}"`;
      return result;
    }
  }


  /**
   * Export filtered data as streaming CSV
   */
  exportQuery(tabId, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;

    const { sortCol = null, sortDir = "asc", visibleHeaders = null } = options;

    const headers = visibleHeaders || meta.headers;
    const safeCols = headers.map((h) => meta.colMap[h]).filter(Boolean);
    const colList = safeCols.join(", ");

    const params = [];
    const whereConditions = [];
    this._applyStandardFilters(options, meta, whereConditions, params);

    const whereClause =
      whereConditions.length > 0
        ? `WHERE ${whereConditions.join(" AND ")}`
        : "";

    let orderClause = "ORDER BY data.rowid";
    if (sortCol) {
      const safeCol = meta.colMap[sortCol];
      if (safeCol) {
        const dir = sortDir === "desc" ? "DESC" : "ASC";
        if (meta.tsColumns.has(sortCol)) {
          orderClause = `ORDER BY sort_datetime(${safeCol}) ${dir}`;
        } else if (meta.numericColumns.has(sortCol)) {
          orderClause = `ORDER BY CAST(${safeCol} AS REAL) ${dir}`;
        } else {
          orderClause = `ORDER BY ${safeCol} COLLATE NOCASE ${dir}`;
        }
      }
    }

    const sql = `SELECT ${colList} FROM data ${whereClause} ${orderClause}`;
    const stmt = meta.db.prepare(sql);
    const iter = stmt.iterate(...params);

    return {
      headers,
      iterator: iter,
      safeCols,
      reverseMap: meta.reverseColMap,
    };
  }

  /**
   * Get column statistics (unique values, min/max for numerics)
   */
  getColumnStats(tabId, colName, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;
    const isTagCol = colName === "__tags__";
    const safeCol = isTagCol ? null : meta.colMap[colName];
    if (!isTagCol && !safeCol) return null;

    const db = meta.db;
    const params = [];
    const whereConditions = [];
    this._applyStandardFilters(options, meta, whereConditions, params);

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

    try {
      if (isTagCol) {
        // Tags column stats — query from tags table
        const totalRows = db.prepare(`SELECT COUNT(*) as cnt FROM data ${whereClause}`).get(...params).cnt;
        const joinWhere = whereClause ? `${whereClause} AND data.rowid = tags.rowid` : `WHERE data.rowid = tags.rowid`;
        const taggedRows = db.prepare(`SELECT COUNT(DISTINCT tags.rowid) as cnt FROM tags, data ${joinWhere}`).get(...params).cnt;
        const uniqueTags = db.prepare(`SELECT COUNT(DISTINCT tag) as cnt FROM tags, data ${joinWhere}`).get(...params).cnt;
        const topValues = db.prepare(`SELECT tag as val, COUNT(*) as cnt FROM tags, data ${joinWhere} GROUP BY tag ORDER BY cnt DESC LIMIT 25`).all(...params);
        return { totalRows, nonEmptyCount: taggedRows, emptyCount: totalRows - taggedRows, uniqueCount: uniqueTags, fillRate: totalRows > 0 ? Math.round((taggedRows / totalRows) * 10000) / 100 : 0, topValues };
      }

      // Combined stats query — 1 scan instead of 3 separate COUNT queries
      const isTs = meta.tsColumns.has(colName);
      const isNum = meta.numericColumns && meta.numericColumns.has(colName);
      let statsSql = `SELECT COUNT(*) as total, SUM(CASE WHEN ${safeCol} IS NOT NULL AND ${safeCol} != '' THEN 1 ELSE 0 END) as nonEmpty, COUNT(DISTINCT CASE WHEN ${safeCol} IS NOT NULL AND ${safeCol} != '' THEN ${safeCol} END) as uniq`;
      if (isTs) statsSql += `, MIN(sort_datetime(${safeCol})) as earliest, MAX(sort_datetime(${safeCol})) as latest`;
      if (isNum) statsSql += `, MIN(CAST(${safeCol} AS REAL)) as minVal, MAX(CAST(${safeCol} AS REAL)) as maxVal, AVG(CAST(${safeCol} AS REAL)) as avgVal`;
      statsSql += ` FROM data ${whereClause}`;
      const stats = db.prepare(statsSql).get(...params);

      const totalRows = stats.total;
      const nonEmptyCount = stats.nonEmpty;
      const emptyCount = totalRows - nonEmptyCount;
      const uniqueCount = stats.uniq;
      const fillRate = totalRows > 0 ? Math.round((nonEmptyCount / totalRows) * 10000) / 100 : 0;

      // Top 25 values (still needs separate GROUP BY query)
      const neWhere = whereConditions.length > 0
        ? `WHERE ${whereConditions.join(" AND ")} AND ${safeCol} IS NOT NULL AND ${safeCol} != ''`
        : `WHERE ${safeCol} IS NOT NULL AND ${safeCol} != ''`;
      const topValues = db.prepare(
        `SELECT ${safeCol} as val, COUNT(*) as cnt FROM data ${neWhere} GROUP BY ${safeCol} ORDER BY cnt DESC LIMIT 25`
      ).all(...params);

      const result = { totalRows, nonEmptyCount, emptyCount, uniqueCount, fillRate, topValues };

      // Timestamp stats (already computed in combined query)
      if (isTs && stats.earliest) {
        result.tsStats = { earliest: stats.earliest, latest: stats.latest };
        try {
          const e = new Date(stats.earliest.replace(" ", "T"));
          const l = new Date(stats.latest.replace(" ", "T"));
          const diffMs = l.getTime() - e.getTime();
          if (!isNaN(diffMs) && diffMs >= 0) result.tsStats.timespanMs = diffMs;
        } catch { /* non-parseable */ }
      }

      // Numeric stats (already computed in combined query)
      if (isNum && stats.minVal != null) {
        result.numStats = {
          min: stats.minVal,
          max: stats.maxVal,
          avg: Math.round(stats.avgVal * 100) / 100,
        };
      }

      return result;
    } catch (e) {
      return { totalRows: 0, nonEmptyCount: 0, emptyCount: 0, uniqueCount: 0, fillRate: 0, topValues: [], error: e.message };
    }
  }

  /**
   * Get columns that are entirely empty (NULL or '')
   */
  getEmptyColumns(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return [];
    const db = meta.db;
    // Sample-based: check first 25K + last 25K rows instead of full table scan.
    // On 30M+ row tables, a full scan blocks the main thread for 10-30s.
    const checks = meta.safeCols.map((c) => `MAX(CASE WHEN ${c.safe} IS NOT NULL AND ${c.safe} != '' THEN 1 ELSE 0 END) as ${c.safe}`);
    const useFullScan = meta.rowCount <= 100000;
    const source = useFullScan
      ? "data"
      : `(SELECT * FROM (SELECT * FROM data LIMIT 25000) UNION ALL SELECT * FROM (SELECT * FROM data ORDER BY rowid DESC LIMIT 25000))`;
    const row = db.prepare(`SELECT ${checks.join(", ")} FROM ${source}`).get();
    if (!row) return [...meta.headers];
    return meta.headers.filter((h) => {
      const sc = meta.colMap[h];
      return sc && !row[sc];
    });
  }

  /**
   * Get tab metadata
   */
  getTabInfo(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;
    return {
      headers: meta.headers,
      rowCount: meta.rowCount,
      tsColumns: [...meta.tsColumns],
      numericColumns: meta.numericColumns ? [...meta.numericColumns] : [],
    };
  }

  /**
   * Get unique values for a column (for checkbox filter dropdowns)
   * Respects all active filters except the checkbox filter for this column.
   */
  getColumnUniqueValues(tabId, colName, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return [];

    const safeCol = meta.colMap[colName];
    if (!safeCol) return [];

    const {
      filterText = "",
      filterRegex = false,
      limit = 1000,
      checkboxFilters = {},
    } = options;

    const db = meta.db;
    const params = [];
    const whereConditions = [];

    // Exclude self-column from checkbox filters to avoid circular filtering
    const filteredOptions = checkboxFilters[colName]
      ? { ...options, checkboxFilters: Object.fromEntries(Object.entries(checkboxFilters).filter(([cn]) => cn !== colName)) }
      : options;
    this._applyStandardFilters(filteredOptions, meta, whereConditions, params);

    // Filter values list by search text (supports regex mode)
    if (filterText.trim()) {
      if (filterRegex) {
        whereConditions.push(`${safeCol} REGEXP ?`);
        params.push(filterText);
      } else {
        whereConditions.push(`${safeCol} LIKE ?`);
        params.push(`%${filterText}%`);
      }
    }

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
    const sql = `SELECT ${safeCol} as val, COUNT(*) as cnt FROM data ${whereClause} GROUP BY ${safeCol} ORDER BY cnt DESC LIMIT ?`;
    params.push(limit);

    return db.prepare(sql).all(...params);
  }

  /**
   * Get every value of a single column for the current (filtered/searched) view —
   * for spreadsheet-style "copy column out". Honors all standard filters + search.
   * distinct:false → all values in row order (with duplicates); distinct:true →
   * unique values sorted (ready to dedup/paste). Returns { values, total } where
   * total is the row count scanned. Capped at `limit` (default 1M) to bound memory.
   */
  getColumnValues(tabId, colName, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { values: [], total: 0, truncated: false };

    const isTagCol = colName === "__tags__";
    const safeCol = isTagCol ? null : meta.colMap[colName];
    if (!isTagCol && !safeCol) return { values: [], total: 0, truncated: false };

    const { distinct = false, limit = 1000000 } = options;
    const db = meta.db;
    const params = [];
    const whereConditions = [];
    this._applyStandardFilters(options, meta, whereConditions, params);
    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

    // Tags live in a side table keyed by rowid; join so filters (on data) still apply.
    const fromExpr = isTagCol
      ? `data JOIN tags ON tags.rowid = data.rowid`
      : `data`;
    const valExpr = isTagCol ? `tags.tag` : safeCol;
    const sql = distinct
      ? `SELECT DISTINCT ${valExpr} AS val FROM ${fromExpr} ${whereClause} ORDER BY val LIMIT ?`
      : `SELECT ${valExpr} AS val FROM ${fromExpr} ${whereClause} ORDER BY data.rowid LIMIT ?`;
    params.push(limit + 1); // fetch one extra to detect truncation

    try {
      const rows = db.prepare(sql).all(...params);
      const truncated = rows.length > limit;
      const values = (truncated ? rows.slice(0, limit) : rows).map((r) => r.val == null ? "" : String(r.val));
      return { values, total: values.length, truncated };
    } catch (e) {
      dbg("DB", `getColumnValues failed`, { tabId, colName, error: e.message });
      return { values: [], total: 0, truncated: false, error: e.message };
    }
  }

  /**
   * Get group values with counts (for column grouping display)
   * Respects all active filters.
   */
  getGroupValues(tabId, groupCol, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return [];

    const safeCol = meta.colMap[groupCol];
    if (!safeCol) return [];

    const { parentFilters = [] } = options;

    const db = meta.db;
    const params = [];
    const whereConditions = [];

    // Parent group filters (for multi-level grouping)
    for (const pf of parentFilters) {
      const sc = meta.colMap[pf.col];
      if (sc) {
        whereConditions.push(`${sc} = ?`);
        params.push(pf.value);
      }
    }

    this._applyStandardFilters(options, meta, whereConditions, params);

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
    const sql = `SELECT ${safeCol} as val, COUNT(*) as cnt FROM data ${whereClause} GROUP BY ${safeCol} ORDER BY cnt DESC`;

    return db.prepare(sql).all(...params);
  }

  /**
   * Count rows matching a search term (for cross-tab find)
   */
  searchCount(tabId, searchTerm, searchMode = "mixed", searchCondition = "contains") {
    const meta = this.databases.get(tabId);
    if (!meta) return 0;
    if (!searchTerm.trim()) return 0;

    const conditions = [];
    const params = [];
    this._applySearch(searchTerm, searchMode, meta, conditions, params, searchCondition);
    if (conditions.length === 0) return 0;
    const sql = `SELECT COUNT(*) as cnt FROM data WHERE ${conditions.join(" AND ")}`;
    return meta.db.prepare(sql).get(...params).cnt;
  }

}

module.exports = QueryStoreMethods.prototype;
