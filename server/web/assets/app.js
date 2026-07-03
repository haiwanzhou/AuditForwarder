const state = {
  token: localStorage.getItem("af.managerToken") || "",
  lastConfigText: "",
  lastBatchesText: "",
  hosts: [],
  operationRecords: parseJson(localStorage.getItem("af.operationRecords") || "[]", []),
  actorIdentity: localStorage.getItem("af.actorIdentity") || "本地控制台用户",
};

const $ = (id) => document.getElementById(id);

const els = {
  endpointText: $("endpointText"),
  refreshBtn: $("refreshBtn"),
  tokenBtn: $("tokenBtn"),
  notice: $("notice"),
  statusPill: $("statusPill"),
  eventsCollected: $("eventsCollected"),
  eventsUploaded: $("eventsUploaded"),
  eventsFailed: $("eventsFailed"),
  alerts: $("alerts"),
  uptime: $("uptime"),
  eventsDropped: $("eventsDropped"),
  bytesUploaded: $("bytesUploaded"),
  lastUpdated: $("lastUpdated"),
  configView: $("configView"),
  reloadConfigBtn: $("reloadConfigBtn"),
  copyConfigBtn: $("copyConfigBtn"),
  batchList: $("batchList"),
  batchCount: $("batchCount"),
  hostList: $("hostList"),
  hostCount: $("hostCount"),
  hostHistoryTitle: $("hostHistoryTitle"),
  hostHistoryOutput: $("hostHistoryOutput"),
  refreshSecurityBtn: $("refreshSecurityBtn"),
  securitySummary: $("securitySummary"),
  alertList: $("alertList"),
  operationLogList: $("operationLogList"),
  analyticsLogCount: $("analyticsLogCount"),
  analyticsAlertCount: $("analyticsAlertCount"),
  operationTypeBreakdown: $("operationTypeBreakdown"),
  alertSeverityBreakdown: $("alertSeverityBreakdown"),
  hostId: $("hostId"),
  hostName: $("hostName"),
  hostIp: $("hostIp"),
  hostHardware: $("hostHardware"),
  hostOs: $("hostOs"),
  hostPermissions: $("hostPermissions"),
  hostNote: $("hostNote"),
  saveHostBtn: $("saveHostBtn"),
  resetHostFormBtn: $("resetHostFormBtn"),
  remoteHostId: $("remoteHostId"),
  remoteCommandType: $("remoteCommandType"),
  remotePayload: $("remotePayload"),
  sendRemoteCommandBtn: $("sendRemoteCommandBtn"),
  actorIdentity: $("actorIdentity"),
  operationRecordList: $("operationRecordList"),
  operationRecordJson: $("operationRecordJson"),
  recordCount: $("recordCount"),
  copyRecordsBtn: $("copyRecordsBtn"),
  exportRecordsBtn: $("exportRecordsBtn"),
  clearRecordsBtn: $("clearRecordsBtn"),
  upgradeUrl: $("upgradeUrl"),
  upgradeBtn: $("upgradeBtn"),
  tokenDialog: $("tokenDialog"),
  tokenInput: $("tokenInput"),
  clearTokenBtn: $("clearTokenBtn"),
  cancelTokenBtn: $("cancelTokenBtn"),
  saveTokenBtn: $("saveTokenBtn"),
};

const validationRules = {
  hostId: { label: "主机 ID", pattern: /^[A-Za-z0-9_-]{2,64}$/, optional: true, message: "主机 ID 只能包含字母、数字、短横线和下划线，长度为 2 到 64 个字符。" },
  hostName: { label: "主机名称", required: true, min: 1, max: 80 },
  hostIp: { label: "IP 地址", format: "ipv4", optional: true, message: "IP 地址格式不正确，例如 192.168.1.10。" },
  hostHardware: { label: "硬件配置", max: 120, optional: true },
  hostOs: { label: "操作系统版本", max: 120, optional: true },
  hostPermissions: { label: "远控权限", format: "permissionList", maxItems: 20, optional: true },
  hostNote: { label: "备注", max: 240, optional: true },
  remoteHostId: { label: "目标主机 ID", required: true, pattern: /^[A-Za-z0-9_-]{2,64}$/, message: "目标主机 ID 格式不正确。" },
  remotePayload: { label: "指令参数", max: 2048, optional: true },
  upgradeUrl: { label: "升级包 URL", required: true, format: "httpUrl", max: 2048 },
  tokenInput: { label: "管理 Token", max: 256, optional: true },
};

function authHeaders(extra = {}) {
  const headers = { ...extra };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  return headers;
}

function showNotice(message, type = "success") {
  els.notice.textContent = message;
  els.notice.className = `notice ${type}`;
  window.clearTimeout(showNotice.timer);
  showNotice.timer = window.setTimeout(() => {
    els.notice.className = "notice hidden";
  }, 4200);
}

function timestampSeconds(date = new Date()) {
  return new Date(Math.floor(date.getTime() / 1000) * 1000).toISOString().replace(".000Z", "Z");
}

function currentActor() {
  const identity = (els.actorIdentity?.value || state.actorIdentity || "本地控制台用户").trim();
  return {
    identity,
    source: "web_console",
    endpoint: window.location.host || "local",
    user_agent: navigator.userAgent,
  };
}

function persistOperationRecords() {
  localStorage.setItem("af.operationRecords", JSON.stringify(state.operationRecords));
}

function recordOperation({ object, type, details, status, error }) {
  const record = {
    actor: currentActor(),
    timestamp: timestampSeconds(),
    object: object || "未指定对象",
    operation_type: type || "unknown",
    operation_details: details || "",
    status: status || (error ? "failure" : "success"),
  };
  if (error) record.error_message = String(error.message || error);
  state.operationRecords.unshift(record);
  state.operationRecords = state.operationRecords.slice(0, 200);
  persistOperationRecords();
  renderOperationRecords();
  return record;
}

function renderOperationRecords() {
  const records = Array.isArray(state.operationRecords) ? state.operationRecords : [];
  els.recordCount.textContent = `${records.length} 条记录`;
  els.operationRecordJson.textContent = JSON.stringify(records, null, 2);
  if (records.length === 0) {
    els.operationRecordList.innerHTML = `
      <tr>
        <td colspan="6" class="empty-cell">暂无结构化操作记录。执行刷新、主机维护、日志查看、配置重载或升级请求后会自动生成。</td>
      </tr>
    `;
    return;
  }
  els.operationRecordList.innerHTML = records.map((record) => `
    <tr>
      <td>${escapeHtml(record.timestamp)}</td>
      <td>${escapeHtml(record.actor?.identity || "--")}</td>
      <td>${escapeHtml(record.object)}</td>
      <td><code>${escapeHtml(record.operation_type)}</code></td>
      <td>${escapeHtml(record.operation_details)}</td>
      <td><span class="status-tag ${record.status === "success" ? "success" : "failure"}">${record.status === "success" ? "成功" : "失败"}</span></td>
    </tr>
  `).join("");
}

async function copyOperationRecords() {
  const text = JSON.stringify(state.operationRecords, null, 2);
  try {
    await navigator.clipboard.writeText(text);
    showNotice("结构化操作记录已复制。");
    recordOperation({
      object: "结构化操作记录",
      type: "copy_operation_records",
      details: `复制 ${state.operationRecords.length} 条操作记录`,
      status: "success",
    });
  } catch (err) {
    showNotice("当前浏览器不允许自动复制，请手动选择复制。", "error");
    recordOperation({
      object: "结构化操作记录",
      type: "copy_operation_records",
      details: "复制结构化操作记录失败",
      status: "failure",
      error: err,
    });
  }
}

function exportOperationRecords() {
  const text = JSON.stringify(state.operationRecords, null, 2);
  const blob = new Blob([text], { type: "application/json;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `auditforwarder-operation-records-${timestampSeconds().replaceAll(":", "-")}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(link.href);
  showNotice("结构化操作记录已导出。");
  recordOperation({
    object: "结构化操作记录",
    type: "export_operation_records",
    details: `导出 ${state.operationRecords.length} 条操作记录为 JSON 文件`,
    status: "success",
  });
}

function clearOperationRecords() {
  const removed = state.operationRecords.length;
  state.operationRecords = [];
  persistOperationRecords();
  renderOperationRecords();
  showNotice("结构化操作记录已清空。");
  recordOperation({
    object: "结构化操作记录",
    type: "clear_operation_records",
    details: `清空 ${removed} 条历史操作记录`,
    status: "success",
  });
}

function setLoading(button, loadingText) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = loadingText;
  return () => {
    button.disabled = false;
    button.textContent = original;
  };
}

async function request(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: authHeaders(options.headers || {}),
  });
  const text = await response.text();
  if (!response.ok) {
    const data = parseJson(text, null);
    if (data && Array.isArray(data.validation_errors)) {
      throw new Error(data.validation_errors.map((item) => `${item.field}: ${item.message}`).join("；"));
    }
    const message = response.status === 401
      ? "接口未授权，请设置正确的管理 Token。"
      : `接口请求失败：HTTP ${response.status}`;
    throw new Error(`${message}${text ? ` ${text}` : ""}`);
  }
  return text;
}

function ensureValidationNode(input) {
  if (!input) return null;
  const field = input.closest(".field") || input.parentElement;
  if (!field) return null;
  let node = field.querySelector(".field-feedback");
  if (!node) {
    node = document.createElement("small");
    node.className = "field-feedback";
    field.appendChild(node);
  }
  return node;
}

function validateValue(value, rule) {
  const text = String(value ?? "").trim();
  if (rule.required && !text) return `${rule.label}不能为空。`;
  if (!text && rule.optional) return "";
  if (rule.min && text.length < rule.min) return `${rule.label}长度不能少于 ${rule.min} 个字符。`;
  if (rule.max && text.length > rule.max) return `${rule.label}长度不能超过 ${rule.max} 个字符。`;
  if (rule.pattern && !rule.pattern.test(text)) return rule.message || `${rule.label}格式不正确。`;
  if (rule.format === "ipv4" && text && !/^((25[0-5]|2[0-4]\d|1?\d?\d)(\.|$)){4}$/.test(text)) {
    return rule.message || `${rule.label}格式不正确。`;
  }
  if (rule.format === "httpUrl" && text && !/^https?:\/\/\S+$/i.test(text)) {
    return `${rule.label}必须以 http:// 或 https:// 开头。`;
  }
  if (rule.format === "permissionList" && text) {
    const items = permissionList(text);
    if (items.length > (rule.maxItems || 20)) return `${rule.label}不能超过 ${rule.maxItems || 20} 项。`;
    if (items.some((item) => !/^[A-Za-z0-9_*-]+$/.test(item))) {
      return `${rule.label}只能包含字母、数字、下划线、短横线或 *，多项用逗号分隔。`;
    }
  }
  if (rule.minValue !== undefined || rule.maxValue !== undefined) {
    const number = Number(text);
    if (!Number.isFinite(number)) return `${rule.label}必须是数字。`;
    if (rule.minValue !== undefined && number < rule.minValue) return `${rule.label}不能小于 ${rule.minValue}。`;
    if (rule.maxValue !== undefined && number > rule.maxValue) return `${rule.label}不能大于 ${rule.maxValue}。`;
  }
  return "";
}

function setFieldValidation(input, message) {
  if (!input) return;
  const node = ensureValidationNode(input);
  input.classList.toggle("invalid", Boolean(message));
  input.classList.toggle("valid", !message && String(input.value || "").trim().length > 0);
  if (node) {
    node.textContent = message || "格式正确";
    node.className = `field-feedback ${message ? "error" : "success"}`;
  }
}

function validateField(input, rule) {
  const message = validateValue(input?.value, rule);
  setFieldValidation(input, message);
  return message;
}

function validateFields(fieldIds) {
  const errors = [];
  for (const id of fieldIds) {
    const rule = validationRules[id];
    const input = els[id];
    if (!rule || !input) continue;
    const message = validateField(input, rule);
    if (message) errors.push(message);
  }
  if (errors.length > 0) {
    showNotice(errors[0], "error");
    const firstId = fieldIds.find((id) => validateValue(els[id]?.value, validationRules[id]));
    if (firstId && els[firstId]) els[firstId].focus();
    return false;
  }
  return true;
}

function bindValidation() {
  Object.entries(validationRules).forEach(([id, rule]) => {
    const input = els[id];
    if (!input) return;
    ensureValidationNode(input);
    input.addEventListener("input", () => validateField(input, rule));
    input.addEventListener("blur", () => validateField(input, rule));
  });
}

function parseJson(text, fallback) {
  try {
    return JSON.parse(text);
  } catch (err) {
    return fallback;
  }
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString("zh-CN");
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`;
}

function formatUptime(seconds) {
  const total = Number(seconds || 0);
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  if (days > 0) return `${days} 天 ${hours} 小时`;
  if (hours > 0) return `${hours} 小时 ${minutes} 分钟`;
  return `${minutes} 分钟`;
}

function renderStatus(data) {
  const running = Boolean(data.running);
  els.statusPill.textContent = running ? "运行中" : "未运行";
  els.statusPill.className = `pill ${running ? "running" : "stopped"}`;
  els.eventsCollected.textContent = formatNumber(data.events_collected);
  els.eventsUploaded.textContent = formatNumber(data.events_uploaded);
  els.eventsFailed.textContent = formatNumber(data.events_failed);
  els.alerts.textContent = formatNumber(data.alerts);
  els.uptime.textContent = formatUptime(data.uptime_seconds);
  els.eventsDropped.textContent = formatNumber(data.events_dropped);
  els.bytesUploaded.textContent = formatBytes(data.bytes_uploaded);
  els.lastUpdated.textContent = new Date().toLocaleString("zh-CN");
}

function renderConfig(text) {
  const data = parseJson(text, null);
  state.lastConfigText = data ? JSON.stringify(data, null, 2) : text;
  els.configView.textContent = state.lastConfigText || "暂无配置数据";
}

function renderBatches(data) {
  const batches = Array.isArray(data.batches) ? data.batches : [];
  state.lastBatchesText = JSON.stringify({ batches }, null, 2);
  els.batchCount.textContent = `${batches.length} 个批次`;
  if (batches.length === 0) {
    els.batchList.innerHTML = `
      <div class="empty-state">
        <strong>暂无证据批次</strong>
        <p>当前还没有生成证据批次。采集到足够事件后，链模块会自动打包并在这里展示。</p>
      </div>
    `;
    return;
  }
  els.batchList.innerHTML = batches.map((batch, index) => `
    <article class="batch-item">
      <div class="batch-title">
        <div>
          <span class="batch-index">批次 ${String(index + 1).padStart(2, "0")}</span>
          <strong class="batch-id">${escapeHtml(batch.id || "未命名")}</strong>
        </div>
        <span class="batch-badge ${batch.signature ? "signed" : "unsigned"}">
          ${batch.signature ? "已签名" : "未签名"}
        </span>
      </div>

      <div class="batch-summary">
        <div class="summary-cell">
          <span>批次 ID</span>
          <strong>${escapeHtml(shortHash(batch.id))}</strong>
        </div>
        <div class="summary-cell">
          <span>Merkle Root 摘要</span>
          <strong>${escapeHtml(shortHash(batch.merkle_root))}</strong>
        </div>
        <div class="summary-cell">
          <span>签名摘要</span>
          <strong>${escapeHtml(shortHash(batch.signature))}</strong>
        </div>
      </div>

      <div class="batch-details">
        <div class="hash-row">
          <span>Merkle Root</span>
          <code>${escapeHtml(batch.merkle_root || "--")}</code>
        </div>
        <div class="hash-row">
          <span>数字签名</span>
          <code>${escapeHtml(batch.signature || "--")}</code>
        </div>
      </div>
    </article>
  `).join("");
}

function permissionList(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function renderHosts(data) {
  const hosts = Array.isArray(data.hosts) ? data.hosts : [];
  state.hosts = hosts;
  const onlineCount = hosts.filter((host) => host.online).length;
  els.hostCount.textContent = `${hosts.length} 台主机，${onlineCount} 台在线`;
  if (hosts.length === 0) {
    els.hostList.innerHTML = `
      <div class="empty-state">
        <strong>暂无主机信息</strong>
        <p>请先添加主机，或让远端代理通过 <code>/hosts/heartbeat</code> 上报心跳。</p>
      </div>
    `;
    return;
  }
  els.hostList.innerHTML = hosts.map((host) => `
    <article class="host-card">
      <div class="host-card-head">
        <div>
          <span class="batch-index">${escapeHtml(host.online ? "在线" : "离线")}</span>
          <strong class="batch-id">${escapeHtml(host.name || host.id || "未命名主机")}</strong>
          <code>${escapeHtml(host.id || "--")}</code>
        </div>
        <span class="pill ${host.online ? "running" : "stopped"}">${host.online ? "在线" : "离线"}</span>
      </div>
      <div class="host-grid">
        <div><span>IP 地址</span><strong>${escapeHtml(host.ip_address || "--")}</strong></div>
        <div><span>操作系统</span><strong>${escapeHtml(host.os_version || "--")}</strong></div>
        <div><span>硬件配置</span><strong>${escapeHtml(host.hardware || "--")}</strong></div>
        <div><span>网络状态</span><strong>${escapeHtml(host.network_status || "--")}</strong></div>
        <div><span>CPU</span><strong>${formatNumber(host.cpu_usage_percent)}%</strong></div>
        <div><span>内存</span><strong>${formatNumber(host.memory_usage_percent)}%</strong></div>
        <div><span>最后心跳</span><strong>${escapeHtml(host.last_seen || "--")}</strong></div>
        <div><span>权限</span><strong>${escapeHtml((host.permissions || []).join(", ") || "--")}</strong></div>
      </div>
      ${host.note ? `<p class="host-note">${escapeHtml(host.note)}</p>` : ""}
      <div class="section-actions">
        <button class="button ghost small" data-host-action="edit" data-host-id="${escapeHtml(host.id)}">编辑</button>
        <button class="button ghost small" data-host-action="select" data-host-id="${escapeHtml(host.id)}">设为远控目标</button>
        <button class="button ghost small" data-host-action="history-metrics" data-host-id="${escapeHtml(host.id)}">资源历史</button>
        <button class="button ghost small" data-host-action="history-audit" data-host-id="${escapeHtml(host.id)}">审计摘要</button>
        <button class="button ghost small" data-host-action="history-commands" data-host-id="${escapeHtml(host.id)}">命令结果</button>
        <button class="button ghost small" data-host-action="history-logs" data-host-id="${escapeHtml(host.id)}">操作日志</button>
        <button class="button ghost small" data-host-action="history-alerts" data-host-id="${escapeHtml(host.id)}">告警历史</button>
        <button class="button danger small" data-host-action="delete" data-host-id="${escapeHtml(host.id)}">删除</button>
      </div>
    </article>
  `).join("");
}

function parseJsonlLines(jsonl, limit = 10) {
  return String(jsonl || "")
    .split(/\r?\n/)
    .filter(Boolean)
    .slice(-limit)
    .reverse()
    .map((line) => parseJson(line, { raw: line }));
}

function renderSecurityItems(container, items, emptyText, type) {
  if (!container) return;
  if (!items.length) {
    container.innerHTML = `<div class="empty-state"><strong>${escapeHtml(emptyText)}</strong></div>`;
    return;
  }
  container.innerHTML = items.map((item) => {
    const severity = item.severity || "info";
    const title = item.message || item.operation_type || item.event_type || item.rule_id || "未命名记录";
    const meta = [
      item.timestamp,
      item.host_id,
      item.rule_id,
      item.operation_type || item.event_type,
      item.status,
    ].filter(Boolean).join(" · ");
    const details = item.evidence || item.command || item.operation_details || item.raw || "";
    return `
      <article class="security-item ${type === "alert" ? severity : ""}">
        <div class="security-item-head">
          <strong>${escapeHtml(title)}</strong>
          ${type === "alert" ? `<span class="severity ${escapeHtml(severity)}">${escapeHtml(severity)}</span>` : ""}
        </div>
        <p>${escapeHtml(meta || "--")}</p>
        ${details ? `<code>${escapeHtml(shortHash(details))}</code>` : ""}
      </article>
    `;
  }).join("");
}

function renderBreakdown(container, counts, emptyText) {
  if (!container) return;
  const entries = Object.entries(counts || {}).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) {
    container.innerHTML = `<span class="muted">${escapeHtml(emptyText)}</span>`;
    return;
  }
  const max = Math.max(...entries.map((item) => Number(item[1]) || 0), 1);
  container.innerHTML = entries.map(([name, value]) => {
    const width = Math.max(6, Math.round(((Number(value) || 0) / max) * 100));
    return `
      <div class="breakdown-row">
        <span>${escapeHtml(name)}</span>
        <div class="breakdown-bar"><i style="width:${width}%"></i></div>
        <strong>${formatNumber(value)}</strong>
      </div>
    `;
  }).join("");
}

function renderSecurityAnalytics(data) {
  if (els.analyticsLogCount) els.analyticsLogCount.textContent = formatNumber(data.log_count || 0);
  if (els.analyticsAlertCount) els.analyticsAlertCount.textContent = formatNumber(data.alert_count || 0);
  renderBreakdown(els.operationTypeBreakdown, data.operation_types, "暂无操作类型统计");
  renderBreakdown(els.alertSeverityBreakdown, data.alert_severities, "暂无告警级别统计");
}

async function loadSecurityMonitor() {
  if (!els.alertList || !els.operationLogList) return;
  try {
    const [alertsText, logsText, analyticsText] = await Promise.all([
      request("/alerts?limit=20"),
      request("/logs/query?limit=20"),
      request("/logs/analytics?limit=1000"),
    ]);
    const alerts = parseJson(alertsText, {});
    const logs = parseJson(logsText, {});
    const analytics = parseJson(analyticsText, {});
    const alertItems = parseJsonlLines(alerts.jsonl, 20);
    const logItems = parseJsonlLines(logs.jsonl, 20);
    renderSecurityItems(els.alertList, alertItems, "暂无违规告警", "alert");
    renderSecurityItems(els.operationLogList, logItems, "暂无操作日志", "log");
    renderSecurityAnalytics(analytics);
    els.securitySummary.textContent = `${alertItems.length} 条告警，${logItems.length} 条日志`;
  } catch (err) {
    els.securitySummary.textContent = "加载失败";
    renderSecurityItems(els.alertList, [], "告警加载失败", "alert");
    renderSecurityItems(els.operationLogList, [], "日志加载失败", "log");
    showNotice(err.message, "error");
  }
}

async function loadHostHistory(hostId, kind) {
  if (!hostId) return;
  const labels = {
    metrics: "资源指标",
    audit: "审计摘要",
    commands: "命令结果",
    logs: "操作日志",
    alerts: "告警历史",
  };
  const label = labels[kind] || "资源指标";
  els.hostHistoryTitle.textContent = `正在加载 ${hostId} 的${label}...`;
  els.hostHistoryOutput.textContent = "加载中...";
  try {
    const text = await request(`/hosts/history?host_id=${encodeURIComponent(hostId)}&kind=${encodeURIComponent(kind)}`);
    const data = parseJson(text, {});
    const lines = String(data.jsonl || "")
      .split(/\r?\n/)
      .filter(Boolean)
      .slice(-20)
      .map((line) => {
        const parsed = parseJson(line, null);
        return parsed ? JSON.stringify(parsed, null, 2) : line;
      });
    els.hostHistoryTitle.textContent = `${hostId} 的${label}，最近 ${lines.length} 条`;
    els.hostHistoryOutput.textContent = lines.length > 0 ? lines.join("\n\n") : "暂无历史数据。";
    recordOperation({
      object: hostId,
      type: "view_host_history",
      details: `查看${label}历史`,
      status: "success",
    });
  } catch (err) {
    els.hostHistoryTitle.textContent = `${hostId} 的${label}加载失败`;
    els.hostHistoryOutput.textContent = err.message;
    showNotice(err.message, "error");
  }
}

function resetHostForm() {
  els.hostId.value = "";
  els.hostName.value = "";
  els.hostIp.value = "";
  els.hostHardware.value = "";
  els.hostOs.value = "";
  els.hostPermissions.value = "remote_control";
  els.hostNote.value = "";
  ["hostId", "hostName", "hostIp", "hostHardware", "hostOs", "hostPermissions", "hostNote"].forEach((id) => {
    if (els[id]) {
      els[id].classList.remove("invalid", "valid");
      const node = els[id].closest(".field")?.querySelector(".field-feedback");
      if (node) node.textContent = "";
    }
  });
}

function fillHostForm(host) {
  els.hostId.value = host.id || "";
  els.hostName.value = host.name || "";
  els.hostIp.value = host.ip_address || "";
  els.hostHardware.value = host.hardware || "";
  els.hostOs.value = host.os_version || "";
  els.hostPermissions.value = (host.permissions || []).join(",");
  els.hostNote.value = host.note || "";
  els.remoteHostId.value = host.id || "";
  validateFields(["hostId", "hostName", "hostIp", "hostHardware", "hostOs", "hostPermissions", "hostNote", "remoteHostId"]);
  location.hash = "#hosts";
}

async function saveHost() {
  if (!validateFields(["hostId", "hostName", "hostIp", "hostHardware", "hostOs", "hostPermissions", "hostNote"])) {
    recordOperation({
      object: "主机信息",
      type: "validate_host_form",
      details: "前端验证失败，未提交主机信息",
      status: "failure",
    });
    return;
  }
  const host = {
    id: els.hostId.value.trim(),
    name: els.hostName.value.trim(),
    ip_address: els.hostIp.value.trim(),
    hardware: els.hostHardware.value.trim(),
    os_version: els.hostOs.value.trim(),
    permissions: permissionList(els.hostPermissions.value),
    note: els.hostNote.value.trim(),
  };
  const exists = Boolean(host.id && state.hosts.some((item) => item.id === host.id));
  const done = setLoading(els.saveHostBtn, "保存中...");
  try {
    const text = await request(exists ? `/hosts?id=${encodeURIComponent(host.id)}` : "/hosts", {
      method: exists ? "PUT" : "POST",
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: JSON.stringify(host),
    });
    renderHosts(parseJson(text, { hosts: [] }));
    showNotice("主机信息已保存。");
    recordOperation({
      object: host.name,
      type: exists ? "update_host" : "add_host",
      details: `主机ID=${host.id || "自动生成"}，权限=${host.permissions.join(",") || "status_view"}`,
      status: "success",
    });
    resetHostForm();
  } catch (err) {
    showNotice(err.message, "error");
    recordOperation({
      object: host.name || "主机信息",
      type: exists ? "update_host" : "add_host",
      details: "保存主机信息失败",
      status: "failure",
      error: err,
    });
  } finally {
    done();
  }
}

async function deleteHost(hostId) {
  if (!hostId) return;
  const host = state.hosts.find((item) => item.id === hostId);
  try {
    const text = await request(`/hosts?id=${encodeURIComponent(hostId)}`, { method: "DELETE" });
    renderHosts(parseJson(text, { hosts: [] }));
    showNotice("主机信息已删除。");
    recordOperation({
      object: host?.name || hostId,
      type: "delete_host",
      details: `删除主机ID=${hostId}`,
      status: "success",
    });
  } catch (err) {
    showNotice(err.message, "error");
    recordOperation({
      object: host?.name || hostId,
      type: "delete_host",
      details: `删除主机ID=${hostId}失败`,
      status: "failure",
      error: err,
    });
  }
}

async function sendRemoteCommand() {
  if (!validateFields(["remoteHostId", "remotePayload"])) {
    recordOperation({
      object: "远程控制指令",
      type: "validate_remote_command",
      details: "前端验证失败，未发送远控指令",
      status: "failure",
    });
    return;
  }
  const targetHostId = els.remoteHostId.value.trim();
  const commandType = els.remoteCommandType.value;
  const payload = els.remotePayload.value.trim();
  const done = setLoading(els.sendRemoteCommandBtn, "发送中...");
  try {
    const text = await request("/remote/control", {
      method: "POST",
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: JSON.stringify({
        target_host_id: targetHostId,
        command_type: commandType,
        payload,
      }),
    });
    const data = parseJson(text, {});
    showNotice(`远程指令已进入目标主机队列：${data.command_id || "已接受"}`);
    recordOperation({
      object: targetHostId,
      type: "send_remote_command",
      details: `指令类型=${commandType}，队列ID=${data.command_id || "--"}，加密=${data.queue_encryption || "AES-256-GCM"}`,
      status: "success",
    });
  } catch (err) {
    showNotice(err.message, "error");
    recordOperation({
      object: targetHostId,
      type: "send_remote_command",
      details: `发送远控指令失败，指令类型=${commandType}`,
      status: "failure",
      error: err,
    });
  } finally {
    done();
  }
}

function shortHash(value) {
  const text = String(value || "--");
  if (text.length <= 18) return text;
  return `${text.slice(0, 10)}...${text.slice(-8)}`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function refreshAll() {
  const done = setLoading(els.refreshBtn, "刷新中...");
  try {
    const [statusText, configText, batchesText, hostsText] = await Promise.all([
      request("/status"),
      request("/config"),
      request("/batches"),
      request("/hosts"),
    ]);
    renderStatus(parseJson(statusText, {}));
    renderConfig(configText);
    renderBatches(parseJson(batchesText, { batches: [] }));
    renderHosts(parseJson(hostsText, { hosts: [] }));
    await loadSecurityMonitor();
    showNotice("数据已刷新。");
    recordOperation({
      object: "管理控制台数据",
      type: "refresh_dashboard",
      details: "刷新运行状态、配置快照、证据批次和主机列表",
      status: "success",
    });
  } catch (err) {
    els.statusPill.textContent = "异常";
    els.statusPill.className = "pill error";
    showNotice(err.message, "error");
    recordOperation({
      object: "管理控制台数据",
      type: "refresh_dashboard",
      details: "刷新运行状态、配置快照、证据批次和主机列表失败",
      status: "failure",
      error: err,
    });
  } finally {
    done();
  }
}

async function reloadConfig() {
  const done = setLoading(els.reloadConfigBtn, "加载中...");
  try {
    const text = await request("/config/reload", { method: "POST" });
    showNotice(`配置已重新加载：${text.replace(/\s+/g, " ").trim()}`);
    const configText = await request("/config");
    renderConfig(configText);
    recordOperation({
      object: "系统配置",
      type: "reload_config",
      details: "调用 /config/reload 并刷新配置快照",
      status: "success",
    });
  } catch (err) {
    showNotice(err.message, "error");
    recordOperation({
      object: "系统配置",
      type: "reload_config",
      details: "调用 /config/reload 失败",
      status: "failure",
      error: err,
    });
  } finally {
    done();
  }
}

async function submitUpgrade() {
  if (!validateFields(["upgradeUrl"])) {
    recordOperation({
      object: "远程升级",
      type: "validate_upgrade_url",
      details: "前端验证失败，未提交升级请求",
      status: "failure",
    });
    return;
  }
  const url = els.upgradeUrl.value.trim();
  const done = setLoading(els.upgradeBtn, "提交中...");
  try {
    const text = await request("/upgrade", {
      method: "POST",
      headers: { "Content-Type": "text/plain; charset=utf-8" },
      body: url,
    });
    showNotice(`升级请求已提交：${text.replace(/\s+/g, " ").trim()}`);
    recordOperation({
      object: url,
      type: "submit_upgrade",
      details: "调用 /upgrade 提交升级包 URL",
      status: "success",
    });
  } catch (err) {
    showNotice(err.message, "error");
    recordOperation({
      object: url,
      type: "submit_upgrade",
      details: "调用 /upgrade 提交升级包 URL 失败",
      status: "failure",
      error: err,
    });
  } finally {
    done();
  }
}

async function copyConfig() {
  if (!state.lastConfigText) return;
  try {
    await navigator.clipboard.writeText(state.lastConfigText);
    showNotice("配置内容已复制。");
    recordOperation({
      object: "当前配置快照",
      type: "copy_config",
      details: `复制配置内容，长度=${state.lastConfigText.length}`,
      status: "success",
    });
  } catch (err) {
    showNotice("当前浏览器不允许自动复制，请手动选择复制。", "error");
    recordOperation({
      object: "当前配置快照",
      type: "copy_config",
      details: "复制配置内容失败",
      status: "failure",
      error: err,
    });
  }
}

function openTokenDialog() {
  els.tokenInput.value = state.token;
  els.tokenDialog.classList.remove("hidden");
  els.tokenInput.focus();
}

function closeTokenDialog() {
  els.tokenDialog.classList.add("hidden");
}

function saveToken() {
  state.token = els.tokenInput.value.trim();
  if (state.token) localStorage.setItem("af.managerToken", state.token);
  else localStorage.removeItem("af.managerToken");
  closeTokenDialog();
  showNotice("Token 已保存，正在重新请求数据。");
  recordOperation({
    object: "管理接口 Token",
    type: "save_token",
    details: state.token ? "保存 Bearer Token，用于访问受保护接口" : "清空 Bearer Token",
    status: "success",
  });
  refreshAll();
}

function clearToken() {
  state.token = "";
  localStorage.removeItem("af.managerToken");
  els.tokenInput.value = "";
  showNotice("Token 已清除。");
  recordOperation({
    object: "管理接口 Token",
    type: "clear_token",
    details: "清除浏览器本地保存的 Bearer Token",
    status: "success",
  });
}

function saveActorIdentity() {
  state.actorIdentity = (els.actorIdentity.value || "本地控制台用户").trim();
  localStorage.setItem("af.actorIdentity", state.actorIdentity);
  recordOperation({
    object: "执行者身份",
    type: "update_actor_identity",
    details: `执行者身份更新为：${state.actorIdentity}`,
    status: "success",
  });
}

function bindNavigation() {
  const links = [...document.querySelectorAll(".nav-link")];
  links.forEach((link) => {
    link.addEventListener("click", () => {
      links.forEach((item) => item.classList.remove("active"));
      link.classList.add("active");
    });
  });
}

function init() {
  els.endpointText.textContent = window.location.host || "本机服务";
  els.actorIdentity.value = state.actorIdentity;
  els.refreshBtn.addEventListener("click", refreshAll);
  if (els.refreshSecurityBtn) els.refreshSecurityBtn.addEventListener("click", loadSecurityMonitor);
  els.reloadConfigBtn.addEventListener("click", reloadConfig);
  els.copyConfigBtn.addEventListener("click", copyConfig);
  els.saveHostBtn.addEventListener("click", saveHost);
  els.resetHostFormBtn.addEventListener("click", resetHostForm);
  els.sendRemoteCommandBtn.addEventListener("click", sendRemoteCommand);
  els.hostList.addEventListener("click", (event) => {
    const button = event.target.closest("[data-host-action]");
    if (!button) return;
    const hostId = button.getAttribute("data-host-id");
    const host = state.hosts.find((item) => item.id === hostId);
    const action = button.getAttribute("data-host-action");
    if (action === "edit" && host) fillHostForm(host);
    if (action === "select" && host) {
      els.remoteHostId.value = host.id;
      validateField(els.remoteHostId, validationRules.remoteHostId);
      showNotice(`已选择远控目标：${host.name || host.id}`);
    }
    if (action === "delete") deleteHost(hostId);
    if (action === "history-metrics") loadHostHistory(hostId, "metrics");
    if (action === "history-audit") loadHostHistory(hostId, "audit");
    if (action === "history-commands") loadHostHistory(hostId, "commands");
    if (action === "history-logs") loadHostHistory(hostId, "logs");
    if (action === "history-alerts") loadHostHistory(hostId, "alerts");
  });
  els.upgradeBtn.addEventListener("click", submitUpgrade);
  els.tokenBtn.addEventListener("click", openTokenDialog);
  els.cancelTokenBtn.addEventListener("click", closeTokenDialog);
  els.saveTokenBtn.addEventListener("click", saveToken);
  els.clearTokenBtn.addEventListener("click", clearToken);
  els.actorIdentity.addEventListener("change", saveActorIdentity);
  els.copyRecordsBtn.addEventListener("click", copyOperationRecords);
  els.exportRecordsBtn.addEventListener("click", exportOperationRecords);
  els.clearRecordsBtn.addEventListener("click", clearOperationRecords);
  els.tokenDialog.addEventListener("click", (event) => {
    if (event.target === els.tokenDialog) closeTokenDialog();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeTokenDialog();
  });
  bindNavigation();
  bindValidation();
  renderOperationRecords();
  refreshAll();
  window.setInterval(refreshAll, 30000);
}

init();
