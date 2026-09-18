const state = {
  token: localStorage.getItem("af.managerToken") || "",
  lastConfigText: "",
  lastBatchesText: "",
  hosts: [],
  operationRecords: parseJson(localStorage.getItem("af.operationRecords") || "[]", []),
  actorIdentity: localStorage.getItem("af.actorIdentity") || "本地控制台用户",
  autoRefresh: localStorage.getItem("af.autoRefresh") !== "false",
  refreshInFlight: false,
  liveRefreshInFlight: false,
  lastRenderedHostsKey: "",
  currentUser: localStorage.getItem("af.currentUser") || "",
};

const $ = (id) => document.getElementById(id);

const els = {
  loginView: $("loginView"),
  appShell: $("appShell"),
  loginForm: $("loginForm"),
  loginUsername: $("loginUsername"),
  loginPassword: $("loginPassword"),
  loginMessage: $("loginMessage"),
  loginSubmitBtn: $("loginSubmitBtn"),
  endpointText: $("endpointText"),
  autoRefreshToggle: $("autoRefreshToggle"),
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
  hostSearch: $("hostSearch"),
  hostStatusFilter: $("hostStatusFilter"),
  hostHistoryTitle: $("hostHistoryTitle"),
  hostHistoryOutput: $("hostHistoryOutput"),
  refreshCollectorBtn: $("refreshCollectorBtn"),
  collectorHostSelect: $("collectorHostSelect"),
  collectorToggleList: $("collectorToggleList"),
  loadViolationRulesBtn: $("loadViolationRulesBtn"),
  saveViolationRulesBtn: $("saveViolationRulesBtn"),
  pushRulesAllBtn: $("pushRulesAllBtn"),
  pushRulesHostBtn: $("pushRulesHostBtn"),
  violationRulesEditor: $("violationRulesEditor"),
  rulesPushNote: $("rulesPushNote"),
  refreshSecurityBtn: $("refreshSecurityBtn"),
  securitySummary: $("securitySummary"),
  alertList: $("alertList"),
  operationLogList: $("operationLogList"),
  analyticsLogCount: $("analyticsLogCount"),
  analyticsAlertCount: $("analyticsAlertCount"),
  operationTypeBreakdown: $("operationTypeBreakdown"),
  alertSeverityBreakdown: $("alertSeverityBreakdown"),
  logCollectorFilter: $("logCollectorFilter"),
  logPriorityFilter: $("logPriorityFilter"),
  refreshLogPolicyBtn: $("refreshLogPolicyBtn"),
  logPolicySummary: $("logPolicySummary"),
  logPolicyHost: $("logPolicyHost"),
  logPolicyQueryBtn: $("logPolicyQueryBtn"),
  collectorCounts: $("collectorCounts"),
  collectorCountsDetail: $("collectorCountsDetail"),
  latencyHighAvg: $("latencyHighAvg"),
  latencyHighCount: $("latencyHighCount"),
  latencyNormalAvg: $("latencyNormalAvg"),
  latencyNormalCount: $("latencyNormalCount"),
  latencyRatio: $("latencyRatio"),
  latencyTarget: $("latencyTarget"),
  latencyP95: $("latencyP95"),
  filterProfileRows: $("filterProfileRows"),
  addFilterProfileBtn: $("addFilterProfileBtn"),
  saveFilterProfilesBtn: $("saveFilterProfilesBtn"),
  filterProfileMsg: $("filterProfileMsg"),
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
  loginUsername: { label: "账号", required: true, min: 2, max: 64, pattern: /^[A-Za-z0-9_.@-]+$/, message: "账号只能包含字母、数字、点、下划线、短横线或 @。" },
  loginPassword: { label: "密码", required: true, min: 6, max: 128 },
};

function authHeaders(extra = {}) {
  const headers = { ...extra };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  return headers;
}

function showLogin(message = "") {
  if (els.loginView) els.loginView.classList.remove("hidden");
  if (els.appShell) els.appShell.classList.add("hidden");
  if (message && els.loginMessage) {
    els.loginMessage.textContent = message;
    els.loginMessage.className = "login-message";
  }
}

function showApp() {
  if (els.loginView) els.loginView.classList.add("hidden");
  if (els.appShell) els.appShell.classList.remove("hidden");
}

async function sha256Hex(text) {
  if (!window.crypto?.subtle) {
    throw new Error("当前浏览器不支持 Web Crypto，无法安全处理密码。");
  }
  const bytes = new TextEncoder().encode(text);
  const digest = await window.crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((item) => item.toString(16).padStart(2, "0")).join("");
}

function setLoginMessage(message, type = "error") {
  if (!els.loginMessage) return;
  els.loginMessage.textContent = message;
  els.loginMessage.className = `login-message ${type === "success" ? "success" : ""}`;
}

async function login(event) {
  event.preventDefault();
  const errors = validateFields(["loginUsername", "loginPassword"]);
  if (errors.length) {
    setLoginMessage(errors[0]);
    return;
  }
  const stopLoading = setLoading(els.loginSubmitBtn, "登录中...");
  try {
    const username = els.loginUsername.value.trim();
    const passwordSha256 = await sha256Hex(els.loginPassword.value);
    const response = await fetch("/auth/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password_sha256: passwordSha256 }),
    });
    const text = await response.text();
    const data = parseJson(text, {});
    if (!response.ok) {
      throw new Error(data.message || "账号或密码不正确。");
    }
    state.token = data.token || "";
    state.currentUser = data.username || username;
    localStorage.setItem("af.managerToken", state.token);
    localStorage.setItem("af.currentUser", state.currentUser);
    els.loginPassword.value = "";
    setLoginMessage("登录成功，正在进入控制台。", "success");
    showApp();
    refreshAll({ record: false });
  } catch (err) {
    setLoginMessage(err.message || "账号或密码不正确。");
  } finally {
    stopLoading();
  }
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
  showNotice(`结构化操作记录已清空，共移除 ${removed} 条。`);
}

function setLoading(button, loadingText) {
  if (!button) return () => {};
  const original = button.textContent;
  button.disabled = true;
  button.textContent = loadingText;
  return () => {
    button.disabled = false;
    button.textContent = original;
  };
}

async function request(path, options = {}) {
  const timeoutMs = options.timeoutMs || 10000;
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(path, {
      ...options,
      signal: controller.signal,
      credentials: "same-origin",
      headers: authHeaders(options.headers || {}),
    }).catch((err) => {
      if (err.name === "AbortError") throw new Error(`接口请求超时：${path}`);
      throw err;
    });
    const text = await response.text();
    if (!response.ok) {
      const data = parseJson(text, null);
      if (data && Array.isArray(data.validation_errors)) {
        throw new Error(data.validation_errors.map((item) => `${item.field}: ${item.message}`).join("；"));
      }
      if (response.status === 401) {
        state.token = "";
        localStorage.removeItem("af.managerToken");
        showLogin("登录已失效，请重新输入账号和密码。");
      }
      const message = response.status === 401
        ? "接口未授权，请重新登录。"
        : `接口请求失败：HTTP ${response.status}`;
      throw new Error(`${message}${text ? ` ${text}` : ""}`);
    }
    return text;
  } finally {
    window.clearTimeout(timer);
  }
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

function debounce(fn, delay = 180) {
  let timer = 0;
  return (...args) => {
    window.clearTimeout(timer);
    timer = window.setTimeout(() => fn(...args), delay);
  };
}

function filteredHosts(hosts) {
  const keyword = String(els.hostSearch?.value || "").trim().toLowerCase();
  const status = els.hostStatusFilter?.value || "all";
  return hosts.filter((host) => {
    if (status === "online" && !host.online) return false;
    if (status === "offline" && host.online) return false;
    if (!keyword) return true;
    const haystack = [
      host.id,
      host.name,
      host.ip_address,
      host.os_version,
      host.hardware,
      host.network_status,
      host.note,
      ...(host.permissions || []),
    ].filter(Boolean).join(" ").toLowerCase();
    return haystack.includes(keyword);
  });
}

function renderHosts(data) {
  const hosts = Array.isArray(data.hosts) ? data.hosts : state.hosts;
  if (Array.isArray(data.hosts)) state.hosts = hosts;
  const visibleHosts = filteredHosts(hosts);
  const onlineCount = hosts.filter((host) => host.online).length;
  els.hostCount.textContent = visibleHosts.length === hosts.length
    ? `${hosts.length} 台主机，${onlineCount} 台在线`
    : `显示 ${visibleHosts.length} / ${hosts.length} 台主机，${onlineCount} 台在线`;
  const renderKey = JSON.stringify({
    hosts: visibleHosts,
    keyword: els.hostSearch?.value || "",
    status: els.hostStatusFilter?.value || "all",
  });
  if (renderKey === state.lastRenderedHostsKey) return;
  state.lastRenderedHostsKey = renderKey;
  refreshCollectorHostSelect();
  if (hosts.length === 0) {
    els.hostList.innerHTML = `
      <div class="empty-state">
        <strong>暂无主机信息</strong>
        <p>请先添加主机，或让远端代理通过 <code>/hosts/heartbeat</code> 上报心跳。</p>
      </div>
    `;
    return;
  }
  if (visibleHosts.length === 0) {
    els.hostList.innerHTML = `
      <div class="empty-state">
        <strong>没有匹配的主机</strong>
        <p>请调整搜索关键字或在线状态筛选条件。</p>
      </div>
    `;
    return;
  }
  els.hostList.innerHTML = visibleHosts.map((host) => `
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

// ---- 采集器控制 ----
const COLLECTOR_LABELS = {
  file_win: "文件采集(Win)", process_win: "进程采集(Win)", network_win: "网络采集(Win)",
  command_win: "命令行采集(Win)", registry_win: "注册表采集(Win)", etw_win: "ETW 安全日志(Win)",
  file_linux: "文件采集(Linux)", process_linux: "进程采集(Linux)", network_linux: "网络采集(Linux)",
  command_linux: "命令行采集(Linux)", audit_linux: "auditd 原生审计(Linux)", unknown: "未知采集器",
};

function collectorLabel(name) {
  return COLLECTOR_LABELS[name] || name;
}

// 用最近一次主机列表刷新“目标主机”下拉框，尽量保留已选项。
function refreshCollectorHostSelect() {
  if (!els.collectorHostSelect) return;
  const keep = els.collectorHostSelect.value;
  const hosts = Array.isArray(state.hosts) ? state.hosts : [];
  els.collectorHostSelect.innerHTML =
    `<option value="">-- 请选择主机 --</option>` +
    hosts.map((h) => {
      const flag = h.online === false ? "（离线）" : "";
      return `<option value="${escapeHtml(h.id)}">${escapeHtml(h.name || h.id)}${flag}</option>`;
    }).join("");
  if (keep && hosts.some((h) => h.id === keep)) els.collectorHostSelect.value = keep;
  renderCollectorToggles();
}

function renderCollectorToggles() {
  if (!els.collectorToggleList) return;
  const hostId = els.collectorHostSelect.value;
  if (!hostId) {
    els.collectorToggleList.innerHTML =
      '<div class="empty-state"><strong>请选择在线主机</strong><p>主机心跳会携带各采集器的运行状态。</p></div>';
    return;
  }
  const host = (state.hosts || []).find((h) => h.id === hostId);
  const collectors = host && Array.isArray(host.collectors) ? host.collectors : [];
  if (!collectors.length) {
    els.collectorToggleList.innerHTML =
      '<div class="empty-state"><strong>暂无采集器心跳状态</strong>'
      + '<p>该主机尚未上报采集器状态（旧版客户端或从未心跳）。请升级客户端后点击“刷新主机状态”。</p></div>';
    return;
  }
  els.collectorToggleList.innerHTML = collectors.map((c) => {
    const on = !!c.running;
    return `
      <div class="collector-row">
        <div>
          <strong>${escapeHtml(collectorLabel(c.name))}</strong>
          <code>${escapeHtml(c.name)}</code>
        </div>
        <label class="switch">
          <input type="checkbox" data-collector-name="${escapeHtml(c.name)}" data-host-id="${escapeHtml(host.id)}" ${on ? "checked" : ""}>
          <span class="slider"></span>
          <span class="switch-state">${on ? "运行中" : "已停止"}</span>
        </label>
      </div>`;
  }).join("");
}

// 下发单个采集器开关（set_collector 远程命令）。
async function sendCollectorToggle(hostId, name, enabled) {
  const payload = JSON.stringify({ name, enabled });
  try {
    const text = await request("/remote/control", {
      method: "POST",
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: JSON.stringify({ target_host_id: hostId, command_type: "set_collector", payload }),
    });
    const data = parseJson(text, {});
    showNotice(`采集器 ${collectorLabel(name)} 已${enabled ? "开启" : "关闭"}指令已入队（${data.command_id || "已接受"}），约 10 秒内生效。`);
    recordOperation({
      object: hostId, type: "set_collector",
      details: `采集器=${name}，期望状态=${enabled ? "运行" : "停止"}`,
      status: "success",
    });
  } catch (err) {
    showNotice(err.message, "error");
    recordOperation({ object: hostId, type: "set_collector", details: `采集器=${name} 下发失败`, status: "failure", error: err });
    throw err;
  }
}

async function loadViolationRules() {
  try {
    const text = await request("/violation/rules");
    els.violationRulesEditor.value = text;
    showNotice("已加载服务端当前违规规则。");
  } catch (err) {
    showNotice(err.message, "error");
  }
}

async function saveViolationRules() {
  let body = els.violationRulesEditor.value.trim();
  if (!body) return showNotice("规则内容为空，未保存。", "error");
  try {
    parseJson(body);  // 校验 JSON 合法性
  } catch {
    return showNotice("规则不是合法 JSON，无法保存。", "error");
  }
  try {
    await request("/violation/rules", {
      method: "PUT",
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body,
    });
    showNotice("违规规则已保存为服务端单一策略。");
    recordOperation({ object: "violation_rules.json", type: "violation_rules_save", details: "保存违规规则", status: "success" });
  } catch (err) {
    showNotice(err.message, "error");
  }
}

// 统一下发规则：target 为空表示全部主机。
async function pushViolationRules(hostId) {
  const scope = hostId ? `主机 ${hostId}` : "全部已注册主机";
  const done = setLoading(els.pushRulesAllBtn, "下发中...");
  const doneHost = setLoading(els.pushRulesHostBtn, "下发中...");
  try {
    const text = await request("/violation/rules/push", {
      method: "POST",
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: JSON.stringify(hostId ? { host_id: hostId } : {}),
    });
    const data = parseJson(text, {});
    showNotice(`违规规则已通过 load_rules 热加载下发到${scope}：${data.queued_count ?? 0} 台主机已入队。`);
    recordOperation({
      object: hostId || "*", type: "load_rules_push",
      details: `违规规则热加载下发到${scope}，入队 ${data.queued_count ?? 0} 台`,
      status: "success",
    });
  } catch (err) {
    showNotice(err.message, "error");
    recordOperation({ object: hostId || "*", type: "load_rules_push", details: `下发到${scope}失败`, status: "failure", error: err });
  } finally {
    done();
    doneHost();
  }
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

function logQueryParams(limit = 20) {
  const params = new URLSearchParams({ limit: String(limit) });
  const collector = els.logCollectorFilter ? els.logCollectorFilter.value : "";
  const priority = els.logPriorityFilter ? els.logPriorityFilter.value : "";
  if (collector) params.set("collector", collector);
  if (priority) params.set("priority", priority);
  return params.toString();
}

async function loadSecurityMonitor(options = {}) {
  if (!els.alertList || !els.operationLogList) return;
  try {
    const [alertsText, logsText, analyticsText] = await Promise.all([
      request("/alerts?limit=20"),
      request(`/logs/query?${logQueryParams(20)}`),
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
    if (!options.silent) showNotice(err.message, "error");
  }
}

function renderCollectorCounts(data) {
  const totals = data.collector_totals || {};
  const entries = Object.entries(totals).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) {
    els.collectorCounts.innerHTML = `<span class="muted">暂无已存储日志</span>`;
  } else {
    const grandTotal = entries.reduce((sum, [, n]) => sum + n, 0);
    els.collectorCounts.innerHTML = entries.map(([collector, n]) => {
      const pct = grandTotal > 0 ? Math.round((n / grandTotal) * 1000) / 10 : 0;
      const tag = collector === "etw_win"
        ? '<span class="severity warning">ETW 安全日志</span>'
        : collector === "legacy"
          ? '<span class="severity info">旧日志迁移</span>'
          : "";
      return `<span><code>${escapeHtml(collector)}</code> ${tag}<em>${formatNumber(n)} 条 · ${pct}%</em></span>`;
    }).join("");
  }
  const hosts = data.hosts || {};
  const hostNames = Object.keys(hosts);
  els.collectorCountsDetail.textContent = hostNames.length === 0
    ? "暂无按主机明细"
    : JSON.stringify({ total: data.total || 0, hosts }, null, 2);
}

function formatLatencyMs(value) {
  if (value === undefined || value === null || Number.isNaN(Number(value))) return "--";
  return `${Number(value).toFixed(0)} ms`;
}

function renderTransferLatency(data) {
  const hi = data.high || {};
  const nm = data.normal || {};
  els.latencyHighAvg.textContent = formatLatencyMs(hi.avg_ms);
  els.latencyNormalAvg.textContent = formatLatencyMs(nm.avg_ms);
  els.latencyHighCount.textContent = `${formatNumber(hi.count || 0)} 条样本`;
  els.latencyNormalCount.textContent = `${formatNumber(nm.count || 0)} 条样本`;
  els.latencyP95.textContent = `${formatLatencyMs(hi.p95_ms)} / ${formatLatencyMs(nm.p95_ms)}`;
  const ratio = Number(data.avg_latency_ratio);
  if (!ratio || Number.isNaN(ratio)) {
    els.latencyRatio.textContent = "--";
    els.latencyTarget.textContent = "样本不足";
  } else {
    els.latencyRatio.textContent = ratio.toFixed(2);
    const met = Boolean(data.target_met);
    els.latencyTarget.textContent = met ? "达标（≤ 0.5）" : `未达标（目标 ≤ ${data.target_ratio_le || 0.5}）`;
    els.latencyTarget.className = met ? "latency-ok" : "latency-bad";
  }
}

function filterProfileRow(profile = {}) {
  const collector = profile.collector || "";
  const mode = profile.mode === "lenient" ? "lenient" : "strict";
  const maxLen = Number.isFinite(Number(profile.message_max_len)) ? Number(profile.message_max_len) : 512;
  const retention = Number.isFinite(Number(profile.retention_lines)) ? Number(profile.retention_lines) : 50000;
  const drops = Array.isArray(profile.drop_fields) ? profile.drop_fields.join(", ") : "";
  const note = profile.note ? escapeHtml(profile.note) : "";
  return `
    <tr class="filter-profile-row">
      <td><input class="profile-collector" type="text" value="${escapeHtml(collector)}" placeholder="如 process_win / default" style="width:11rem"></td>
      <td>
        <select class="profile-mode">
          <option value="strict"${mode === "strict" ? " selected" : ""}>strict 严格</option>
          <option value="lenient"${mode === "lenient" ? " selected" : ""}>lenient 宽松</option>
        </select>
      </td>
      <td><input class="profile-maxlen" type="number" min="64" max="1048576" value="${maxLen}" style="width:7rem"></td>
      <td><input class="profile-retention" type="number" min="100" max="5000000" value="${retention}" style="width:8rem"></td>
      <td><input class="profile-dropfields" type="text" value="${escapeHtml(drops)}" placeholder="raw_xml, raw_payload" style="width:13rem"></td>
      <td><button type="button" class="button danger small profile-remove">删除</button></td>
    </tr>
    ${note ? `<tr><td colspan="6" class="muted profile-note-row">${note}</td></tr>` : ""}`;
}

function renderFilterProfiles(profiles) {
  const rows = Array.isArray(profiles) ? profiles : [];
  els.filterProfileRows.innerHTML = rows.map(filterProfileRow).join("") || filterProfileRow({ mode: "strict" });
}

function collectFilterProfiles() {
  const profiles = [];
  const seen = new Set();
  const blocks = els.filterProfileRows.querySelectorAll(".filter-profile-row");
  blocks.forEach((row) => {
    const collector = row.querySelector(".profile-collector").value.trim();
    const mode = row.querySelector(".profile-mode").value;
    const messageMaxLen = Number(row.querySelector(".profile-maxlen").value);
    const retentionLines = Number(row.querySelector(".profile-retention").value);
    const dropFields = row.querySelector(".profile-dropfields").value
      .split(",").map((s) => s.trim()).filter(Boolean);
    if (!collector) return;
    if (!/^[a-z0-9_]{2,32}$/.test(collector)) {
      throw new Error(`采集器 ID 不合法：${collector}（仅允许小写字母、数字、下划线，2-32 位）`);
    }
    if (seen.has(collector)) throw new Error(`采集器 ID 重复：${collector}`);
    seen.add(collector);
    if (!Number.isFinite(messageMaxLen) || messageMaxLen < 64) {
      throw new Error(`${collector} 的消息最大长度必须 ≥ 64`);
    }
    if (!Number.isFinite(retentionLines) || retentionLines < 100) {
      throw new Error(`${collector} 的保留行数必须 ≥ 100`);
    }
    profiles.push({
      collector,
      mode,
      message_max_len: Math.round(messageMaxLen),
      drop_fields: dropFields,
      retention_lines: Math.round(retentionLines),
    });
  });
  if (profiles.length === 0) throw new Error("至少保留一条过滤策略");
  if (!seen.has("default")) throw new Error("必须保留 collector=default 的兜底策略");
  return profiles;
}

async function saveFilterProfiles() {
  let profiles;
  try {
    profiles = collectFilterProfiles();
  } catch (err) {
    els.filterProfileMsg.textContent = err.message;
    showNotice(err.message, "error");
    return;
  }
  const done = setLoading(els.saveFilterProfilesBtn, "保存中...");
  try {
    const text = await request("/log-filter/profiles", {
      method: "PUT",
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: JSON.stringify({ profiles }),
    });
    const result = parseJson(text, {});
    els.filterProfileMsg.textContent = result.saved ? "已保存，新日志立即按新策略过滤" : "已提交";
    showNotice("日志过滤策略已保存。");
  } catch (err) {
    els.filterProfileMsg.textContent = err.message;
    showNotice(err.message, "error");
  } finally {
    done();
  }
}

async function loadLogPolicy(options = {}) {
  if (!els.filterProfileRows) return;
  const silent = Boolean(options && options.silent);
  const skipProfiles = Boolean(options && options.skipProfiles);
  const host = els.logPolicyHost.value.trim();
  const qs = host ? `?host_id=${encodeURIComponent(host)}` : "";
  try {
    const tasks = [
      request(`/logs/collector-counts${qs}`),
      request(`/stats/transfer-latency${qs}${qs ? "&" : "?"}limit=5000`),
    ];
    if (!skipProfiles) tasks.push(request("/log-filter/profiles"));
    const [countsText, latencyText, profilesText] = await Promise.all(tasks);
    renderCollectorCounts(parseJson(countsText, { collector_totals: {}, hosts: {} }));
    renderTransferLatency(parseJson(latencyText, {}));
    if (!skipProfiles) renderFilterProfiles(parseJson(profilesText, { profiles: [] }).profiles);
    els.logPolicySummary.textContent = host ? `主机 ${host} 的统计` : "全部主机汇总";
  } catch (err) {
    els.logPolicySummary.textContent = "加载失败";
    if (!silent) showNotice(err.message, "error");
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
  const label = host?.name || hostId;
  if (!window.confirm(`确认删除主机“${label}”吗？该操作会从监管列表移除该主机信息。`)) return;
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

async function refreshAll(options = {}) {
  if (!state.token) {
    showLogin();
    return;
  }
  if (state.refreshInFlight) return;
  state.refreshInFlight = true;
  const record = options.record !== false;
  const silent = Boolean(options.silent);
  const done = silent ? () => {} : setLoading(els.refreshBtn, "刷新中...");
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
    await loadSecurityMonitor({ silent });
    await loadLogPolicy({ silent });
    if (!silent) showNotice("数据已刷新。");
    if (record) {
      recordOperation({
        object: "管理控制台数据",
        type: "refresh_dashboard",
        details: "刷新运行状态、配置快照、证据批次和主机列表",
        status: "success",
      });
    }
  } catch (err) {
    els.statusPill.textContent = "异常";
    els.statusPill.className = "pill error";
    if (!silent) showNotice(err.message, "error");
    if (record) {
      recordOperation({
        object: "管理控制台数据",
        type: "refresh_dashboard",
        details: "刷新运行状态、配置快照、证据批次和主机列表失败",
        status: "failure",
        error: err,
      });
    }
  } finally {
    state.refreshInFlight = false;
    done();
  }
}

async function refreshLiveData() {
  if (!state.token || !state.autoRefresh || state.liveRefreshInFlight || document.hidden) return;
  state.liveRefreshInFlight = true;
  try {
    const [statusText, hostsText] = await Promise.all([
      request("/status", { timeoutMs: 8000 }),
      request("/hosts", { timeoutMs: 8000 }),
    ]);
    renderStatus(parseJson(statusText, {}));
    renderHosts(parseJson(hostsText, { hosts: [] }));
    await loadSecurityMonitor({ silent: true });
    await loadLogPolicy({ silent: true, skipProfiles: true });
  } catch (err) {
    els.statusPill.textContent = "连接异常";
    els.statusPill.className = "pill error";
    els.lastUpdated.textContent = `刷新失败：${err.message}`;
  } finally {
    state.liveRefreshInFlight = false;
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
  if (state.token) showApp();
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
  closeTokenDialog();
  showLogin("Token 已清除，请重新登录。");
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
  const byHash = new Map(links.map((link) => [link.getAttribute("href"), link]));
  const activate = (hash) => {
    links.forEach((item) => item.classList.toggle("active", item.getAttribute("href") === hash));
  };
  links.forEach((link) => {
    link.addEventListener("click", () => {
      activate(link.getAttribute("href"));
    });
  });
  if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver((entries) => {
      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
      if (visible) activate(`#${visible.target.id}`);
    }, { rootMargin: "-20% 0px -65% 0px", threshold: [0.1, 0.35, 0.65] });
    byHash.forEach((_, hash) => {
      const section = document.querySelector(hash);
      if (section) observer.observe(section);
    });
  }
}

function init() {
  els.endpointText.textContent = window.location.host || "本机服务";
  els.actorIdentity.value = state.actorIdentity;
  if (els.loginForm) {
    els.loginForm.addEventListener("submit", login);
    els.loginForm.addEventListener("reset", () => {
      window.setTimeout(() => {
        if (els.loginMessage) els.loginMessage.className = "login-message hidden";
      }, 0);
    });
  }
  if (els.autoRefreshToggle) {
    els.autoRefreshToggle.checked = state.autoRefresh;
    els.autoRefreshToggle.addEventListener("change", () => {
      state.autoRefresh = els.autoRefreshToggle.checked;
      localStorage.setItem("af.autoRefresh", String(state.autoRefresh));
      showNotice(state.autoRefresh ? "已开启自动轻量刷新。" : "已暂停自动刷新。");
    });
  }
  els.refreshBtn.addEventListener("click", () => refreshAll());
  if (els.refreshSecurityBtn) els.refreshSecurityBtn.addEventListener("click", () => loadSecurityMonitor());
  if (els.logCollectorFilter) els.logCollectorFilter.addEventListener("change", () => loadSecurityMonitor({ silent: true }));
  if (els.logPriorityFilter) els.logPriorityFilter.addEventListener("change", () => loadSecurityMonitor({ silent: true }));
  if (els.refreshLogPolicyBtn) els.refreshLogPolicyBtn.addEventListener("click", () => loadLogPolicy());
  if (els.logPolicyQueryBtn) els.logPolicyQueryBtn.addEventListener("click", () => loadLogPolicy());
  if (els.logPolicyHost) els.logPolicyHost.addEventListener("keydown", (event) => {
    if (event.key === "Enter") loadLogPolicy();
  });
  if (els.addFilterProfileBtn) els.addFilterProfileBtn.addEventListener("click", () => {
    els.filterProfileRows.insertAdjacentHTML("beforeend", filterProfileRow({ mode: "strict" }));
  });
  if (els.filterProfileRows) els.filterProfileRows.addEventListener("click", (event) => {
    if (!event.target.classList.contains("profile-remove")) return;
    const block = event.target.closest(".filter-profile-row");
    const noteRow = block ? block.nextElementSibling : null;
    if (block) block.remove();
    if (noteRow && noteRow.classList.contains("profile-note-row")) noteRow.remove();
  });
  if (els.saveFilterProfilesBtn) els.saveFilterProfilesBtn.addEventListener("click", saveFilterProfiles);
  els.reloadConfigBtn.addEventListener("click", reloadConfig);
  els.copyConfigBtn.addEventListener("click", copyConfig);
  els.saveHostBtn.addEventListener("click", saveHost);
  els.resetHostFormBtn.addEventListener("click", resetHostForm);
  els.sendRemoteCommandBtn.addEventListener("click", sendRemoteCommand);

  // ---- 采集器控制 ----
  if (els.refreshCollectorBtn) els.refreshCollectorBtn.addEventListener("click", async () => {
    const done = setLoading(els.refreshCollectorBtn, "刷新中...");
    try {
      const text = await request("/hosts", { timeoutMs: 8000 });
      state.lastRenderedHostsKey = "";
      renderHosts(parseJson(text, { hosts: [] }));
      showNotice("已从服务端刷新最新心跳与采集器状态。");
    } catch (err) {
      showNotice(err.message, "error");
    } finally {
      done();
    }
  });
  if (els.collectorHostSelect) els.collectorHostSelect.addEventListener("change", renderCollectorToggles);
  if (els.collectorToggleList) els.collectorToggleList.addEventListener("change", async (event) => {
    const input = event.target.closest('input[type="checkbox"][data-collector-name]');
    if (!input) return;
    const hostId = input.getAttribute("data-host-id");
    const name = input.getAttribute("data-collector-name");
    const enabled = input.checked;
    try {
      await sendCollectorToggle(hostId, name, enabled);
    } catch {
      // 失败回滚 UI 开关
      input.checked = !enabled;
    }
  });
  if (els.loadViolationRulesBtn) els.loadViolationRulesBtn.addEventListener("click", loadViolationRules);
  if (els.saveViolationRulesBtn) els.saveViolationRulesBtn.addEventListener("click", saveViolationRules);
  if (els.pushRulesAllBtn) els.pushRulesAllBtn.addEventListener("click", () => pushViolationRules(""));
  if (els.pushRulesHostBtn) els.pushRulesHostBtn.addEventListener("click", () => {
    const hostId = els.collectorHostSelect ? els.collectorHostSelect.value : "";
    if (!hostId) return showNotice("请先在上方选择目标主机。", "error");
    pushViolationRules(hostId);
  });

  const updateHostFilter = debounce(() => {
    state.lastRenderedHostsKey = "";
    renderHosts({ hosts: state.hosts });
  });
  if (els.hostSearch) els.hostSearch.addEventListener("input", updateHostFilter);
  if (els.hostStatusFilter) els.hostStatusFilter.addEventListener("change", updateHostFilter);
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
  if (state.token) {
    showApp();
    refreshAll({ record: false });
  } else {
    showLogin();
    if (els.loginUsername) els.loginUsername.focus();
  }
  window.setInterval(refreshLiveData, 30000);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && state.token) refreshLiveData();
  });
}

init();
