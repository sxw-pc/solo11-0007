"use strict";
const state = { jobId: "", timer: null, polling: false, rules: [], findings: [], toastTimer: null };
const $ = (id) => document.getElementById(id);
const SEVERITY_LABEL = { high: "高风险", medium: "中风险", low: "低风险" };
const CATEGORY_LABEL = {
  hardcoded_credential: "硬编码凭据",
  weak_security: "弱安全配置",
  sensitive_info: "敏感信息泄露",
};
async function api(url, options = {}) {
  const response = await fetch(url, options);
  let payload = null;
  try { payload = await response.json(); }
  catch (error) { throw new Error(`服务返回了无法解析的响应 (${response.status})`); }
  if (!response.ok) {
    throw new Error(payload && payload.error ? payload.error : `请求失败 (${response.status})`);
  }
  return payload;
}
function toast(message, isError = false) {
  const node = $("toast");
  node.textContent = message;
  node.className = isError ? "toast error" : "toast";
  node.hidden = false;
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => { node.hidden = true; }, 4200);
}
function setBusy(busy) {
  $("scanBtn").disabled = busy;
  $("scanBtn").textContent = busy ? "检测中…" : "开始检测";
}
function setExportEnabled(enabled) {
  ["downloadFullJson", "downloadFullCsv", "exportJson", "exportCsv"].forEach((id) => { $(id).disabled = !enabled; });
}
function currentFilters() {
  const params = new URLSearchParams();
  const values = {
    severity: $("filterSeverity").value,
    category: $("filterCategory").value,
    rule_id: $("filterRule").value,
    path: $("filterPath").value.trim(),
  };
  Object.entries(values).forEach(([key, value]) => { if (value) params.set(key, value); });
  return params;
}
function renderStats(stats) {
  if (!stats) return;
  $("summarySection").hidden = false;
  $("statTotal").textContent = stats.total_files;
  $("statScanned").textContent = `已扫描 ${stats.scanned_files} 个目标`;
  $("statHigh").textContent = stats.high;
  $("statMedium").textContent = stats.medium;
  $("statLow").textContent = stats.low;
  $("statSkipped").textContent = stats.skipped_files;
  $("statRules").textContent = `已加载 ${stats.rules_loaded} 条规则`;
}
function makeCell(text, className = "") {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  cell.textContent = text; return cell;
}
function renderFindings(findings) {
  const body = $("resultsBody");
  body.replaceChildren();
  $("emptyResults").hidden = findings.length > 0;
  findings.forEach((finding) => {
    const row = document.createElement("tr");
    row.tabIndex = 0;
    row.setAttribute("role", "button");
    row.addEventListener("click", () => showDetail(finding));
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") showDetail(finding);
    });
    const severityCell = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `risk-badge ${finding.severity}`;
    badge.textContent = SEVERITY_LABEL[finding.severity] || finding.severity;
    severityCell.appendChild(badge);
    const fileCell = document.createElement("td");
    fileCell.className = "file-cell";
    fileCell.textContent = finding.file_path;
    const line = document.createElement("small");
    line.textContent = `第 ${finding.line} 行`;
    fileCell.appendChild(line);
    row.append(
      severityCell,
      makeCell(finding.rule_id, "rule-code"),
      fileCell,
      makeCell(finding.matched_masked, "masked-cell"),
      makeCell(finding.description, "desc-cell"),
      makeCell(`×${finding.occurrences}`, "rule-code"),
    );
    body.appendChild(row);
  });
}
function renderSkipped(skipped) {
  const list = $("skippedList");
  list.replaceChildren();
  $("skippedCount").textContent = `(${skipped.length})`; $("skippedPanel").hidden = skipped.length === 0;
  skipped.forEach((item) => {
    const row = document.createElement("li");
    const code = document.createElement("code");
    code.textContent = item.file_path;
    const reason = document.createElement("span");
    reason.textContent = item.reason;
    row.append(code, reason);
    list.appendChild(row);
  });
}
function appendDetail(label, value, asCode = false) {
  const term = document.createElement("dt");
  term.textContent = label;
  const description = document.createElement("dd");
  if (asCode) {
    const code = document.createElement("code");
    code.textContent = value;
    description.appendChild(code);
  } else {
    description.textContent = value;
  }
  $("detailBody").append(term, description);
}
function showDetail(finding) {
  $("detailTitle").textContent = finding.rule_name || finding.rule_id;
  $("detailBody").replaceChildren();
  appendDetail("风险等级", SEVERITY_LABEL[finding.severity] || finding.severity);
  appendDetail("规则 ID", finding.rule_id, true);
  appendDetail("风险类别", CATEGORY_LABEL[finding.category] || finding.category);
  appendDetail("文件路径", finding.file_path, true);
  appendDetail("匹配行号", (finding.line_numbers || [finding.line]).join(", "));
  appendDetail("掩码片段", finding.matched_masked, true);
  appendDetail("出现次数", String(finding.occurrences));
  appendDetail("风险描述", finding.description);
  appendDetail("修复建议", finding.remediation);
  $("detailDialog").showModal();
}
async function loadRules() {
  try {
    const data = await api("/api/rules");
    state.rules = data.rules;
    $("ruleSummary").textContent = `${data.count} 条`;
    const select = $("filterRule");
    const list = $("ruleList");
    list.replaceChildren();
    data.rules.forEach((rule) => {
      const option = document.createElement("option");
      option.value = rule.id;
      option.textContent = `${rule.id} · ${rule.name}`;
      select.appendChild(option);
      const chip = document.createElement("span");
      chip.className = "rule-chip";
      chip.textContent = `${rule.id} ${rule.severity}`;
      chip.title = rule.description;
      list.appendChild(chip);
    });
    if (data.errors && data.errors.length) {
      toast(`有 ${data.errors.length} 条自定义规则未加载，请检查规则格式`, true);
    }
  } catch (error) {
    toast(`规则加载失败：${error.message}`, true);
  }
}
function updateProgress(job) {
  const percent = Math.max(0, Math.min(100, Number(job.progress) || 0));
  $("progressCard").hidden = false;
  $("progressPercent").textContent = `${percent}%`;
  $("progressBar").style.width = `${percent}%`;
  $("progressMessage").textContent = job.message || "";
  $("progressTitle").textContent = job.status === "completed" ? "检测完成"
    : job.status === "failed" ? "检测失败" : "正在执行静态检测";
  $("progressCard").querySelector(".progress-track").setAttribute("aria-valuenow", String(percent));
}
async function fetchResults() {
  if (!state.jobId) return;
  const params = currentFilters();
  params.set("job_id", state.jobId);
  const data = await api(`/api/results?${params.toString()}`);
  state.findings = data.findings;
  renderFindings(data.findings);
  renderSkipped(data.skipped || []);
}
async function pollJob() {
  if (!state.jobId || state.polling) return;
  state.polling = true;
  try {
    const job = await api(`/api/progress?job_id=${encodeURIComponent(state.jobId)}`);
    updateProgress(job);
    if (job.status === "completed") {
      clearInterval(state.timer);
      state.timer = null;
      setBusy(false);
      setExportEnabled(true);
      renderStats(job.statistics);
      await fetchResults();
      $("resultsPanel").hidden = false;
      toast(job.message);
    } else if (job.status === "failed") {
      clearInterval(state.timer);
      state.timer = null;
      setBusy(false);
      toast(job.error || "检测失败", true);
    }
  } catch (error) {
    clearInterval(state.timer);
    state.timer = null;
    setBusy(false);
    toast(error.message, true);
  } finally {
    state.polling = false;
  }
}
async function startScan(event) {
  event.preventDefault();
  const path = $("scanPath").value.trim();
  if (!path) {
    toast("请输入本地文件或目录路径", true);
    return;
  }
  clearInterval(state.timer);
  state.timer = null;
  state.jobId = "";
  state.findings = [];
  setBusy(true);
  setExportEnabled(false);
  $("resultsPanel").hidden = true;
  $("summarySection").hidden = true;
  $("skippedPanel").hidden = true;
  $("progressCard").hidden = false;
  updateProgress({ progress: 1, message: "正在提交检测任务…", status: "queued" });
  try {
    const job = await api("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path }),
    });
    state.jobId = job.job_id;
    updateProgress(job);
    state.timer = setInterval(pollJob, 400);
  } catch (error) {
    setBusy(false);
    toast(error.message, true);
  }
}
function downloadReport(format, filtered) {
  if (!state.jobId) {
    toast("请先完成一次检测", true);
    return;
  }
  let url = `/api/download?job_id=${encodeURIComponent(state.jobId)}&format=${format}`;
  if (filtered) {
    const params = currentFilters();
    params.set("job_id", state.jobId);
    params.set("format", format);
    url = `/api/export?${params.toString()}`;
  }
  const link = document.createElement("a");
  link.href = url;
  link.download = "";
  document.body.appendChild(link);
  link.click();
  link.remove();
}
async function applyFilters() {
  if (!state.jobId) return;
  try { await fetchResults(); $("resultsPanel").hidden = false; }
  catch (error) { toast(error.message, true); }
}
function resetFilters() {
  $("filterSeverity").value = ""; $("filterCategory").value = "";
  $("filterRule").value = ""; $("filterPath").value = "";
  applyFilters();
}
function bindEvents() {
  $("scanForm").addEventListener("submit", startScan);
  $("applyFilters").addEventListener("click", applyFilters);
  $("resetFilters").addEventListener("click", resetFilters);
  $("filterPath").addEventListener("keydown", (event) => {
    if (event.key === "Enter") applyFilters();
  });
  $("downloadFullJson").addEventListener("click", () => downloadReport("json", false));
  $("downloadFullCsv").addEventListener("click", () => downloadReport("csv", false));
  $("exportJson").addEventListener("click", () => downloadReport("json", true));
  $("exportCsv").addEventListener("click", () => downloadReport("csv", true));
  document.querySelectorAll("[data-path]").forEach((button) => {
    button.addEventListener("click", () => {
      $("scanPath").value = button.dataset.path;
      $("scanPath").focus();
    });
  });
  $("detailDialog").addEventListener("click", (event) => {
    if (event.target === $("detailDialog")) $("detailDialog").close();
  });
}
document.addEventListener("DOMContentLoaded", () => {
  bindEvents(); setExportEnabled(false); loadRules();
});
