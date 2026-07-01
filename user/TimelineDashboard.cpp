#include "TimelineDashboard.h"

#include "McpJson.h"

#include "../shared/KnLiveDbgIoctl.h"

#include <sstream>

namespace
{
    void ReplaceAll(std::wstring* value, const std::wstring& from, const std::wstring& to)
    {
        if (value == nullptr || from.empty())
        {
            return;
        }

        size_t offset = 0;
        while ((offset = value->find(from, offset)) != std::wstring::npos)
        {
            value->replace(offset, from.size(), to);
            offset += to.size();
        }
    }

    std::wstring ScriptSafeJson(std::wstring value)
    {
        ReplaceAll(&value, L"</", L"<\\/");
        ReplaceAll(&value, L"<!--", L"<\\!--");
        return value;
    }

    std::wstring TimelineDashboardEventsJson(const std::vector<TimelineEvent>& events)
    {
        std::wstring out = L"[";
        for (size_t i = 0; i < events.size(); ++i)
        {
            if (i != 0)
            {
                out += L",";
            }
            out += TimelineEventToJson(events[i]);
        }
        out += L"]";
        return out;
    }

    std::wstring TimelineDashboardHeaderJson(const TimelineDashboardDocument& document)
    {
        std::wstring out = L"{";
        out += L"\"schema\":\"kn-live-dbg.timeline-dashboard.v1\"";
        out += L",\"generatedUtc\":" + mcpjson::Quote(document.GeneratedUtc);
        out += L",\"displayedEvents\":" + std::to_wstring(document.Events.size());
        out += L",\"totalStored\":" + std::to_wstring(document.TotalStored);
        out += L",\"truncated\":";
        out += document.Truncated ? L"true" : L"false";
        out += L",\"maxEvents\":" + std::to_wstring(document.MaxEvents);
        out += L"}";
        return out;
    }

    std::wstring TimelineDashboardLiveJson(const TimelineDashboardDocument& document)
    {
        std::wstring out = L"{";
        out += L"\"available\":";
        out += document.HasLiveStatus ? L"true" : L"false";
        out += L",\"flags\":" + std::to_wstring(document.LiveFlags);
        out += L",\"active\":";
        out += ((document.LiveFlags & KNDBG_TIMELINE_STATUS_ACTIVE) != 0 ? L"true" : L"false");
        out += L",\"processCallback\":";
        out += ((document.LiveFlags & KNDBG_TIMELINE_STATUS_PROCESS_CALLBACK) != 0 ? L"true" : L"false");
        out += L",\"imageCallback\":";
        out += ((document.LiveFlags & KNDBG_TIMELINE_STATUS_IMAGE_CALLBACK) != 0 ? L"true" : L"false");
        out += L",\"threadCallback\":";
        out += ((document.LiveFlags & KNDBG_TIMELINE_STATUS_THREAD_CALLBACK) != 0 ? L"true" : L"false");
        out += L",\"capacity\":" + std::to_wstring(document.LiveCapacity);
        out += L",\"queued\":" + std::to_wstring(document.LiveQueued);
        out += L",\"dropped\":" + std::to_wstring(document.LiveDropped);
        out += L",\"nextSequence\":" + std::to_wstring(document.LiveNextSequence);
        out += L",\"autoDrainRunning\":";
        out += document.AutoDrainRunning ? L"true" : L"false";
        out += L",\"autoDrainBatches\":" + std::to_wstring(document.AutoDrainBatches);
        out += L",\"autoDrainEvents\":" + std::to_wstring(document.AutoDrainEvents);
        out += L",\"autoDrainAdded\":" + std::to_wstring(document.AutoDrainAdded);
        out += L",\"autoDrainErrors\":" + std::to_wstring(document.AutoDrainErrors);
        out += L",\"autoDrainLastUtc\":" + mcpjson::Quote(document.AutoDrainLastUtc);
        out += L",\"autoDrainLastError\":" + mcpjson::Quote(document.AutoDrainLastError);
        out += L"}";
        return out;
    }
}

std::wstring BuildTimelineDashboardHtml(const TimelineDashboardDocument& document)
{
    std::wstringstream html;

    std::wstring headerJson = ScriptSafeJson(TimelineDashboardHeaderJson(document));
    std::wstring statusJson = ScriptSafeJson(BuildTimelineStatusJson(document.Stats));
    std::wstring liveJson = ScriptSafeJson(TimelineDashboardLiveJson(document));
    std::wstring analysisJson = ScriptSafeJson(BuildTimelineAnalysisJson(document.Analysis));
    std::wstring eventsJson = ScriptSafeJson(TimelineDashboardEventsJson(document.Events));

    html << LR"KNL(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KnLiveDbg Timeline Dashboard</title>
<style>
:root {
  color-scheme: dark;
  --bg: #070b10;
  --chrome: #0a0f15;
  --title: #1f1f22;
  --panel: #0f151d;
  --panel2: #121b25;
  --panel3: #172434;
  --line: #263847;
  --line2: #345064;
  --text: #f1f7ff;
  --muted: #8aa0b4;
  --muted2: #607486;
  --accent: #42c7ff;
  --accent2: #1f9bd0;
  --good: #48d597;
  --warn: #ffbd4a;
  --bad: #ff5b72;
  --mid: #8bc7ff;
  --selected: #143653;
  font-family: Segoe UI, Inter, Arial, sans-serif;
}
* {
  box-sizing: border-box;
}
body {
  margin: 0;
  background: #05080c;
  color: var(--text);
  font-size: 12px;
  overflow: hidden;
}
.app-window {
  min-height: 100vh;
  display: grid;
  grid-template-rows: 32px 44px minmax(0, 1fr) 26px;
  background: var(--bg);
}
.titlebar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 32px;
  padding: 0 10px;
  background: var(--title);
  border-bottom: 1px solid #111;
  color: #e8eef6;
}
.window-brand {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
}
.app-logo {
  display: inline-grid;
  place-items: center;
  width: 16px;
  height: 16px;
  border: 1px solid #245d7d;
  border-radius: 3px;
  color: var(--accent);
  font-weight: 700;
}
.window-actions {
  color: #c9d3df;
  letter-spacing: 8px;
}
.topbar {
  display: grid;
  grid-template-columns: 260px minmax(420px, 1fr) 360px;
  gap: 14px;
  align-items: center;
  padding: 6px 10px;
  background: linear-gradient(#0f141b, #090d13);
  border-bottom: 1px solid var(--line);
}
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}
.status-ring {
  width: 16px;
  height: 16px;
  border-radius: 50%;
  border: 2px solid var(--accent);
  box-shadow: 0 0 10px rgba(66, 199, 255, 0.35);
}
h1 {
  margin: 0;
  font-size: 14px;
  font-weight: 700;
}
.subtitle {
  margin-top: 2px;
  color: var(--muted);
  font-size: 11px;
}
.toolbar {
  display: flex;
  gap: 8px;
  align-items: center;
  min-width: 0;
}
.tool-pill {
  min-width: 118px;
  height: 30px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--line);
  border-radius: 5px;
  color: #9db1c5;
  background: #0d131b;
}
.tool-pill.primary {
  color: #001923;
  border-color: #58cfff;
  background: linear-gradient(#75d8ff, #2aa9df);
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.35), 0 0 16px rgba(66,199,255,0.25);
}
.tool-pill.action {
  font: inherit;
  cursor: pointer;
}
.tool-pill.action:hover {
  color: #eaf8ff;
  border-color: var(--accent);
  background: #102130;
}
)KNL";
    html << LR"KNL(
.snapshot-status {
  justify-self: end;
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  align-items: center;
  gap: 6px;
  width: 100%;
  color: #e0ebf7;
}
.status-chip {
  min-width: 0;
  height: 30px;
  display: grid;
  align-content: center;
  gap: 1px;
  padding: 0 8px;
  border: 1px solid var(--line);
  border-radius: 5px;
  background: #0a1017;
}
.status-chip b {
  color: var(--text);
  font-size: 11px;
  font-weight: 700;
  line-height: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.status-chip span {
  color: var(--muted);
  font-size: 10px;
  line-height: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.status-chip.warn {
  border-color: #6d5520;
  background: #1c170d;
}
.status-chip.warn b {
  color: var(--warn);
}
.status-chip.muted {
  border-color: var(--line);
}
.layout {
  min-height: 0;
  display: grid;
  grid-template-columns: 380px minmax(520px, 1fr) 360px;
}
.left-rail {
  min-width: 0;
  overflow: auto;
  background: var(--chrome);
  border-right: 1px solid var(--line);
}
.rail-tabs {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 6px;
  padding: 6px;
  border-bottom: 1px solid var(--line);
}
.rail-tab {
  padding: 6px 4px;
  border: 1px solid var(--line);
  border-radius: 5px;
  text-align: center;
  color: #b5c9dd;
  background: #0b1118;
}
.rail-tab.active {
  color: #ffffff;
  background: #142435;
  border-color: var(--line2);
}
.panel {
  border-bottom: 1px solid var(--line);
  padding-bottom: 8px;
}
.summary {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px;
  padding: 8px;
}
.metric {
  min-height: 54px;
  padding: 9px;
  border: 1px solid var(--line);
  border-radius: 5px;
  background: var(--panel);
}
.metric .label {
  color: var(--muted);
  font-size: 10px;
  text-transform: uppercase;
}
.metric .value {
  margin-top: 4px;
  color: var(--accent);
  font-size: 18px;
  font-weight: 700;
}
.controls {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 8px;
}
.control-label {
  display: grid;
  gap: 4px;
  color: #b8cde2;
  font-size: 11px;
}
input,
select {
  width: 100%;
  min-height: 29px;
  color: var(--text);
  background: #0a1017;
  border: 1px solid var(--line);
  border-radius: 4px;
  padding: 0 9px;
}
input:focus,
select:focus {
  border-color: var(--accent);
  outline: 1px solid rgba(66,199,255,0.35);
}
.legend {
  display: grid;
  gap: 7px;
  padding: 8px;
}
.ti-focus,
.finding-focus {
  display: grid;
  gap: 7px;
  padding: 8px;
}
.ti-card,
.finding-card {
  padding: 8px;
  border: 1px solid var(--line);
  border-radius: 5px;
  background: var(--panel);
}
.finding-card {
  cursor: pointer;
  width: 100%;
  color: inherit;
  font: inherit;
  text-align: left;
}
.finding-card:hover {
  border-color: var(--accent);
  background: #102030;
}
.ti-card .ti-title,
.finding-card .finding-title {
  color: var(--accent);
  font-weight: 700;
}
.ti-card .ti-sub,
.finding-card .finding-sub {
  margin-top: 3px;
  color: var(--muted);
  font-size: 11px;
}
.legend-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 7px 8px;
  border: 1px solid var(--line);
  border-radius: 5px;
  background: var(--panel);
}
.legend-accent {
  color: var(--accent);
  font-weight: 700;
}
.workspace {
  min-width: 0;
  min-height: 0;
  overflow: hidden;
  border-right: 1px solid var(--line);
  background: #0b1118;
}
.section-title {
  padding: 9px 10px;
  color: #ffffff;
  border-bottom: 1px solid var(--line);
  font-size: 12px;
  font-weight: 700;
}
.workspace-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--line);
  background: #0d131a;
}
.workspace-top .section-title {
  border-bottom: 0;
}
.hint {
  padding-right: 10px;
  color: var(--muted);
}
.timeline {
  height: 40vh;
  min-height: 260px;
  overflow: auto;
  padding: 8px 10px 12px;
  border-bottom: 1px solid var(--line);
  background: #0a1016;
}
.axis {
  position: sticky;
  top: 0;
  z-index: 2;
  display: grid;
  grid-template-columns: 210px 1fr;
  align-items: center;
  min-width: 820px;
  padding: 0 0 8px;
  background: #0a1016;
  color: var(--muted);
  font-size: 11px;
}
.axis-line {
  display: flex;
  justify-content: space-between;
  border-bottom: 1px solid var(--line);
  padding-bottom: 5px;
}
.lane {
  display: grid;
  grid-template-columns: 210px 1fr;
  min-width: 820px;
  min-height: 38px;
  border-bottom: 1px solid rgba(255,255,255,0.06);
}
.lane-label {
  padding: 11px 10px 0 0;
  color: var(--text);
  font-size: 12px;
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
}
.lane-track {
  position: relative;
  min-height: 38px;
}
.lane-track::before {
  content: "";
  position: absolute;
  left: 0;
  right: 0;
  top: 19px;
  border-top: 1px solid rgba(255,255,255,0.08);
}
.marker {
  position: absolute;
  top: 10px;
  width: 15px;
  height: 15px;
  transform: translateX(-8px);
  border-radius: 50%;
  border: 2px solid #081018;
  cursor: pointer;
  background: var(--accent);
  box-shadow: 0 0 9px rgba(66,199,255,0.28);
}
.marker.process {
  border-radius: 4px;
}
.marker.image {
  background: var(--mid);
}
.marker.thread {
  background: var(--good);
}
.marker.threat-intelligence {
  background: var(--warn);
}
.marker.high,
.marker.critical {
  background: var(--bad);
}
.marker.medium {
  background: var(--warn);
}
.marker.warning {
  background: var(--warn);
}
.marker.low,
.marker.info {
  background: var(--good);
}
.marker.selected {
  outline: 2px solid #ffffff;
  box-shadow: 0 0 0 4px rgba(66,199,255,0.25);
}
)KNL";
    html << LR"KNL(
.panels {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(320px, 42%);
  min-height: 0;
}
.event-list,
.graph-list {
  min-height: 220px;
  max-height: calc(60vh - 130px);
  overflow: auto;
  background: #0a1016;
}
.event-row,
.edge-row {
  display: grid;
  grid-template-columns: 72px 96px 78px minmax(0, 1fr);
  gap: 8px;
  min-height: 27px;
  padding: 6px 10px;
  border-bottom: 1px solid rgba(255,255,255,0.06);
  cursor: pointer;
  font-size: 12px;
}
.event-row:nth-child(odd),
.edge-row:nth-child(odd) {
  background: rgba(255,255,255,0.025);
}
.event-row:hover,
.edge-row:hover {
  background: #12283a;
}
.event-row.selected {
  background: var(--selected);
}
.cell-muted {
  color: var(--muted);
}
.side {
  min-width: 0;
  min-height: 0;
  overflow: hidden;
  background: var(--chrome);
}
.detail {
  padding: 14px;
  overflow: auto;
  max-height: calc(100vh - 112px);
}
.detail h2 {
  margin: 0 0 10px;
  color: var(--accent);
  font-size: 15px;
}
.detail h3 {
  margin: 14px 0 8px;
  color: #ffffff;
  font-size: 12px;
}
.kv {
  display: grid;
  grid-template-columns: 120px minmax(0, 1fr);
  gap: 6px 10px;
  font-size: 12px;
  margin-bottom: 14px;
}
.kv .k {
  color: var(--muted);
}
pre {
  margin: 0;
  padding: 10px;
  border: 1px solid var(--line);
  border-radius: 5px;
  background: #070b10;
  color: #d8e2f0;
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 12px;
}
.related-list {
  display: grid;
  gap: 6px;
  margin-bottom: 14px;
}
.related-row {
  display: grid;
  grid-template-columns: 52px 72px minmax(0, 1fr);
  gap: 7px;
  min-height: 25px;
  padding: 6px 8px;
  border: 1px solid var(--line);
  border-radius: 4px;
  background: var(--panel);
  cursor: pointer;
  color: inherit;
  font: inherit;
  text-align: left;
}
.related-row:hover {
  border-color: var(--accent);
  background: #102030;
}
.empty {
  padding: 24px;
  color: var(--muted);
}
.warning {
  display: none;
  padding: 8px 10px;
  background: #302414;
  color: #ffd77a;
  border-bottom: 1px solid #6d5520;
  font-size: 13px;
}
.warning.show {
  display: block;
}
.statusbar {
  display: flex;
  align-items: center;
  gap: 22px;
  padding: 0 10px;
  color: #dbe7f3;
  background: #05080c;
  border-top: 1px solid var(--line);
  font-size: 12px;
}
@media (max-width: 1180px) {
  body {
    overflow: auto;
  }
  .app-window {
    min-height: 100vh;
    grid-template-rows: 32px auto auto 26px;
  }
  .topbar {
    grid-template-columns: 1fr;
  }
  .snapshot-status {
    justify-self: stretch;
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .layout {
    grid-template-columns: 1fr;
  }
  .left-rail,
  .workspace,
  .side {
    border-right: 0;
    border-bottom: 1px solid var(--line);
  }
  .summary {
    grid-template-columns: repeat(3, 1fr);
  }
}
</style>
</head>
<body>
<div class="app-window">
<div class="titlebar">
  <div class="window-brand"><span class="app-logo">K</span><span>KnLiveDbg Timeline Dashboard</span></div>
  <div class="window-actions">- [] X</div>
</div>
<header class="topbar">
  <div class="brand">
    <span class="status-ring"></span>
    <div>
      <h1>KnLiveDbg Timeline Dashboard</h1>
      <div class="subtitle" id="subtitle"></div>
    </div>
  </div>
  <div class="toolbar">
    <div class="tool-pill primary">Timeline View</div>
    <div class="tool-pill">Events</div>
    <div class="tool-pill">Relationships</div>
    <button class="tool-pill action" id="exportJsonl" type="button">Export JSONL</button>
  </div>
  <div class="snapshot-status" id="snapshotStatus">
    <div class="status-chip warn" id="liveModeChip"><b id="liveMode">static</b><span id="liveModeSub">snapshot</span></div>
    <div class="status-chip muted" id="autoDrainChip"><b id="autoDrainState">not live</b><span id="autoDrainSub">HTML view</span></div>
    <div class="status-chip"><b id="statusGenerated">--</b><span>generated</span></div>
    <div class="status-chip"><b id="statusEvents">0</b><span>events</span></div>
  </div>
</header>
<main class="layout">
  <aside class="left-rail">
    <div class="rail-tabs">
      <div class="rail-tab active">Timeline</div>
      <div class="rail-tab">Graph</div>
      <div class="rail-tab">Evidence</div>
    </div>
    <section class="panel">
      <div class="section-title">Evidence Summary</div>
      <section class="summary" id="summary"></section>
    </section>
    <section class="panel">
      <div class="section-title">Display Filters</div>
      <section class="controls">
        <label class="control-label">Text<input id="search" type="search" placeholder="process, image, summary, evidence"></label>
        <label class="control-label">Source<select id="sourceFilter"></select></label>
        <label class="control-label">Domain<select id="domainFilter"></select></label>
        <label class="control-label">Process<select id="pidFilter"></select></label>
        <label class="control-label">Image / Driver / DLL<select id="imageFilter"></select></label>
        <label class="control-label">TI Task<select id="taskFilter"></select></label>
        <label class="control-label">Risk<select id="riskFilter"></select></label>
      </section>
    </section>
    <section class="panel">
      <div class="section-title">Threat Intelligence</div>
      <div class="ti-focus" id="tiFocus"></div>
    </section>
    <section class="panel">
      <div class="section-title">Matched Rules</div>
      <div class="finding-focus" id="findingFocus"></div>
    </section>
    <section class="panel">
      <div class="section-title">Marker Legend</div>
      <div class="legend">
        <div class="legend-item"><span>Process event</span><span class="legend-accent">cyan</span></div>
        <div class="legend-item"><span>Thread event</span><span class="legend-accent">green</span></div>
        <div class="legend-item"><span>Image or module</span><span class="legend-accent">blue</span></div>
        <div class="legend-item"><span>TI / warning</span><span class="legend-accent">amber</span></div>
        <div class="legend-item"><span>High risk</span><span class="legend-accent">red</span></div>
      </div>
    </section>
  </aside>
  <section class="workspace">
    <div class="warning" id="warning"></div>
    <div class="workspace-top">
      <div class="section-title">Timeline</div>
      <div class="hint">select markers or rows to inspect evidence</div>
    </div>
    <div class="timeline" id="timeline"></div>
    <div class="panels">
      <section>
        <div class="section-title">Events</div>
        <div class="event-list" id="eventList"></div>
      </section>
      <section>
        <div class="section-title">Relationships</div>
        <div class="graph-list" id="graphList"></div>
      </section>
    </div>
  </section>
  <aside class="side">
    <div class="section-title">Selection</div>
    <div class="detail" id="detail"></div>
  </aside>
</main>
<footer class="statusbar" id="footerStatus"></footer>
</div>
<script>
const KN_DATA = )KNL";
    html << L"{\"header\":" << headerJson
         << L",\"status\":" << statusJson
         << L",\"live\":" << liveJson
         << L",\"analysis\":" << analysisJson
         << L",\"events\":" << eventsJson
         << L"}";
    html << LR"KNL(;

const state = {
  selectedId: null
};

function byId(id) {
  return document.getElementById(id);
}

function lower(value) {
  return String(value || "").toLowerCase();
}

function riskClass(value) {
  const text = lower(value || "info");
  if (text.includes("critical")) {
    return "critical";
  }
  if (text.includes("high")) {
    return "high";
  }
  if (text.includes("medium")) {
    return "medium";
  }
  if (text.includes("warning")) {
    return "warning";
  }
  if (text.includes("low")) {
    return "low";
  }
  return "info";
}

function eventImageValues(event) {
  const values = new Set();
  const evidence = event.evidence || {};
  for (const key of Object.keys(evidence)) {
    const lk = lower(key);
    if (lk.includes("image") || lk.includes("dll") || lk.includes("driver") || lk.includes("module")) {
      if (evidence[key]) {
        values.add(String(evidence[key]));
      }
    }
  }
  const domainText = lower(event.domain);
  if ((domainText.includes("image") || domainText.includes("driver") || domainText.includes("module")) && event.entity) {
    values.add(String(event.entity));
  }
  return Array.from(values).sort((a, b) => a.localeCompare(b));
}

function eventText(event) {
  const parts = [
    event.eventId,
    event.timestampUtc,
    event.source,
    event.domain,
    event.action,
    event.pid,
    event.tid,
    event.targetPid,
    event.entity,
    event.summary,
    event.risk,
    event.confidence
  ];
  const evidence = event.evidence || {};
  for (const key of Object.keys(evidence)) {
    parts.push(key);
    parts.push(evidence[key]);
  }
  return lower(parts.filter((item) => item !== undefined && item !== null).join(" "));
}

function tiTaskValue(event) {
  const evidence = event.evidence || {};
  return event.action || evidence.ti_action || evidence.task_name || "";
}

function isTiEvent(event) {
  return event.source === "ti" || event.domain === "threat-intelligence";
}

function fileTimeToMs(value) {
  const numberValue = Number(value);
  if (!Number.isFinite(numberValue) || numberValue <= 0) {
    return NaN;
  }
  return (numberValue / 10000) - 11644473600000;
}

function timeValue(event) {
  if (event.timestampUtc) {
    const parsed = Date.parse(event.timestampUtc);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  if (event.timestampFileTime) {
    return fileTimeToMs(event.timestampFileTime);
  }
  return NaN;
}

function timeLabel(event) {
  if (event.timestampUtc) {
    return event.timestampUtc;
  }
  const value = timeValue(event);
  if (Number.isFinite(value)) {
    return new Date(value).toISOString();
  }
  return "event #" + event.eventId;
}

function laneLabel(event) {
  if (isTiEvent(event)) {
    return "TI " + (tiTaskValue(event) || "event");
  }
  if (event.pid) {
    const name = event.entity ? " " + event.entity : "";
    return "PID " + event.pid + name;
  }
  if (event.targetPid) {
    return "Target PID " + event.targetPid;
  }
  if (event.domain) {
    return "Domain " + event.domain;
  }
  return "Unscoped";
}

function option(select, value, label) {
  const element = document.createElement("option");
  element.value = value;
  element.textContent = label;
  select.appendChild(element);
}

function populateFilters() {
  const sources = new Set();
  const domains = new Set();
  const pids = new Map();
  const images = new Set();
  const tasks = new Set();
  const risks = new Set();

  for (const event of KN_DATA.events) {
    if (event.source) {
      sources.add(event.source);
    }
    if (event.domain) {
      domains.add(event.domain);
    }
    if (event.pid) {
      const label = "PID " + event.pid + (event.entity ? " " + event.entity : "");
      if (!pids.has(String(event.pid))) {
        pids.set(String(event.pid), label);
      }
    }
    if (event.targetPid) {
      const target = String(event.targetPid);
      if (!pids.has(target)) {
        pids.set(target, "PID " + target);
      }
    }
    for (const image of eventImageValues(event)) {
      images.add(image);
    }
    if (isTiEvent(event) && tiTaskValue(event)) {
      tasks.add(tiTaskValue(event));
    }
    if (event.risk) {
      risks.add(event.risk);
    }
  }

  const sourceFilter = byId("sourceFilter");
  const domainFilter = byId("domainFilter");
  const pidFilter = byId("pidFilter");
  const imageFilter = byId("imageFilter");
  const taskFilter = byId("taskFilter");
  const riskFilter = byId("riskFilter");

  option(sourceFilter, "", "All sources");
  option(domainFilter, "", "All domains");
  option(pidFilter, "", "All PIDs");
  option(imageFilter, "", "All images/drivers");
  option(taskFilter, "", "All TI tasks");
  option(riskFilter, "", "All risk");

  Array.from(sources).sort().forEach((value) => option(sourceFilter, value, value));
  Array.from(domains).sort().forEach((value) => option(domainFilter, value, value));
  Array.from(pids.entries()).sort((a, b) => Number(a[0]) - Number(b[0])).forEach((item) => option(pidFilter, item[0], item[1]));
  Array.from(images).sort((a, b) => a.localeCompare(b)).forEach((value) => option(imageFilter, value, value));
  Array.from(tasks).sort((a, b) => a.localeCompare(b)).forEach((value) => option(taskFilter, value, value));
  Array.from(risks).sort().forEach((value) => option(riskFilter, value, value));
}

function filteredEvents() {
  const text = lower(byId("search").value);
  const source = byId("sourceFilter").value;
  const domain = byId("domainFilter").value;
  const pid = byId("pidFilter").value;
  const image = byId("imageFilter").value;
  const task = byId("taskFilter").value;
  const risk = byId("riskFilter").value;

  return KN_DATA.events.filter((event) => {
    if (source && event.source !== source) {
      return false;
    }
    if (domain && event.domain !== domain) {
      return false;
    }
    if (pid && String(event.pid || event.targetPid || "") !== pid && String(event.targetPid || "") !== pid) {
      return false;
    }
    if (image && !eventImageValues(event).some((value) => value === image)) {
      return false;
    }
    if (task && tiTaskValue(event) !== task) {
      return false;
    }
    if (risk && event.risk !== risk) {
      return false;
    }
    if (text && !eventText(event).includes(text)) {
      return false;
    }
    return true;
  }).sort((a, b) => {
    const at = timeValue(a);
    const bt = timeValue(b);
    if (Number.isFinite(at) && Number.isFinite(bt) && at !== bt) {
      return at - bt;
    }
    return Number(a.eventId || 0) - Number(b.eventId || 0);
  });
}

function jsonlForEvents(events) {
  if (!events.length) {
    return "";
  }
  return events.map((event) => JSON.stringify(event)).join("\n") + "\n";
}

function exportJsonl() {
  const events = filteredEvents();
  const blob = new Blob([jsonlForEvents(events)], { type: "application/jsonl;charset=utf-8" });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "kn-live-dbg-timeline-" + stamp + ".jsonl";
  document.body.appendChild(link);
  link.click();
  setTimeout(() => {
    URL.revokeObjectURL(url);
    link.remove();
  }, 0);
}

)KNL";
    html << LR"KNL(
function markerPosition(events, event, index) {
  const times = events.map(timeValue).filter((value) => Number.isFinite(value));
  if (times.length > 1) {
    const min = Math.min(...times);
    const max = Math.max(...times);
    const current = timeValue(event);
    if (Number.isFinite(current) && max > min) {
      return Math.max(1, Math.min(99, ((current - min) * 100) / (max - min)));
    }
  }
  if (events.length <= 1) {
    return 50;
  }
  return 1 + ((index * 98) / (events.length - 1));
}

function renderSummary(events) {
  const status = KN_DATA.status;
  const header = KN_DATA.header;
  const live = KN_DATA.live || {};
  const tiEvents = events.filter(isTiEvent);
  const criticalTiEvents = tiEvents.filter((event) => riskClass(event.risk) === "critical");
  byId("subtitle").textContent = "Generated " + header.generatedUtc + " | " + header.displayedEvents + " embedded events";
  byId("statusGenerated").textContent = header.generatedUtc || "--";
  byId("statusEvents").textContent = String(events.length) + "/" + String(status.stored || 0);
  renderLiveStatus(live);

  const metrics = [
    ["Stored", status.stored || 0],
    ["Displayed", events.length],
    ["TI Events", tiEvents.length],
    ["Critical TI", criticalTiEvents.length],
    ["Capacity", status.capacity || 0],
    ["Dropped", status.dropped || 0],
    ["Sources", Object.keys(status.bySource || {}).length],
    ["Domains", Object.keys(status.byDomain || {}).length]
  ];
  byId("summary").innerHTML = metrics.map((item) =>
    "<div class=\"metric\"><div class=\"label\">" + escapeHtml(item[0]) + "</div><div class=\"value\">" + escapeHtml(item[1]) + "</div></div>"
  ).join("");

  const warnings = [];
  if (status.dropped) {
    warnings.push("Timeline store reports dropped events. Treat this dashboard as partial evidence.");
  }
  if (live.dropped) {
    warnings.push("Kernel live ring reports dropped events. Live evidence is partial.");
  }
  if (live.available && live.capacity && live.queued && ((live.queued * 100) / live.capacity) >= 75) {
    warnings.push("Kernel live ring pressure is high. Keep auto-drain running or export current evidence.");
  }
  if (live.autoDrainErrors) {
    warnings.push("Auto-drain reported errors. Check timeline live status before relying on absence evidence.");
  }
  if (header.truncated) {
    warnings.push("Dashboard embeds newest " + header.maxEvents + " events out of " + header.totalStored + " stored events.");
  }
  byId("warning").className = warnings.length ? "warning show" : "warning";
  byId("warning").textContent = warnings.join(" ");
  byId("footerStatus").textContent =
    "State: local dashboard" +
    "    Events: " + events.length + "/" + (status.stored || 0) +
    "    TI: " + tiEvents.length +
    "    Dropped: " + (status.dropped || 0) +
    "    Capacity: " + (status.capacity || 0) +
    "    Live queued: " + (live.queued || 0) + "/" + (live.capacity || 0) +
    "    Auto-drain: " + (live.autoDrainRunning ? "running" : "stopped");

  renderTiFocus(tiEvents);
  renderFindings(events);
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'\"]/g, (ch) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "'": "&#39;",
    "\"": "&quot;"
  })[ch]);
}

function livePressurePercent(live) {
  if (!live || !live.capacity) {
    return 0;
  }
  return Math.min(100, Math.round(((live.queued || 0) * 100) / live.capacity));
}

function renderLiveStatus(live) {
  const active = !!(live && live.available && live.active);
  const pressure = livePressurePercent(live);
  const liveModeChip = byId("liveModeChip");
  const autoDrainChip = byId("autoDrainChip");
  byId("liveMode").textContent = active ? "live on" : (live && live.available ? "live off" : "static");
  byId("liveModeSub").textContent = active ?
    ((live.threadCallback ? "process/image/thread" : "process/image") + " " + pressure + "%") :
    "snapshot";
  liveModeChip.className = active ?
    (pressure >= 75 ? "status-chip warn" : "status-chip") :
    "status-chip warn";

  byId("autoDrainState").textContent = live && live.autoDrainRunning ? "draining" : "not live";
  byId("autoDrainSub").textContent = live && live.autoDrainRunning ?
    ("+" + (live.autoDrainAdded || 0) + " events") :
    "HTML view";
  autoDrainChip.className = live && live.autoDrainRunning ?
    (live.autoDrainErrors ? "status-chip warn" : "status-chip") :
    "status-chip muted";
}

function visibleFindings(events) {
  const visibleIds = new Set(events.map((event) => Number(event.eventId || 0)));
  const findings = ((KN_DATA.analysis || {}).findings || []);
  return findings.filter((finding) => {
    const first = Number(finding.firstEventId || 0);
    const last = Number(finding.lastEventId || 0);
    return (!first && !last) || visibleIds.has(first) || visibleIds.has(last);
  });
}

function selectableFindingEventId(finding) {
  const eventIds = new Set(KN_DATA.events.map((event) => String(event.eventId)));
  const last = String(finding.lastEventId || "");
  const first = String(finding.firstEventId || "");
  if (last && eventIds.has(last)) {
    return last;
  }
  if (first && eventIds.has(first)) {
    return first;
  }
  return "";
}

function renderFindings(events) {
  const container = byId("findingFocus");
  const findings = visibleFindings(events);
  if (!findings.length) {
    container.innerHTML = "<div class=\"empty\">No live analysis findings match the current filters.</div>";
    return;
  }

  container.innerHTML = findings.slice(0, 10).map((finding) =>
    "<button class=\"finding-card\" type=\"button\" data-event-id=\"" +
    escapeHtml(selectableFindingEventId(finding)) + "\">" +
    "<div class=\"finding-title\">" + escapeHtml(finding.kind || "finding") + "</div>" +
    "<div class=\"finding-sub\">" + escapeHtml(finding.risk || "info") +
    " | " + escapeHtml(finding.summary || "") + "</div></button>"
  ).join("");
  container.querySelectorAll("[data-event-id]").forEach((element) => {
    element.addEventListener("click", () => {
      const eventId = element.getAttribute("data-event-id");
      if (eventId) {
        selectEvent(eventId);
      }
    });
  });
}

)KNL";
    html << LR"KNL(
function renderTiFocus(events) {
  const container = byId("tiFocus");
  if (!events.length) {
    container.innerHTML = "<div class=\"empty\">No TI events match the current filters.</div>";
    return;
  }

  const tasks = new Map();
  for (const event of events) {
    const task = tiTaskValue(event) || "TI event";
    if (!tasks.has(task)) {
      tasks.set(task, { count: 0, critical: 0, warning: 0 });
    }
    const item = tasks.get(task);
    item.count += 1;
    if (riskClass(event.risk) === "critical") {
      item.critical += 1;
    }
    else if (riskClass(event.risk) === "medium" || riskClass(event.risk) === "warning") {
      item.warning += 1;
    }
  }

  container.innerHTML = Array.from(tasks.entries())
    .sort((a, b) => b[1].count - a[1].count || a[0].localeCompare(b[0]))
    .slice(0, 8)
    .map((item) =>
      "<div class=\"ti-card\"><div class=\"ti-title\">" + escapeHtml(item[0]) + "</div>" +
      "<div class=\"ti-sub\">events=" + escapeHtml(item[1].count) +
      " critical=" + escapeHtml(item[1].critical) +
      " warning=" + escapeHtml(item[1].warning) + "</div></div>"
    ).join("");
}

function renderTimeline(events) {
  const container = byId("timeline");
  if (!events.length) {
    container.innerHTML = "<div class=\"empty\">No timeline events match the current filters.</div>";
    return;
  }

  const laneMap = new Map();
  events.forEach((event, index) => {
    const label = laneLabel(event);
    if (!laneMap.has(label)) {
      laneMap.set(label, []);
    }
    laneMap.get(label).push({ event, index });
  });

  const first = timeLabel(events[0]);
  const last = timeLabel(events[events.length - 1]);
  let html = "<div class=\"axis\"><div></div><div class=\"axis-line\"><span>" + escapeHtml(first) + "</span><span>" + escapeHtml(last) + "</span></div></div>";

  for (const [label, items] of laneMap.entries()) {
    html += "<div class=\"lane\"><div class=\"lane-label\" title=\"" + escapeHtml(label) + "\">" + escapeHtml(label) + "</div><div class=\"lane-track\">";
    for (const item of items) {
      const event = item.event;
      const x = markerPosition(events, event, item.index);
      const classes = ["marker", lower(event.domain || "event"), riskClass(event.risk)];
      if (String(event.eventId) === String(state.selectedId)) {
        classes.push("selected");
      }
      html += "<button class=\"" + classes.join(" ") + "\" style=\"left:" + x.toFixed(2) + "%\" title=\"" + escapeHtml(timeLabel(event) + " " + (event.summary || event.entity || "")) + "\" data-event-id=\"" + escapeHtml(event.eventId) + "\"></button>";
    }
    html += "</div></div>";
  }

  container.innerHTML = html;
  container.querySelectorAll("[data-event-id]").forEach((element) => {
    element.addEventListener("click", () => selectEvent(element.getAttribute("data-event-id")));
  });
}

)KNL";
    html << LR"KNL(
function renderEventList(events) {
  const container = byId("eventList");
  if (!events.length) {
    container.innerHTML = "<div class=\"empty\">No events.</div>";
    return;
  }
  container.innerHTML = events.map((event) => {
    const selected = String(event.eventId) === String(state.selectedId) ? " selected" : "";
    return "<div class=\"event-row" + selected + "\" data-event-id=\"" + escapeHtml(event.eventId) + "\">" +
      "<div class=\"cell-muted\">#" + escapeHtml(event.eventId) + "</div>" +
      "<div>" + escapeHtml(event.source || "") + "</div>" +
      "<div>" + escapeHtml(event.domain || "") + "</div>" +
      "<div>" + escapeHtml(event.summary || event.entity || "") + "</div>" +
      "</div>";
  }).join("");
  container.querySelectorAll("[data-event-id]").forEach((element) => {
    element.addEventListener("click", () => selectEvent(element.getAttribute("data-event-id")));
  });
}

)KNL";
    html << LR"KNL(
function edgeKey(from, to, kind) {
  return from + "|" + to + "|" + kind;
}

function addEdge(map, from, to, kind, event) {
  if (!from || !to) {
    return;
  }
  const key = edgeKey(from, to, kind);
  if (!map.has(key)) {
    map.set(key, { from, to, kind, count: 0, first: event.eventId, last: event.eventId });
  }
  const edge = map.get(key);
  edge.count += 1;
  edge.first = Math.min(Number(edge.first), Number(event.eventId));
  edge.last = Math.max(Number(edge.last), Number(event.eventId));
}

function buildEdges(events) {
  const edges = new Map();
  for (const event of events) {
    const source = event.source ? "source:" + event.source : "";
    const domain = event.domain ? "domain:" + event.domain : "";
    const process = event.pid ? "process:" + event.pid : "";
    const target = event.targetPid ? "process:" + event.targetPid : "";
    addEdge(edges, source, domain, "source-domain", event);
    addEdge(edges, source, process || target, "source-observes-process", event);
    addEdge(edges, process, domain, event.source === "snapshot" ? "snapshot-record" : "process-domain", event);
    addEdge(edges, process, target, event.source === "ti" ? "ti-targets-process" : "targets-process", event);
    const evidence = event.evidence || {};
    const parent = evidence.parent_pid || evidence.ppid || evidence.parent_process_id || evidence.inherited_from_pid || evidence.creator_pid;
    if (parent && process) {
      addEdge(edges, "process:" + parent, process, "parent-child", event);
    }
    for (const image of eventImageValues(event)) {
      const imageNode = "image:" + image;
      addEdge(edges, source, imageNode, "source-observes-image", event);
      addEdge(edges, process || target, imageNode, "process-loads-image", event);
    }
  }
  return Array.from(edges.values()).sort((a, b) => b.count - a.count || a.kind.localeCompare(b.kind)).slice(0, 80);
}

function renderGraph(events) {
  const container = byId("graphList");
  const edges = buildEdges(events);
  if (!edges.length) {
    container.innerHTML = "<div class=\"empty\">No relationships.</div>";
    return;
  }
  container.innerHTML = edges.map((edge) =>
    "<div class=\"edge-row\">" +
    "<div class=\"cell-muted\">" + escapeHtml(edge.kind) + "</div>" +
    "<div>" + escapeHtml(edge.from) + "</div>" +
    "<div class=\"cell-muted\">x" + escapeHtml(edge.count) + "</div>" +
    "<div>" + escapeHtml(edge.to) + "</div>" +
    "</div>"
  ).join("");
}

)KNL";
    html << LR"KNL(
function relatedEvents(event) {
  if (!event) {
    return [];
  }

  const pids = new Set();
  if (event.pid) {
    pids.add(String(event.pid));
  }
  if (event.targetPid) {
    pids.add(String(event.targetPid));
  }
  const tid = event.tid ? String(event.tid) : "";
  const baseTime = timeValue(event);
  const windowMs = 10000;

  return KN_DATA.events.filter((candidate) => {
    if (String(candidate.eventId) === String(event.eventId)) {
      return false;
    }

    let matched = false;
    if (candidate.pid && pids.has(String(candidate.pid))) {
      matched = true;
    }
    if (candidate.targetPid && pids.has(String(candidate.targetPid))) {
      matched = true;
    }
    if (tid && candidate.tid && String(candidate.tid) === tid) {
      matched = true;
    }
    if (!matched) {
      return false;
    }

    const candidateTime = timeValue(candidate);
    if (Number.isFinite(baseTime) && Number.isFinite(candidateTime)) {
      return Math.abs(candidateTime - baseTime) <= windowMs;
    }
    return true;
  }).sort((a, b) => {
    const at = timeValue(a);
    const bt = timeValue(b);
    if (Number.isFinite(at) && Number.isFinite(bt) && at !== bt) {
      return at - bt;
    }
    return Number(a.eventId || 0) - Number(b.eventId || 0);
  }).slice(0, 12);
}

function renderRelatedEvents(event) {
  const related = relatedEvents(event);
  if (!related.length) {
    return "<h3>Related Events</h3><div class=\"empty\">No nearby related events.</div>";
  }

  return "<h3>Related Events</h3><div class=\"related-list\">" + related.map((item) =>
    "<button class=\"related-row\" type=\"button\" data-event-id=\"" + escapeHtml(item.eventId) + "\">" +
    "<div class=\"cell-muted\">#" + escapeHtml(item.eventId) + "</div>" +
    "<div>" + escapeHtml(item.domain || "") + "</div>" +
    "<div>" + escapeHtml(item.summary || item.entity || "") + "</div></button>"
  ).join("") + "</div>";
}

function renderDetail(event) {
  const container = byId("detail");
  if (!event) {
    container.innerHTML = "<div class=\"empty\">Select a timeline marker or event row.</div>";
    return;
  }
  const rows = [
    ["Event", "#" + event.eventId],
    ["Time", timeLabel(event)],
    ["Source", event.source],
    ["Domain", event.domain],
    ["Action", event.action],
    ["PID", event.pid || ""],
    ["TID", event.tid || ""],
    ["Target PID", event.targetPid || ""],
    ["Risk", event.risk || ""],
    ["Confidence", event.confidence || ""],
    ["Entity", event.entity || ""],
    ["Summary", event.summary || ""]
  ];
  container.innerHTML = "<h2>" + escapeHtml(event.summary || event.entity || "Event #" + event.eventId) + "</h2>" +
    "<div class=\"kv\">" + rows.map((row) => "<div class=\"k\">" + escapeHtml(row[0]) + "</div><div>" + escapeHtml(row[1]) + "</div>").join("") + "</div>" +
    renderRelatedEvents(event) +
    "<pre>" + escapeHtml(JSON.stringify(event, null, 2)) + "</pre>";
  container.querySelectorAll("[data-event-id]").forEach((element) => {
    element.addEventListener("click", () => selectEvent(element.getAttribute("data-event-id")));
  });
}

function selectEvent(eventId) {
  state.selectedId = eventId;
  const event = KN_DATA.events.find((item) => String(item.eventId) === String(eventId));
  renderDetail(event);
  render();
}

function render() {
  const events = filteredEvents();
  renderSummary(events);
  renderTimeline(events);
  renderEventList(events);
  renderGraph(events);
  if (state.selectedId) {
    renderDetail(KN_DATA.events.find((item) => String(item.eventId) === String(state.selectedId)));
  }
}

populateFilters();
byId("exportJsonl").addEventListener("click", exportJsonl);
["search", "sourceFilter", "domainFilter", "pidFilter", "imageFilter", "taskFilter", "riskFilter"].forEach((id) => {
  byId(id).addEventListener("input", () => {
    state.selectedId = null;
    renderDetail(null);
    render();
  });
});
renderDetail(null);
render();
</script>
</body>
</html>
)KNL";

    return html.str();
}
