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
        out += L",\"warnings\":[";
        for (size_t i = 0; i < document.Warnings.size(); ++i)
        {
            if (i != 0)
            {
                out += L",";
            }
            out += mcpjson::Quote(document.Warnings[i]);
        }
        out += L"]";
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
  --left-width: 380px;
  --side-width: 360px;
  --timeline-height: 40vh;
  --relationships-width: 42%;
  --timeline-min-width: 1400px;
  font-family: Segoe UI, Inter, Arial, sans-serif;
}
* {
  box-sizing: border-box;
}
html {
  height: 100%;
  overflow: hidden;
}
body {
  margin: 0;
  height: 100%;
  background: #05080c;
  color: var(--text);
  font-size: 12px;
  overflow: hidden;
}
body.resizing,
body.resizing * {
  user-select: none;
}
.app-window {
  height: 100vh;
  min-height: 0;
  display: grid;
  grid-template-rows: 32px 44px minmax(0, 1fr) 26px;
  overflow: hidden;
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
  min-width: 104px;
  height: 30px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--line);
  border-radius: 5px;
  color: #9db1c5;
  background: #0d131b;
  font: inherit;
  cursor: pointer;
}
.tool-pill.primary,
.tool-pill.active {
  color: #001923;
  border-color: #58cfff;
  background: linear-gradient(#75d8ff, #2aa9df);
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.35), 0 0 16px rgba(66,199,255,0.25);
}
.tool-pill.action {
}
.tool-pill:hover,
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
  grid-template-columns: var(--left-width) 6px minmax(520px, 1fr) 6px var(--side-width);
  overflow: hidden;
}
.left-rail {
  grid-column: 1;
  min-width: 0;
  min-height: 0;
  overflow-x: hidden;
  overflow-y: auto;
  scrollbar-gutter: stable;
  background: var(--chrome);
  border-right: 1px solid var(--line);
}
.splitter {
  position: relative;
  z-index: 8;
  background: #071019;
  touch-action: none;
}
.splitter.vertical {
  width: 6px;
  cursor: col-resize;
  border-left: 1px solid rgba(255,255,255,0.06);
  border-right: 1px solid rgba(255,255,255,0.06);
}
.splitter.horizontal {
  height: 6px;
  cursor: row-resize;
  border-top: 1px solid rgba(255,255,255,0.06);
  border-bottom: 1px solid rgba(255,255,255,0.06);
}
.splitter::after {
  content: "";
  position: absolute;
  inset: 0;
  background: transparent;
}
.splitter:hover::after,
.splitter.dragging::after {
  background: rgba(66,199,255,0.28);
}
.left-splitter {
  grid-column: 2;
}
.workspace-side {
  grid-column: 4;
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
  font: inherit;
  cursor: pointer;
}
.rail-tab.active {
  color: #ffffff;
  background: #142435;
  border-color: var(--line2);
}
.tool-pill:focus-visible,
.rail-tab:focus-visible {
  outline: 1px solid rgba(66,199,255,0.75);
  outline-offset: 2px;
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
.analyst-focus,
.ti-focus,
.finding-focus {
  display: grid;
  gap: 7px;
  padding: 8px;
}
.focus-card {
  display: grid;
  gap: 5px;
  padding: 9px;
  border: 1px solid var(--line);
  border-left: 3px solid var(--accent);
  border-radius: 5px;
  background: var(--panel);
}
.focus-card.good {
  border-left-color: var(--good);
}
.focus-card.warn {
  border-left-color: var(--warn);
  background: #16140d;
}
.focus-card.bad {
  border-left-color: var(--bad);
  background: #1a1014;
}
.focus-title {
  color: var(--accent);
  font-weight: 700;
}
.focus-card.good .focus-title {
  color: var(--good);
}
.focus-card.warn .focus-title {
  color: var(--warn);
}
.focus-card.bad .focus-title {
  color: var(--bad);
}
.focus-sub {
  color: var(--muted);
  line-height: 1.35;
}
.focus-counts {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 5px;
}
.focus-metric {
  padding: 6px;
  border: 1px solid rgba(255,255,255,0.08);
  border-radius: 4px;
  background: rgba(0,0,0,0.16);
}
.focus-metric b {
  display: block;
  color: var(--text);
  font-size: 13px;
}
.focus-metric span {
  color: var(--muted);
  font-size: 10px;
  text-transform: uppercase;
}
.ti-card,
.finding-card {
  padding: 8px;
  border: 1px solid var(--line);
  border-radius: 5px;
  background: var(--panel);
}
.ti-card {
  cursor: pointer;
  width: 100%;
  color: inherit;
  font: inherit;
  text-align: left;
}
.finding-card {
  cursor: pointer;
  width: 100%;
  color: inherit;
  font: inherit;
  text-align: left;
}
.ti-card:hover,
.finding-card:hover {
  border-color: var(--accent);
  background: #102030;
}
)KNL";
    html << LR"KNL(
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
  grid-column: 3;
  min-width: 0;
  min-height: 0;
  display: grid;
  grid-template-rows: auto auto minmax(0, var(--timeline-height)) 6px minmax(0, 1fr);
  overflow: hidden;
  border-right: 1px solid var(--line);
  background: #0b1118;
}
.app-window.mode-events .timeline,
.app-window.mode-relationships .timeline,
.app-window.mode-events .timeline-splitter,
.app-window.mode-relationships .timeline-splitter {
  display: none;
}
.app-window.mode-events .panels,
.app-window.mode-relationships .panels {
  grid-template-columns: 1fr;
}
.app-window.mode-events .workspace,
.app-window.mode-relationships .workspace {
  grid-template-rows: auto auto minmax(0, 1fr);
}
.app-window.mode-events .relationships-panel,
.app-window.mode-relationships .events-panel,
.app-window.mode-events .panel-splitter,
.app-window.mode-relationships .panel-splitter {
  display: none;
}
.app-window.mode-events .event-list,
.app-window.mode-relationships .graph-list {
  height: 100%;
  min-height: 0;
  max-height: none;
}
.app-window.mode-evidence .layout {
  grid-template-columns: var(--left-width) 6px minmax(520px, 1fr);
}
.app-window.mode-evidence .workspace {
  display: none;
}
.app-window.mode-evidence .workspace-side {
  display: none;
}
.app-window.mode-evidence .side {
  grid-column: 3;
  border-right: 0;
}
.app-window.mode-evidence .detail {
  max-height: none;
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
  min-height: 0;
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
  grid-template-columns: 280px 1fr;
  align-items: center;
  min-width: var(--timeline-min-width);
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
  grid-template-columns: 280px 1fr;
  min-width: var(--timeline-min-width);
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
.marker.network,
.marker.dns {
  background: var(--accent2);
}
.marker.file,
.marker.registry,
.marker.service,
.marker.scheduled-task,
.marker.task,
.marker.wmi {
  background: var(--warn);
}
.marker.memory,
.marker.vad,
.marker.vad-dkom,
.marker.snapshot-diff {
  background: var(--bad);
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
  grid-template-columns: minmax(360px, 1fr) 6px minmax(320px, var(--relationships-width));
  min-height: 0;
  min-width: 0;
  overflow: hidden;
}
.events-panel,
.relationships-panel {
  min-width: 0;
  min-height: 0;
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  overflow: hidden;
}
.event-list,
.graph-list {
  min-width: 0;
  min-height: 0;
  height: 100%;
  max-height: none;
  overflow: auto;
  background: #0a1016;
}
.event-row,
.edge-row {
  display: grid;
  gap: 8px;
  min-height: 27px;
  padding: 6px 10px;
  border-bottom: 1px solid rgba(255,255,255,0.06);
  color: inherit;
  cursor: pointer;
  font-size: 12px;
  white-space: nowrap;
}
.event-row {
  grid-template-columns: 72px 176px 112px 108px 80px 80px 96px 88px minmax(720px, 1fr);
  min-width: 1532px;
}
.edge-row {
  grid-template-columns: 260px 300px 72px minmax(700px, 1fr);
  min-width: 1360px;
}
.event-row.header,
.event-row.header:nth-child(odd),
.edge-row.header,
.edge-row.header:nth-child(odd) {
  position: sticky;
  top: 0;
  z-index: 2;
  min-height: 28px;
  color: #b8cde2;
  background: #0e1721;
  border-bottom: 1px solid var(--line);
  cursor: default;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
}
.graph-explainer {
  position: sticky;
  top: 0;
  z-index: 3;
  padding: 8px 10px;
  border-bottom: 1px solid var(--line);
  background: #0e1721;
  color: #bfd4e8;
  white-space: normal;
}
.graph-explainer b {
  color: var(--accent);
}
.edge-kind-title {
  color: var(--accent);
  font-weight: 700;
}
.edge-kind-sub {
  margin-top: 2px;
  color: var(--muted);
  font-size: 11px;
  white-space: normal;
}
.node-label {
  color: #f2f7ff;
}
.event-row:nth-child(odd),
.edge-row:nth-child(odd) {
  background: rgba(255,255,255,0.025);
}
.event-row.header:hover,
.edge-row.header:hover {
  background: #0e1721;
}
.event-row:hover,
.edge-row:hover {
  background: #12283a;
}
.event-row.selected {
  background: var(--selected);
}
.edge-row.selected {
  background: var(--selected);
}
.cell-muted {
  color: var(--muted);
}
.side {
  grid-column: 5;
  min-width: 0;
  min-height: 0;
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  overflow: hidden;
  background: var(--chrome);
}
.detail {
  min-height: 0;
  padding: 14px;
  overflow: auto;
  max-height: none;
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
.evidence-table {
  display: grid;
  gap: 5px;
  margin-bottom: 14px;
}
.evidence-row {
  display: grid;
  grid-template-columns: 128px minmax(0, 1fr);
  gap: 8px;
  padding: 6px 8px;
  border: 1px solid var(--line);
  border-radius: 4px;
  background: var(--panel);
}
.evidence-key {
  color: var(--muted);
  overflow-wrap: anywhere;
}
.evidence-value {
  color: var(--text);
  overflow-wrap: anywhere;
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
  min-width: 0;
  overflow: visible;
}
.related-row {
  display: grid;
  grid-template-columns: 52px 86px minmax(0, 1fr);
  gap: 7px;
  min-height: 25px;
  min-width: 0;
  padding: 6px 8px;
  border: 1px solid var(--line);
  border-radius: 4px;
  background: var(--panel);
  cursor: pointer;
  color: inherit;
  font: inherit;
  text-align: left;
  white-space: normal;
}
.related-row > div {
  min-width: 0;
  overflow-wrap: anywhere;
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
  .splitter {
    display: none;
  }
  .left-rail,
  .workspace,
  .side {
    grid-column: auto;
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
<div class="app-window mode-timeline" id="appWindow">
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
    <button class="tool-pill primary active" type="button" data-view="timeline">Timeline</button>
    <button class="tool-pill" type="button" data-view="events">Events</button>
    <button class="tool-pill" type="button" data-view="relationships">Relationships</button>
    <button class="tool-pill" type="button" data-view="evidence">Evidence</button>
    <button class="tool-pill action" id="exportJsonl" type="button">Export JSONL</button>
  </div>
  <div class="snapshot-status" id="snapshotStatus">
    <div class="status-chip warn" id="liveModeChip"><b id="liveMode">static</b><span id="liveModeSub">snapshot</span></div>
    <div class="status-chip muted" id="autoDrainChip"><b id="autoDrainState">not live</b><span id="autoDrainSub">HTML view</span></div>
    <div class="status-chip"><b id="statusGenerated">--</b><span>generated</span></div>
    <div class="status-chip"><b id="statusEvents">0</b><span>events</span></div>
  </div>
</header>
)KNL";
    html << LR"KNL(
<main class="layout">
  <aside class="left-rail">
    <div class="rail-tabs">
      <button class="rail-tab active" type="button" data-view="timeline">Timeline</button>
      <button class="rail-tab" type="button" data-view="relationships">Graph</button>
      <button class="rail-tab" type="button" data-view="evidence">Evidence</button>
    </div>
    <section class="panel">
      <div class="section-title">Analyst Focus</div>
      <div class="analyst-focus" id="analystFocus"></div>
    </section>
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
  <div class="splitter vertical left-splitter" data-resize="left" title="Resize filters"></div>
  <section class="workspace">
    <div class="warning" id="warning"></div>
    <div class="workspace-top">
      <div class="section-title" id="workspaceTitle">Timeline</div>
      <div class="hint" id="workspaceHint">select markers or rows to inspect evidence</div>
    </div>
    <div class="timeline" id="timeline"></div>
    <div class="splitter horizontal timeline-splitter" data-resize="timeline" title="Resize timeline"></div>
    <div class="panels">
      <section class="events-panel" id="eventsPanel">
        <div class="section-title">Events</div>
        <div class="event-list" id="eventList"></div>
      </section>
      <div class="splitter vertical panel-splitter" data-resize="relationships" title="Resize event and relationship panes"></div>
      <section class="relationships-panel" id="relationshipsPanel">
        <div class="section-title">Relationships</div>
        <div class="graph-list" id="graphList"></div>
      </section>
    </div>
  </section>
  <div class="splitter vertical workspace-side" data-resize="side" title="Resize evidence"></div>
  <aside class="side">
    <div class="section-title" id="detailTitle">Selection</div>
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
  selectedId: null,
  view: "timeline"
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

)KNL";
    html << LR"KNL(
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

let KN_PID_CONTEXT = null;

function addPidContext(map, pid, value) {
  if (!hasValue(pid) || !hasValue(value)) {
    return;
  }
  const key = String(pid);
  if (!map.has(key)) {
    map.set(key, []);
  }
  map.get(key).push(String(value));
}

function pidContextMap() {
  if (KN_PID_CONTEXT) {
    return KN_PID_CONTEXT;
  }
  KN_PID_CONTEXT = new Map();
  for (const event of KN_DATA.events) {
    if (!hasValue(event.pid)) {
      continue;
    }
    if (event.domain === "process" || event.domain === "image") {
      addPidContext(KN_PID_CONTEXT, event.pid, event.entity);
      addPidContext(KN_PID_CONTEXT, event.pid, event.summary);
      for (const image of eventImageValues(event)) {
        addPidContext(KN_PID_CONTEXT, event.pid, image);
      }
    }
  }
  return KN_PID_CONTEXT;
}

function eventSearchText(event) {
  const parts = [eventText(event)];
  const context = pidContextMap();
  for (const pid of eventPidValues(event)) {
    if (hasValue(pid) && context.has(String(pid))) {
      parts.push(context.get(String(pid)).join(" "));
    }
  }
  return lower(parts.join(" "));
}

function addPidValue(values, value) {
  if (!hasValue(value)) {
    return;
  }
  values.add(String(value));
}

function evidencePidValue(event, keys) {
  const evidence = event.evidence || {};
  for (const key of keys) {
    if (hasValue(evidence[key])) {
      return String(evidence[key]);
    }
  }
  return "";
}

function eventPidValues(event) {
  const values = new Set();
  const evidence = event.evidence || {};
  addPidValue(values, event.pid);
  addPidValue(values, event.targetPid);
  [
    "target_pid",
    "target_process_id",
    "targetprocessid",
    "victim_pid",
    "destination_pid",
    "source_pid",
    "creator_pid",
    "parent_pid",
    "ppid",
    "parent_process_id",
    "inherited_from_pid"
  ].forEach((key) => addPidValue(values, evidence[key]));
  return values;
}

function targetPidValue(event) {
  if (hasValue(event.targetPid)) {
    return String(event.targetPid);
  }
  return evidencePidValue(event, [
    "target_pid",
    "target_process_id",
    "targetprocessid",
    "victim_pid",
    "destination_pid"
  ]);
}

function sourcePidValue(event) {
  return evidencePidValue(event, ["source_pid", "creator_pid"]);
}

)KNL";
    html << LR"KNL(
function tiTaskValue(event) {
  const evidence = event.evidence || {};
  return event.action || evidence.ti_action || evidence.task_name || "";
}

function evidenceValue(event, keys) {
  const evidence = event.evidence || {};
  for (const key of keys) {
    if (evidence[key]) {
      return String(evidence[key]);
    }
  }
  return "";
}

function hasValue(value) {
  return value !== undefined && value !== null && value !== "";
}

function displayValue(value) {
  return hasValue(value) ? String(value) : "";
}

function entityCorrelationValues(event) {
  const values = new Set();
  for (const value of eventImageValues(event)) {
    values.add("image:" + value);
  }
  const pairs = [
    ["host", ["network_endpoint", "remote_host"]],
    ["dns", ["dns_query"]],
    ["file", ["file_path"]],
    ["registry", ["registry_key"]],
    ["service", ["service_name"]],
    ["task", ["scheduled_task"]],
    ["wmi", ["wmi_entity"]],
    ["memory", ["memory_address", "vad_address"]],
    ["snapshot-diff", ["snapshot_diff_subject"]]
  ];
  for (const pair of pairs) {
    const value = evidenceValue(event, pair[1]);
    if (value) {
      values.add(pair[0] + ":" + value);
    }
  }
  return values;
}

function isTiEvent(event) {
  return event.source === "ti" || event.domain === "threat-intelligence";
}

function eventHasAnyText(event, terms) {
  const text = eventSearchText(event);
  return terms.some((term) => text.includes(term));
}

function isSnapshotBaselineEvent(event) {
  return event.source === "snapshot" && event.domain === "process";
}

function isMemorySignal(event) {
  const domain = lower(event.domain);
  if (domain === "memory" || domain === "vad" || domain === "vad-dkom") {
    return true;
  }
  return eventHasAnyText(event, [
    "allocvm",
    "virtualalloc",
    "valloc",
    "protectvm",
    "virtualprotect",
    "rwx",
    "page_execute_readwrite",
    "execute_readwrite",
    "rw->rx",
    "memory_address",
    "vad_address",
    "private executable",
    "private_executable"
  ]);
}

function isRemoteThreadSignal(event) {
  const evidence = event.evidence || {};
  return evidence.remote_thread === "true" ||
    eventHasAnyText(event, ["createremotethread", "ntcreatethreadex", "remote thread"]);
}

function isCrossProcessSignal(event) {
  const evidence = event.evidence || {};
  if (evidence.cross_process_operation) {
    return true;
  }
  const sourcePid = sourcePidValue(event);
  const targetPid = targetPidValue(event) || event.pid;
  if (hasValue(sourcePid) && hasValue(targetPid) && String(sourcePid) !== String(targetPid)) {
    return true;
  }
  return eventHasAnyText(event, [
    "writevirtualmemory",
    "readvirtualmemory",
    "openprocess",
    "duplicatehandle",
    "queueuserapc",
    "setthreadcontext"
  ]);
}

function isHighRiskSignal(event) {
  const risk = riskClass(event.risk);
  return risk === "critical" || risk === "high" || risk === "warning" || risk === "medium";
}

function focusCard(level, title, subtitle) {
  return "<div class=\"focus-card " + escapeHtml(level) + "\">" +
    "<div class=\"focus-title\">" + escapeHtml(title) + "</div>" +
    "<div class=\"focus-sub\">" + escapeHtml(subtitle) + "</div></div>";
}

function renderAnalystFocus(events) {
  const container = byId("analystFocus");
  const headerWarnings = KN_DATA.header.warnings || [];
  const tiEvents = events.filter(isTiEvent);
  const memoryEvents = events.filter(isMemorySignal);
  const crossEvents = events.filter(isCrossProcessSignal);
  const remoteEvents = events.filter(isRemoteThreadSignal);
  const highRiskEvents = events.filter(isHighRiskSignal);
  const liveEvents = events.filter((event) => event.source === "kernel-live");
  const snapshotOnly = events.length > 0 && events.every(isSnapshotBaselineEvent);
  const searchText = lower(byId("search").value);
  const tiDeliveryWarning = headerWarnings.find((warning) =>
    lower(warning).includes("threat-intelligence etw is active but has received no events"));

  if (!events.length) {
    container.innerHTML = focusCard("warn", "No events match the current filters", "Clear or widen filters to inspect the embedded timeline snapshot.");
    return;
  }

  const cards = [];
  if (tiDeliveryWarning) {
    cards.push(focusCard("bad", "TI is active but silent", tiDeliveryWarning));
  }
  if (memoryEvents.length || crossEvents.length || remoteEvents.length) {
    cards.push(focusCard(
      highRiskEvents.length ? "bad" : "warn",
      "Injection-relevant activity present",
      "Memory=" + memoryEvents.length + ", cross-process=" + crossEvents.length + ", remote-thread=" + remoteEvents.length + ". Select rows to inspect the exact event evidence."));
  }
  else if (snapshotOnly) {
    cards.push(focusCard(
      "warn",
      "Baseline only",
      "Current filters only match already-running process snapshot rows. No live callback or TI activity matches this view."));
  }
  else {
    cards.push(focusCard(
      "good",
      "No injection signal in this view",
      "The current filter result has no TI memory, cross-process, or remote-thread evidence."));
  }

  if ((searchText.includes("notepad") || searchText.includes("valloc") || searchText.includes("rwx")) &&
      !memoryEvents.length &&
      !tiEvents.length) {
    cards.push(focusCard(
      "warn",
      "RWX VAlloc is not present",
      "The embedded timeline has no TI memory-allocation event for this filter. Re-run !timeline dashboard after TI receives AllocVM/VirtualAlloc evidence."));
  }

  const counts = "<div class=\"focus-card\"><div class=\"focus-title\">Current view</div>" +
    "<div class=\"focus-counts\">" +
    "<div class=\"focus-metric\"><b>" + escapeHtml(events.length) + "</b><span>events</span></div>" +
    "<div class=\"focus-metric\"><b>" + escapeHtml(tiEvents.length) + "</b><span>TI</span></div>" +
    "<div class=\"focus-metric\"><b>" + escapeHtml(liveEvents.length) + "</b><span>live</span></div>" +
    "<div class=\"focus-metric\"><b>" + escapeHtml(highRiskEvents.length) + "</b><span>risk</span></div>" +
    "</div></div>";
  cards.push(counts);
  container.innerHTML = cards.join("");
}

)KNL";
    html << LR"KNL(
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
  if (hasValue(event.pid)) {
    const name = event.entity ? " " + event.entity : "";
    return "PID " + event.pid + name;
  }
  const targetPid = targetPidValue(event);
  if (hasValue(targetPid)) {
    return "Target PID " + targetPid;
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
    for (const value of eventPidValues(event)) {
      if (!pids.has(value)) {
        pids.set(value, "PID " + value);
      }
    }
    if (hasValue(event.pid) && event.entity) {
      const pid = String(event.pid);
      const existing = pids.get(pid) || "";
      if (event.domain === "process" || existing === "PID " + pid) {
        pids.set(pid, "PID " + pid + " " + event.entity);
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
  Array.from(pids.entries()).sort((a, b) => {
    const an = Number(a[0]);
    const bn = Number(b[0]);
    if (Number.isFinite(an) && Number.isFinite(bn) && an !== bn) {
      return an - bn;
    }
    return a[0].localeCompare(b[0]);
  }).forEach((item) => option(pidFilter, item[0], item[1]));
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
    if (pid && !eventPidValues(event).has(pid)) {
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
    if (text && !eventSearchText(event).includes(text)) {
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
function timelineScale(events) {
  const times = events.map(timeValue);
  const finiteTimes = times.filter((value) => Number.isFinite(value));
  if (finiteTimes.length > 1) {
    const min = Math.min(...finiteTimes);
    const max = Math.max(...finiteTimes);
    if (max > min) {
      return { times, min, max, ranged: true };
    }
  }
  return { times, min: 0, max: 0, ranged: false };
}

function markerPosition(scale, index, total) {
  if (scale && scale.ranged) {
    const current = scale.times[index];
    if (Number.isFinite(current)) {
      return Math.max(1, Math.min(99, ((current - scale.min) * 100) / (scale.max - scale.min)));
    }
  }
  if (total <= 1) {
    return 50;
  }
  return 1 + ((index * 98) / (total - 1));
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
  renderAnalystFocus(events);

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
  for (const item of (header.warnings || [])) {
    warnings.push(item);
  }
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
  if (live.available && (live.active || live.autoDrainRunning)) {
    warnings.push("This HTML is a generated snapshot. Run !timeline dashboard again to refresh after new live events arrive.");
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
    "    Auto-drain: " + (live.autoDrainRunning ? "running" : "stopped") +
    "    View: generated snapshot; rerun !timeline dashboard to refresh";

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

function attachEventSelectionHandlers(container) {
  container.querySelectorAll("[data-event-id]").forEach((element) => {
    const selectFromElement = () => {
      const eventId = element.getAttribute("data-event-id");
      if (eventId) {
        selectEvent(eventId);
      }
    };
    element.addEventListener("click", selectFromElement);
    if (element.tagName !== "BUTTON") {
      element.setAttribute("role", "button");
      element.setAttribute("tabindex", "0");
      element.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          selectFromElement();
        }
      });
    }
  });
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
  const findings = visibleFindings(events)
    .map((finding) => ({ finding, eventId: selectableFindingEventId(finding) }))
    .filter((item) => item.eventId);
  if (!findings.length) {
    container.innerHTML = "<div class=\"empty\">No live analysis findings match the current filters.</div>";
    return;
  }

  container.innerHTML = findings.slice(0, 10).map((item) =>
    "<button class=\"finding-card\" type=\"button\" data-event-id=\"" +
    escapeHtml(item.eventId) + "\">" +
    "<div class=\"finding-title\">" + escapeHtml(item.finding.kind || "finding") + "</div>" +
    "<div class=\"finding-sub\">" + escapeHtml(item.finding.risk || "info") +
    " | " + escapeHtml(item.finding.summary || "") + "</div></button>"
  ).join("");
  attachEventSelectionHandlers(container);
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
      "<button class=\"ti-card\" type=\"button\" data-ti-task=\"" + escapeHtml(item[0]) + "\"><div class=\"ti-title\">" + escapeHtml(item[0]) + "</div>" +
      "<div class=\"ti-sub\">events=" + escapeHtml(item[1].count) +
      " critical=" + escapeHtml(item[1].critical) +
      " warning=" + escapeHtml(item[1].warning) + "</div></button>"
    ).join("");
  container.querySelectorAll("[data-ti-task]").forEach((element) => {
    element.addEventListener("click", () => {
      byId("taskFilter").value = element.getAttribute("data-ti-task") || "";
      state.selectedId = null;
      state.view = "events";
      render();
    });
  });
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
  const scale = timelineScale(events);
  let html = "<div class=\"axis\"><div></div><div class=\"axis-line\"><span>" + escapeHtml(first) + "</span><span>" + escapeHtml(last) + "</span></div></div>";

  for (const [label, items] of laneMap.entries()) {
    html += "<div class=\"lane\"><div class=\"lane-label\" title=\"" + escapeHtml(label) + "\">" + escapeHtml(label) + "</div><div class=\"lane-track\">";
    for (const item of items) {
      const event = item.event;
      const x = markerPosition(scale, item.index, events.length);
      const classes = ["marker", lower(event.domain || "event"), riskClass(event.risk)];
      if (String(event.eventId) === String(state.selectedId)) {
        classes.push("selected");
      }
      html += "<button class=\"" + classes.join(" ") + "\" style=\"left:" + x.toFixed(2) + "%\" title=\"" + escapeHtml(timeLabel(event) + " " + (event.summary || event.entity || "")) + "\" data-event-id=\"" + escapeHtml(event.eventId) + "\"></button>";
    }
    html += "</div></div>";
  }

  container.innerHTML = html;
  attachEventSelectionHandlers(container);
}

)KNL";
    html << LR"KNL(
function renderEventList(events) {
  const container = byId("eventList");
  if (!events.length) {
    container.innerHTML = "<div class=\"empty\">No events.</div>";
    return;
  }
  const header = "<div class=\"event-row header\">" +
    "<div>#</div><div>Time</div><div>Source</div><div>Domain</div>" +
    "<div>PID</div><div>TID</div><div>Target</div><div>Risk</div><div>Summary</div></div>";
  container.innerHTML = header + events.map((event) => {
    const selected = String(event.eventId) === String(state.selectedId) ? " selected" : "";
    return "<div class=\"event-row" + selected + "\" data-event-id=\"" + escapeHtml(event.eventId) + "\">" +
      "<div class=\"cell-muted\">#" + escapeHtml(event.eventId) + "</div>" +
      "<div>" + escapeHtml(timeLabel(event)) + "</div>" +
      "<div>" + escapeHtml(event.source || "") + "</div>" +
      "<div>" + escapeHtml(event.domain || "") + "</div>" +
      "<div>" + escapeHtml(displayValue(event.pid)) + "</div>" +
      "<div>" + escapeHtml(displayValue(event.tid)) + "</div>" +
      "<div>" + escapeHtml(displayValue(targetPidValue(event))) + "</div>" +
      "<div>" + escapeHtml(event.risk || "") + "</div>" +
      "<div>" + escapeHtml(event.summary || event.entity || "") + "</div>" +
      "</div>";
  }).join("");
  attachEventSelectionHandlers(container);
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
    const evidence = event.evidence || {};
    const source = event.source ? "source:" + event.source : "";
    const domain = event.domain ? "domain:" + event.domain : "";
    const process = hasValue(event.pid) ? "process:" + event.pid : "";
    const targetPid = targetPidValue(event);
    const target = hasValue(targetPid) ? "process:" + targetPid : "";
    addEdge(edges, source, domain, "source-domain", event);
    addEdge(edges, source, process || target, "source-observes-process", event);
    addEdge(edges, process, domain, event.source === "snapshot" ? "snapshot-record" : "process-domain", event);
    addEdge(edges, process, target, event.source === "ti" ? "ti-targets-process" : "targets-process", event);
    if (process && target && evidence.cross_process_operation) {
      addEdge(edges, process, target, "cross-process-" + evidence.cross_process_operation, event);
    }
    const sourcePid = sourcePidValue(event);
    if (sourcePid && process && String(sourcePid) !== String(event.pid || "")) {
      addEdge(
        edges,
        "process:" + sourcePid,
        target || process,
        "cross-process-" + (evidence.cross_process_operation || "creator"),
        event);
    }
    const parent = evidence.parent_pid || evidence.ppid || evidence.parent_process_id || evidence.inherited_from_pid;
    if (parent && process) {
      addEdge(edges, "process:" + parent, process, "parent-child", event);
    }
    for (const image of eventImageValues(event)) {
      const imageNode = "image:" + image;
      addEdge(edges, source, imageNode, "source-observes-image", event);
      addEdge(edges, process || target, imageNode, "process-loads-image", event);
    }
    const entities = [
      ["host", evidence.network_endpoint || evidence.remote_host, "process-connects-host"],
      ["dns", evidence.dns_query, "process-queries-dns"],
      ["file", evidence.file_path, "process-touches-file"],
      ["registry", evidence.registry_key, "process-modifies-registry"],
      ["service", evidence.service_name, "process-controls-service"],
      ["task", evidence.scheduled_task, "process-controls-task"],
      ["wmi", evidence.wmi_entity, "process-controls-wmi"],
      ["memory", evidence.memory_address || evidence.vad_address, "process-changes-memory"],
      ["snapshot-diff", evidence.snapshot_diff_subject || (event.source === "snapshot-diff" ? event.entity : ""), "snapshot-diff-record"]
    ];
    for (const entity of entities) {
      if (!entity[1]) {
        continue;
      }
      const node = entity[0] + ":" + entity[1];
      addEdge(edges, source, node, "source-observes-" + entity[0], event);
      addEdge(edges, process || target, node, entity[2], event);
    }
  }
  return Array.from(edges.values()).sort((a, b) => b.count - a.count || a.kind.localeCompare(b.kind)).slice(0, 80);
}

function nodeLabel(node) {
  const text = String(node || "");
  if (text.startsWith("process:")) {
    return "PID " + text.slice("process:".length);
  }
  if (text.startsWith("source:")) {
    return "Source " + text.slice("source:".length);
  }
  if (text.startsWith("domain:")) {
    return "Domain " + text.slice("domain:".length);
  }
  if (text.startsWith("image:")) {
    return "Image " + text.slice("image:".length);
  }
  return text.replace(":", " ");
}

function relationshipLabel(kind) {
  if (kind === "source-domain") {
    return "Collector produced evidence domain";
  }
  if (kind === "source-observes-process") {
    return "Collector observed process";
  }
  if (kind === "source-observes-image") {
    return "Collector observed image";
  }
  if (kind === "process-domain") {
    return "Process has event domain";
  }
  if (kind === "snapshot-record") {
    return "Existing process baseline";
  }
  if (kind === "parent-child") {
    return "Parent created child process";
  }
  if (kind === "process-loads-image") {
    return "Process loaded image/module";
  }
  if (kind === "ti-targets-process") {
    return "TI event targeted process";
  }
  if (kind === "targets-process") {
    return "Event references target process";
  }
  if (kind.startsWith("cross-process-")) {
    return "Cross-process operation";
  }
  if (kind === "process-connects-host") {
    return "Process contacted host";
  }
  if (kind === "process-queries-dns") {
    return "Process queried DNS";
  }
  if (kind === "process-touches-file") {
    return "Process touched file";
  }
  if (kind === "process-modifies-registry") {
    return "Process modified registry";
  }
  if (kind === "process-controls-service") {
    return "Process controlled service";
  }
  if (kind === "process-controls-task") {
    return "Process controlled scheduled task";
  }
  if (kind === "process-controls-wmi") {
    return "Process touched WMI persistence";
  }
  if (kind === "process-changes-memory") {
    return "Process changed executable memory";
  }
  if (kind === "snapshot-diff-record") {
    return "Snapshot diff milestone";
  }
  return kind;
}

function relationshipHint(kind) {
  if (kind === "snapshot-record") {
    return "Baseline context for processes that were already running before live callbacks started.";
  }
  if (kind === "parent-child") {
    return "Use this to follow process lineage and inherited execution context.";
  }
  if (kind === "process-loads-image") {
    return "Use this to pivot from a process to loaded DLLs, drivers, or image paths.";
  }
  if (kind === "ti-targets-process" || kind.startsWith("cross-process-")) {
    return "High-value pivot for injection, memory access, thread manipulation, or process control.";
  }
  if (kind.startsWith("process-controls") || kind === "process-modifies-registry") {
    return "Persistence or system-control pivot from process activity to OS object.";
  }
  if (kind === "process-connects-host" || kind === "process-queries-dns") {
    return "Network pivot from process activity to endpoint or DNS evidence.";
  }
  return "Aggregated relationship derived from the currently filtered timeline events.";
}

function renderGraph(events) {
  const container = byId("graphList");
  const edges = buildEdges(events);
  if (!edges.length) {
    container.innerHTML = "<div class=\"empty\">No relationships.</div>";
    return;
  }
  const explainer = "<div class=\"graph-explainer\"><b>Relationship graph</b> connects the filtered events. Click a row to inspect the latest supporting event; count shows how many events support the same relationship.</div>";
  container.innerHTML = explainer + edges.map((edge) => {
    const selected = String(edge.first) === String(state.selectedId) || String(edge.last) === String(state.selectedId) ? " selected" : "";
    const eventId = edge.last || edge.first || "";
    return "<div class=\"edge-row" + selected + "\" role=\"button\" tabindex=\"0\" data-event-id=\"" +
    escapeHtml(eventId) + "\">" +
    "<div><div class=\"edge-kind-title\">" + escapeHtml(relationshipLabel(edge.kind)) + "</div><div class=\"edge-kind-sub\">" + escapeHtml(edge.kind + " | " + relationshipHint(edge.kind)) + "</div></div>" +
    "<div class=\"node-label\">" + escapeHtml(nodeLabel(edge.from)) + "</div>" +
    "<div class=\"cell-muted\">x" + escapeHtml(edge.count) + "</div>" +
    "<div class=\"node-label\">" + escapeHtml(nodeLabel(edge.to)) + "</div>" +
    "</div>";
  }).join("");
  attachEventSelectionHandlers(container);
}

)KNL";
    html << LR"KNL(
function relatedEvents(event) {
  if (!event) {
    return [];
  }

  const pids = eventPidValues(event);
  const tid = event.tid ? String(event.tid) : "";
  const entityValues = entityCorrelationValues(event);
  const baseTime = timeValue(event);
  const windowMs = 10000;

  return KN_DATA.events.filter((candidate) => {
    if (String(candidate.eventId) === String(event.eventId)) {
      return false;
    }

    let matched = false;
    for (const value of eventPidValues(candidate)) {
      if (pids.has(value)) {
        matched = true;
        break;
      }
    }
    if (tid && candidate.tid && String(candidate.tid) === tid) {
      matched = true;
    }
    if (!matched && entityValues.size) {
      const candidateValues = entityCorrelationValues(candidate);
      for (const value of candidateValues) {
        if (entityValues.has(value)) {
          matched = true;
          break;
        }
      }
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
    "<button class=\"related-row\" type=\"button\" title=\"" +
    escapeHtml(item.summary || item.entity || "") + "\" data-event-id=\"" +
    escapeHtml(item.eventId) + "\">" +
    "<div class=\"cell-muted related-id\">#" + escapeHtml(item.eventId) + "</div>" +
    "<div class=\"related-domain\">" + escapeHtml(item.domain || "") + "</div>" +
    "<div class=\"related-summary\">" + escapeHtml(item.summary || item.entity || "") + "</div></button>"
  ).join("") + "</div>";
}

function evidencePriority(key) {
  const priorities = [
    "memory_address",
    "allocation_size",
    "protection",
    "allocation_type",
    "cross_process_operation",
    "source_pid",
    "target_pid",
    "source_tid",
    "target_tid",
    "desired_access",
    "granted_access",
    "start_address",
    "object_name",
    "section_name",
    "image_path",
    "target_image",
    "classification",
    "classification_reason",
    "ti_action"
  ];
  const index = priorities.indexOf(String(key || ""));
  if (index >= 0) {
    return index;
  }
  if (String(key || "").startsWith("payload.")) {
    return 100;
  }
  if (String(key || "").startsWith("payload_type.")) {
    return 200;
  }
  return 300;
}

function renderEvidenceFields(event) {
  const evidence = event.evidence || {};
  const entries = Object.keys(evidence)
    .sort((a, b) => evidencePriority(a) - evidencePriority(b) || a.localeCompare(b))
    .map((key) => [key, evidence[key]]);
  if (!entries.length) {
    return "<h3>Evidence Fields</h3><div class=\"empty\">No key/value evidence.</div>";
  }

  return "<h3>Evidence Fields</h3><div class=\"evidence-table\">" + entries.map((row) =>
    "<div class=\"evidence-row\" title=\"" + escapeHtml(row[0] + "=" + row[1]) + "\">" +
    "<div class=\"evidence-key\">" + escapeHtml(row[0]) + "</div>" +
    "<div class=\"evidence-value\">" + escapeHtml(row[1]) + "</div></div>"
  ).join("") + "</div>";
}

function renderDetail(event) {
  const container = byId("detail");
  if (!event) {
    container.innerHTML = "<div class=\"empty\">Select a timeline marker or event row.</div>";
    return;
  }
  const evidence = event.evidence || {};
  const rows = [
    ["Event", "#" + event.eventId],
    ["Time", timeLabel(event)],
    ["Source", event.source],
    ["Domain", event.domain],
    ["Action", event.action],
    ["PID", displayValue(event.pid)],
    ["TID", displayValue(event.tid)],
    ["Target PID", displayValue(targetPidValue(event))],
    ["Memory Address", displayValue(evidence.memory_address || evidence.vad_address)],
    ["Allocation Size", displayValue(evidence.allocation_size || evidence.region_size)],
    ["Protection", displayValue(evidence.protection || evidence.protect)],
    ["Access", displayValue(evidence.desired_access || evidence.granted_access)],
    ["Start Address", displayValue(evidence.start_address)],
    ["Creator PID", displayValue(evidence.creator_pid || evidence.source_pid)],
    ["Creator TID", displayValue(evidence.creator_tid)],
    ["Remote Thread", evidence.remote_thread === "true" ? "yes" : ""],
    ["Risk", event.risk || ""],
    ["Confidence", event.confidence || ""],
    ["Entity", event.entity || ""],
    ["Summary", event.summary || ""]
  ];
  container.innerHTML = "<h2>" + escapeHtml(event.summary || event.entity || "Event #" + event.eventId) + "</h2>" +
    "<div class=\"kv\">" + rows.map((row) => "<div class=\"k\">" + escapeHtml(row[0]) + "</div><div>" + escapeHtml(row[1]) + "</div>").join("") + "</div>" +
    renderEvidenceFields(event) +
    renderRelatedEvents(event) +
    "<pre>" + escapeHtml(JSON.stringify(event, null, 2)) + "</pre>";
  attachEventSelectionHandlers(container);
}

function selectEvent(eventId) {
  state.selectedId = eventId;
  render();
}

function viewModeInfo(mode) {
  const modes = {
    timeline: {
      title: "Timeline",
      hint: "lanes, filtered events, and relationships stay linked",
      detail: "Selection"
    },
    events: {
      title: "Events",
      hint: "filtered event table; select a row to inspect evidence",
      detail: "Event Evidence"
    },
    relationships: {
      title: "Relationships",
      hint: "click an edge to inspect the latest supporting event",
      detail: "Relationship Evidence"
    },
    evidence: {
      title: "Evidence",
      hint: "raw selected event evidence",
      detail: "Evidence"
    }
  };
  return modes[mode] || modes.timeline;
}

function applyDashboardMode() {
  const mode = state.view || "timeline";
  const info = viewModeInfo(mode);
  const app = byId("appWindow");
  app.classList.remove("mode-timeline", "mode-events", "mode-relationships", "mode-evidence");
  app.classList.add("mode-" + mode);

  document.querySelectorAll("[data-view]").forEach((item) => {
    const active = item.getAttribute("data-view") === mode;
    item.classList.toggle("active", active);
    item.classList.toggle("primary", active && item.classList.contains("tool-pill"));
  });

  byId("workspaceTitle").textContent = info.title;
  byId("workspaceHint").textContent = info.hint;
  byId("detailTitle").textContent = info.detail;
}

function setDashboardMode(mode) {
  state.view = mode || "timeline";
  render();
}

)KNL";
    html << LR"KNL(
function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function setRootPixelVar(name, value) {
  document.documentElement.style.setProperty(name, Math.round(value) + "px");
}

function resizeValue(kind, event) {
  const layout = document.querySelector(".layout");
  const panels = document.querySelector(".panels");
  const timeline = byId("timeline");

  if (kind === "left" && layout) {
    const rect = layout.getBoundingClientRect();
    const width = clamp(event.clientX - rect.left, 260, Math.max(300, rect.width - 760));
    setRootPixelVar("--left-width", width);
  }
  else if (kind === "side" && layout) {
    const rect = layout.getBoundingClientRect();
    const width = clamp(rect.right - event.clientX, 300, Math.max(340, rect.width - 760));
    setRootPixelVar("--side-width", width);
  }
  else if (kind === "timeline" && timeline) {
    const rect = timeline.getBoundingClientRect();
    const height = clamp(event.clientY - rect.top, 180, Math.max(220, window.innerHeight - 360));
    setRootPixelVar("--timeline-height", height);
  }
  else if (kind === "relationships" && panels) {
    const rect = panels.getBoundingClientRect();
    const width = clamp(rect.right - event.clientX, 280, Math.max(320, rect.width - 420));
    setRootPixelVar("--relationships-width", width);
  }
}

function resetResizeValue(kind) {
  const root = document.documentElement.style;
  if (kind === "left") {
    root.removeProperty("--left-width");
  }
  else if (kind === "side") {
    root.removeProperty("--side-width");
  }
  else if (kind === "timeline") {
    root.removeProperty("--timeline-height");
  }
  else if (kind === "relationships") {
    root.removeProperty("--relationships-width");
  }
}

function initSplitters() {
  document.querySelectorAll("[data-resize]").forEach((splitter) => {
    const kind = splitter.getAttribute("data-resize");
    splitter.addEventListener("pointerdown", (event) => {
      if (event.button !== 0) {
        return;
      }
      event.preventDefault();
      splitter.classList.add("dragging");
      document.body.classList.add("resizing");
      splitter.setPointerCapture(event.pointerId);
      const move = (moveEvent) => resizeValue(kind, moveEvent);
      const stop = () => {
        splitter.classList.remove("dragging");
        document.body.classList.remove("resizing");
        splitter.removeEventListener("pointermove", move);
        splitter.removeEventListener("pointerup", stop);
        splitter.removeEventListener("pointercancel", stop);
      };
      splitter.addEventListener("pointermove", move);
      splitter.addEventListener("pointerup", stop);
      splitter.addEventListener("pointercancel", stop);
    });
    splitter.addEventListener("dblclick", () => resetResizeValue(kind));
  });
}

function render() {
  const events = filteredEvents();
  if (state.view === "evidence" && !state.selectedId && events.length) {
    state.selectedId = String(events[0].eventId);
  }
  renderSummary(events);
  renderTimeline(events);
  renderEventList(events);
  renderGraph(events);
  const selected = state.selectedId ?
    KN_DATA.events.find((item) => String(item.eventId) === String(state.selectedId)) :
    null;
  renderDetail(selected || null);
  applyDashboardMode();
}

populateFilters();
byId("exportJsonl").addEventListener("click", exportJsonl);
document.querySelectorAll("[data-view]").forEach((element) => {
  element.addEventListener("click", () => setDashboardMode(element.getAttribute("data-view")));
});
initSplitters();
["search", "sourceFilter", "domainFilter", "pidFilter", "imageFilter", "taskFilter", "riskFilter"].forEach((id) => {
  byId(id).addEventListener("input", () => {
    state.selectedId = null;
    render();
  });
});
render();
</script>
</body>
</html>
)KNL";

    return html.str();
}
