/* The Playground — sandbox mode's panel (2026-10-21).
 *
 * Reads GET /api/playground. In sandbox mode it marks the page (<html data-sandbox="on">,
 * which index.html turns violet), shows a fixed SANDBOX badge and draws the panel into
 * #playground-root: four test buttons (a listed threat of each kind, sent through the real
 * check), this node's own tests, and the graph's sandbox lane (what every member shared).
 * Out of sandbox mode it removes all of that, so the page is the ordinary one again.
 *
 * Every POST carries the dashboard's session token (X-Blackbox-Token from /api/session),
 * like index.html's own postJSON. Text from the node is written with textContent only.
 */
(function () {
  "use strict";
  var POLL_MS = 5000;
  var KIND_LABELS = { "package": "Malware package", "domain": "Malicious domain", "ip": "C2 server address", "url": "Payload link" };
  var root = null, badge = null, timer = null, busy = "", firstSeen = {}, lastResult = null, lastError = "";

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = String(text);
    return node;
  }

  function token() {
    return fetch("/api/session", { cache: "no-store" }).then(function (r) {
      if (!r.ok) throw new Error("This dashboard is opened read-only here; open it on the machine itself to run tests.");
      return r.json();
    }).then(function (j) { return (j && j.token) || ""; });
  }

  function setSandboxLook(on) {
    var html = document.documentElement;
    if (on) html.setAttribute("data-sandbox", "on"); else html.removeAttribute("data-sandbox");
    if (on && !badge) {
      badge = el("div", "pg-badge", "SANDBOX MODE");
      badge.setAttribute("role", "status");
      badge.title = "Shares go to the sandbox lane only. Switch off in Settings → Community sharing.";
      document.body.appendChild(badge);
    } else if (!on && badge) {
      badge.remove();
      badge = null;
    }
  }

  function listOrEmpty(items, empty, render) {
    var list = el("ul", "pg-list");
    if (!items.length) { list.appendChild(el("li", "pg-meta", empty)); return list; }
    items.forEach(function (item) { list.appendChild(render(item)); });
    return list;
  }

  function testRow(row) {
    var f = row.finding || row || {};
    var li = el("li");
    li.appendChild(el("div", "pg-id", f.identifier || row.identifier || "—"));
    var when = row.iso || (row.ts ? new Date(row.ts * 1000).toISOString() : "");
    li.appendChild(el("div", "pg-meta", [f.severity || "", when.replace("T", " ").replace("Z", " UTC")].filter(Boolean).join(" · ")));
    return li;
  }

  function laneRow(entry) {
    var key = entry.identifier + "|" + entry.reporter;
    if (!firstSeen[key]) firstSeen[key] = new Date();
    var li = el("li");
    li.appendChild(el("div", "pg-id", entry.identifier));
    var meta = el("div", "pg-meta");
    meta.appendChild(el("span", entry.mine ? "pg-mine" : "", entry.mine ? "this node" : "member " + entry.reporter.slice(0, 10) + "…"));
    meta.appendChild(document.createTextNode(" · " + entry.severity + " · seen here " + firstSeen[key].toLocaleTimeString()));
    li.appendChild(meta);
    return li;
  }

  function draw(state) {
    root.innerHTML = "";
    var panel = el("section", "pg-panel");
    panel.setAttribute("aria-label", "Sandbox Playground");
    panel.appendChild(el("h2", "", "Playground · sandbox mode"));
    panel.appendChild(el("p", "", "Send a threat already listed in this node's verified rules through the real check. " +
      "The finding and its share stay in the sandbox: the share goes to the graph's sandbox lane, which no rule or flag on any " +
      "machine reads, and nothing lands in your real findings. Members who joined the same graph see it below within seconds."));
    if (!state.sharing) panel.appendChild(el("p", "pg-error", "Community sharing is off. Turn it on in Settings to run tests (they stay in the sandbox lane)."));
    var kinds = el("div", "pg-kinds");
    (state.kinds || []).forEach(function (kind) {
      var button = el("button", "", busy === kind ? "Asking Blackbox… (up to 90 s)" : "Send: " + (KIND_LABELS[kind] || kind));
      button.type = "button";
      button.disabled = !!busy || !state.sharing;
      button.addEventListener("click", function () { run(kind); });
      kinds.appendChild(button);
    });
    panel.appendChild(kinds);
    if (lastError) panel.appendChild(el("p", "pg-error", lastError));
    if (lastResult) {
      panel.appendChild(el("p", "", "Last test: " + lastResult.decision.toUpperCase() + " " + lastResult.identifier +
        " in " + (lastResult.check_ms / 1000).toFixed(1) + " s · share " + (lastResult.shared || "not sent")));
    }
    var cols = el("div", "pg-cols");
    var mine = el("div");
    mine.appendChild(el("h3", "", "This node's tests"));
    mine.appendChild(listOrEmpty(state.tests || [], "No tests yet.", testRow));
    var lane = el("div");
    var view = state.lane || {};
    lane.appendChild(el("h3", "", "Sandbox lane · " + (view.agents || 0) + " agent(s) heard"));
    lane.appendChild(view.readable === false
      ? el("p", "pg-meta", "The local node did not answer; trying again.")
      : listOrEmpty(view.entries || [], "Nothing in the sandbox lane yet.", laneRow));
    cols.appendChild(mine);
    cols.appendChild(lane);
    panel.appendChild(cols);
    root.appendChild(panel);
  }

  function refresh() {
    if (!root) return Promise.resolve();
    return fetch("/api/playground", { cache: "no-store" }).then(function (r) { return r.json(); }).then(function (state) {
      setSandboxLook(!!state.sandbox);
      root.hidden = !state.sandbox;
      if (state.sandbox) draw(state); else root.innerHTML = "";
    }).catch(function () { /* the dashboard's own banner reports a down service */ });
  }

  function run(kind) {
    busy = kind; lastError = "";
    refresh();
    token().then(function (tok) {
      return fetch("/api/playground/run", {
        method: "POST", cache: "no-store",
        headers: { "Content-Type": "application/json", "Accept": "application/json", "X-Blackbox-Token": tok },
        body: JSON.stringify({ kind: kind })
      });
    }).then(function (r) { return r.json(); }).then(function (body) {
      if (body && body.ok) lastResult = body.result; else lastError = (body && body.error) || "The test did not run.";
    }).catch(function (err) { lastError = err && err.message ? err.message : "The test did not run."; })
      .then(function () { busy = ""; return refresh(); });
  }

  function start() {
    root = document.getElementById("playground-root");
    if (!root) return;
    refresh();
    timer = window.setInterval(function () { if (!document.hidden && !busy) refresh(); }, POLL_MS);
  }

  window.blackboxPlayground = { refresh: refresh };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
