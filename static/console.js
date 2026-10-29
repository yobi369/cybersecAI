(() => {
  let token = null;
  const $ = id => document.getElementById(id);
  const setStatus = (id, message) => { $(id).textContent = message; };
  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (options.body) headers.set("Content-Type", "application/json");
    if (token) headers.set("Authorization", "Bearer " + token);
    const response = await fetch(path, {...options, headers});
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.message || body.error || ("Request failed: " + response.status));
    return body;
  }
  function requireAuth() { if (!token) throw new Error("Sign in first."); }
  function renderEvents(items) {
    const root = $("events"); root.replaceChildren();
    if (!items.length) { root.textContent = "No events recorded yet."; return; }
    for (const item of items) {
      const el = document.createElement("article"); el.className = "event";
      const title = document.createElement("strong"); title.textContent = item.title;
      const meta = document.createElement("div"); meta.className = "muted";
      meta.textContent = item.source + " · " + item.event_time;
      const pills = document.createElement("div");
      for (const value of [item.severity, item.status]) { const pill = document.createElement("span"); pill.className = "pill"; pill.textContent = value; pills.append(pill); }
      const desc = document.createElement("p"); desc.className = "muted"; desc.textContent = item.description;
      el.append(title, meta, pills, desc);
      if (["admin","analyst"].includes(window.currentRole) && !["resolved","false_positive"].includes(item.status)) {
        const btn = document.createElement("button"); btn.className = "secondary"; btn.textContent = "Mark investigating";
        btn.addEventListener("click", async () => { try { await api("/api/v1/events/" + item.id, {method:"PATCH",body:JSON.stringify({status:"investigating"})}); await loadEvents(); } catch(e) { setStatus("service-status",e.message); } });
        el.append(btn);
      }
      root.append(el);
    }
  }
  async function loadEvents() { requireAuth(); const data = await api("/api/v1/events?limit=100"); renderEvents(data.items); setStatus("service-status", data.total + " event(s) available."); }
  $("login").addEventListener("click", async () => {
    try {
      const data = await api("/api/v1/auth/login", {method:"POST",body:JSON.stringify({username:$("username").value,password:$("password").value})});
      token = data.access_token; window.currentRole = data.user.role;
      $("password").value = ""; $("session").textContent = "Signed in as " + data.user.username + " (" + data.user.role + "). Token expires in " + data.expires_in + " seconds.";
      setStatus("auth-status","Authentication successful."); await loadEvents();
    } catch(e) { token = null; setStatus("auth-status",e.message); }
  });
  $("logout").addEventListener("click", () => { token = null; window.currentRole = null; $("session").textContent = "Session cleared."; $("events").textContent = "Sign in and refresh to load events."; setStatus("auth-status","Local session cleared."); });
  $("health").addEventListener("click", async () => { try { const data = await api("/health"); setStatus("service-status","API status: " + data.status + " · " + data.timestamp); } catch(e) { setStatus("service-status",e.message); } });
  $("refresh").addEventListener("click", async () => { try { await loadEvents(); } catch(e) { setStatus("service-status",e.message); } });
  $("analyze").addEventListener("click", async () => {
    try {
      requireAuth(); const data = await api("/api/v1/analyze",{method:"POST",body:JSON.stringify({logs:$("logs").value})});
      setStatus("analysis-status",data.finding_count + " indicator(s) found across " + data.lines_processed + " line(s). " + data.disclaimer);
      const root=$("findings"); root.replaceChildren();
      for (const f of data.findings) {
        const el=document.createElement("article"); el.className="finding "+f.severity;
        const title=document.createElement("strong"); title.textContent=f.rule_id+" · "+f.title+" · "+f.severity;
        const evidence=document.createElement("p"); evidence.textContent="Line "+f.line+": "+f.evidence;
        const guidance=document.createElement("p"); guidance.textContent=f.guidance;
        el.append(title,evidence,guidance); root.append(el);
      }
      if (!data.finding_count) root.textContent="No configured patterns matched. This does not establish that the logs are safe.";
    } catch(e) { setStatus("analysis-status",e.message); }
  });
  $("create-event").addEventListener("click", async () => {
    try {
      requireAuth(); const data=await api("/api/v1/events",{method:"POST",body:JSON.stringify({
        title:$("event-title").value,source:$("event-source").value,severity:$("severity").value,description:$("description").value
      })});
      setStatus("event-status","Event #"+data.id+" saved."); $("event-title").value=""; $("event-source").value=""; $("description").value=""; await loadEvents();
    } catch(e) { setStatus("event-status",e.message); }
  });
})();
