const events = [
  {
    type: "New device challenge",
    user: "ana@northstar.dev",
    risk: "72 · High",
  },
  { type: "API key rotated", user: "Deploy workflow", risk: "Expected" },
  { type: "Member invited", user: "marco@northstar.dev", risk: "Low" },
];

export default function AdminPage() {
  return (
    <main className="console-shell">
      <aside className="console-nav">
        <a className="brand" href="/">
          <span>A</span>
          <strong>Aegis</strong>
        </a>
        <nav aria-label="Console">
          <a className="active" href="#overview">
            Overview
          </a>
          <a href="#people">People</a>
          <a href="#sessions">Sessions</a>
          <a href="#keys">API keys</a>
          <a href="#audit">Audit log</a>
        </nav>
        <div className="console-user">
          <b>AM</b>
          <span>
            Admin workspace<small>Owner</small>
          </span>
        </div>
      </aside>
      <section className="console-main" id="overview">
        <header className="console-head">
          <div>
            <p>SECURITY CONSOLE</p>
            <h1>Good morning, Aditya.</h1>
            <span>Your identity perimeter is healthy.</span>
          </div>
          <button type="button">Invite member</button>
        </header>
        <div className="health">
          <i>✓</i>
          <div>
            <strong>All systems protected</strong>
            <span>
              Signing key active · Webhooks delivering · No critical alerts
            </span>
          </div>
          <b>LIVE</b>
        </div>
        <div className="stat-grid">
          <article>
            <span>Active users</span>
            <strong>2,408</strong>
            <small>+8.4% this month</small>
          </article>
          <article>
            <span>Live sessions</span>
            <strong>1,176</strong>
            <small>Across 34 countries</small>
          </article>
          <article>
            <span>MFA coverage</span>
            <strong>84.7%</strong>
            <small>12 users remaining</small>
          </article>
          <article>
            <span>Blocked risks</span>
            <strong>28</strong>
            <small>Last 30 days</small>
          </article>
        </div>
        <div className="console-grid">
          <article className="activity" id="audit">
            <div className="panel-title">
              <div>
                <span>Recent security activity</span>
                <small>Risk events and administrative changes</small>
              </div>
              <a href="#all">View all →</a>
            </div>
            {events.map((event) => (
              <div className="event" key={event.type}>
                <i />
                <span>
                  <strong>{event.type}</strong>
                  <small>{event.user}</small>
                </span>
                <b>{event.risk}</b>
              </div>
            ))}
          </article>
          <article className="quick" id="keys">
            <div className="panel-title">
              <div>
                <span>Quick controls</span>
                <small>Operator-only actions</small>
              </div>
            </div>
            <button type="button">
              Rotate signing key <b>→</b>
            </button>
            <button type="button">
              Review active sessions <b>→</b>
            </button>
            <button type="button">
              Export audit events <b>→</b>
            </button>
          </article>
        </div>
      </section>
    </main>
  );
}
