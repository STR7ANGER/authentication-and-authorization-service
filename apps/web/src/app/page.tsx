"use client";
import { useAuthStore } from "../store";
export default function Page() {
  const { revealPassword, togglePassword } = useAuthStore();
  return (
    <main className="shell">
      <section className="story">
        <div className="brand">
          <span>A</span>
          <strong>Aegis</strong>
        </div>
        <div className="copy">
          <p>IDENTITY INFRASTRUCTURE</p>
          <h1>
            Secure access,
            <br />
            without the drag.
          </h1>
          <blockquote>
            “One boundary for every user, session, service, and organization.”
          </blockquote>
        </div>
        <div className="signals">
          <div>
            <i />
            Ed25519 signed
          </div>
          <div>
            <i />
            MFA ready
          </div>
          <div>
            <i />
            Tenant isolated
          </div>
        </div>
      </section>
      <section className="auth">
        <div className="card">
          <div className="card-head">
            <span className="lock">⌁</span>
            <p>WELCOME BACK</p>
            <h2>Sign in to your workspace</h2>
            <span>
              Use your verified account. Suspicious sessions require step-up
              authentication.
            </span>
          </div>
          <div className="providers">
            <button type="button">G&nbsp;&nbsp; Continue with Google</button>
            <button type="button">◈&nbsp;&nbsp; Continue with GitHub</button>
          </div>
          <div className="divider">
            <span>or continue with email</span>
          </div>
          <form onSubmit={(event) => event.preventDefault()}>
            <label htmlFor="email">Work email</label>
            <input
              id="email"
              name="email"
              type="email"
              autoComplete="email"
              placeholder="you@company.com"
              required
            />
            <label htmlFor="password">Password</label>
            <div className="password">
              <input
                id="password"
                name="password"
                type={revealPassword ? "text" : "password"}
                autoComplete="current-password"
                placeholder="At least 12 characters"
                minLength={12}
                required
              />
              <button
                type="button"
                onClick={togglePassword}
                aria-label={revealPassword ? "Hide password" : "Show password"}
              >
                {revealPassword ? "Hide" : "Show"}
              </button>
            </div>
            <div className="form-meta">
              <label className="remember">
                <input type="checkbox" /> Remember this device
              </label>
              <a href="#reset">Forgot password?</a>
            </div>
            <button className="submit" type="submit">
              Continue securely <span>→</span>
            </button>
          </form>
          <p className="signup">
            New to Aegis? <a href="#signup">Create an account</a>
          </p>
        </div>
        <footer>
          <span>Protected by adaptive risk checks</span>
          <nav aria-label="Legal">
            <a href="#privacy">Privacy</a>
            <a href="#terms">Terms</a>
            <a href="#status">Status</a>
          </nav>
        </footer>
        <a className="demo-link" href="/admin">
          Open demo security console →
        </a>
      </section>
    </main>
  );
}
