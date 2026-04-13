<h1>XWA-SEC: UI Architecture & Folder Structure</h1>

<p>To scale XWA-SEC into a comprehensive cybersecurity platform (capable of handling native link discovery, topological graphs, vulnerability counting, and automated injections), the Angular frontend must immediately migrate from a flat schema to a <strong>Feature-Driven Architecture</strong>. This guarantees infinite scalability, separation of concerns, and the ability to implement <em>lazy-loading</em> so as not to saturate the web browser under the <em>Nothing Design</em> scheme.</p>

<hr>

<h2>1. High-Level Directory Overview</h2>

<pre><code>frontend/src/app/
├── core/         # Singleton Services, Interceptors, and Guards.
├── shared/       # "Dumb" UI Components (Nothing Design), Pipes, Directives.
├── features/     # Isolated business domains (The pillars of cybersecurity).
├── layouts/      # Global wrapper views (Sidebars, Menus, Navbars).
└── app.routes.ts # Asynchronous routing rules (Lazy Loading).
</code></pre>

<hr>

<h2>2. Folder Anatomy</h2>

<h3>2.1 The Core: <code>core/</code></h3>
<p>Contains heavy logic that is instantiated only once. No visual components should exist here under any circumstances.</p>
<ul>
    <li><code>core/services/websocket.service.ts</code>: Maintains and monitors bidirectional connections for stdout commands incoming from FastAPI.</li>
    <li><code>core/services/api.service.ts</code>: Encapsulates the main HTTP client.</li>
    <li><code>core/interceptors/auth.interceptor.ts</code>: Injects JWT tokens to secure closed API routes for authorized users.</li>
    <li><code>core/guards/auth.guard.ts</code>: Protects browser routes (e.g., redirecting if not an admin).</li>
</ul>

<h3>2.2 Visual Philosophy: <code>shared/</code></h3>
<p>The home of the <strong>Nothing Design System</strong> ecosystem. Contains everything reusable, "dumb" (components without dependency injection to HTTP services). They are dedicated strictly to <em>rendering data injected via Inputs</em>.</p>
<ul>
    <li><code>shared/components/nothing-terminal/</code>: The final UI of the UNIX-like terminal console in pure phosphor code text.</li>
    <li><code>shared/components/metric-card/</code>: Asymmetrical boxes displaying numeric OLED counters.</li>
    <li><code>shared/components/status-badge/</code>: Luminous indicators (Red, Amber, or Green).</li>
    <li><code>shared/styles/</code>: Global SCSS variables, typography tokens, and <em>mixins</em>.</li>
</ul>

<h3>2.3 The Operating System: <code>features/</code></h3>
<p>Where the logic and cybersecurity magic reside. Each "feature" inside this folder must behave like an independent micro-app, being autonomous and linked only by its main route.</p>

<h4>A. <code>features/scanner/</code></h4>
<p>Responsible for managing active infrastructure and port scanning (Nmap, Ping).</p>
<ul>
    <li><code>pages/active-scan-dashboard/</code>: Dashboard aggregating the terminal and IP configuration inputs.</li>
    <li><code>scanner.service.ts</code>: Isolated service managing the ongoing active websocket state.</li>
</ul>

<h4>B. <code>features/recon/</code></h4>
<p>For aggressive logic involving domain discovery, fuzzing, and headless browsers.</p>
<ul>
    <li><code>components/network-graph/</code>: Topological visualization tool (tree structure) linking discovered links and URIs from the Spidering phase.</li>
    <li><code>components/headless-gallery/</code>: Visual module in charge of paginating and displaying <em>Screenshots</em> of targets retrieved using Puppeteer or Playwright.</li>
    <li><code>pages/recon-dashboard/</code></li>
</ul>

<h4>C. <code>features/vulnerabilities/</code></h4>
<p>In charge of listing and consolidating all critical findings (CVEs, XSS flaws, SQL Injections dictated by SQLMap).</p>
<ul>
    <li><code>components/finding-data-grid/</code>: An ultra-high visual density data grid (Monospace font mandatory).</li>
    <li><code>components/severity-chart/</code>: Metrics to isolate critical severities in informational cards.</li>
    <li><code>pages/findings-report/</code></li>
</ul>

<h4>D. <code>features/automation/</code></h4>
<p>Background tasks planner and schedule manager (Workers / Celery Beat).</p>
<ul>
    <li><code>components/cron-builder/</code></li>
    <li><code>pages/scheduler/</code></li>
</ul>

<hr>

<h2>3. High-Stress State Management</h2>
<p>In deep security analysis where hundreds of URLs or endpoints are discovered per second, "prop-drilling" would destroy the application's rendering performance. To mitigate stagnant visualizations, the component tree must employ a <strong>Signal-based State Management</strong> strategy using native Angular 17 Signals. Child routes will subscribe to these <em>signals</em>, emitting precise reactivity (e.g., a rapidly incrementing port counter) without re-rendering the entire parent container (like a half-built topological graph).</p> 

<hr>
<p><i>Base architecture designed to structure the XWA-SEC cybersecurity project at an enterprise-grade level.</i></p>
