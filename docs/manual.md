<h1>XWA-SEC Application Manual</h1>

<p>This document details the necessary steps to run the application in a local development environment and provides the architectural configuration required for a production deployment.</p>

<hr>

<h2>1. Local Development Execution</h2>

<p>The local environment is configured with Hot Module Replacement (HMR) for both the Angular frontend and the FastAPI backend. Changes made to the source files will be reflected immediately without the need to rebuild the containers.</p>

<h3>1.1 Prerequisites</h3>
<ul>
    <li>Docker Engine installed and running.</li>
    <li>Docker Compose installed.</li>
</ul>

<h3>1.2 Startup Instructions</h3>
<ol>
    <li>Open a terminal and navigate to the project root directory: <code>/xwa-sec</code></li>
    <li>Execute the following command to build and launch all orchestrated containers in detached mode:</li>
</ol>

<pre><code>docker compose up -d --build</code></pre>

<h3>1.3 Running Locally (Without Docker) / IDE Setup</h3>
<p>If you wish to run the Angular app manually or simply want your IDE (like VSCode) to stop highlighting TypeScript errors, you must install the Node dependencies locally on your host machine:</p>
<ol>
    <li>Navigate to the frontend folder: <code>cd frontend/</code></li>
    <li>Install packages: <code>npm install</code></li>
    <li>To spin up the web server manually without Docker: <code>npm run start</code> (The frontend will boot up at <code>localhost:4200</code>)</li>
</ol>

<h3>1.4 Accessing the Services</h3>
<ul>
    <li><strong>Frontend (Angular UI):</strong> Accessible at <code>http://localhost:4200</code></li>
    <li><strong>Backend API (FastAPI):</strong> Accessible at <code>http://localhost:8000/docs</code> (Swagger UI)</li>
</ul>

<hr>

<h2>2. Production Configuration</h2>

<p>For a production environment, the development configuration must be modified to ensure security, performance, and stability. The following steps outline the required changes to transition the architecture.</p>

<h3>2.1 Frontend Optimization (Nginx)</h3>
<p>In production, the Angular development server must be replaced by a compiled static build served via a high-performance web server like Nginx.</p>
<ul>
    <li>Create a <code>Dockerfile.prod</code> inside the frontend directory implementing a multi-stage build.</li>
    <li>Stage 1: Build the Angular project using <code>npx @angular/cli build --configuration production</code>.</li>
    <li>Stage 2: Copy the built files from <code>/dist/xwa-sec-web/browser</code> to the Nginx static serving directory <code>/usr/share/nginx/html</code>.</li>
    <li>Update the <code>docker-compose.yml</code> frontend service to use <code>Dockerfile.prod</code> and expose port <code>80</code> (or <code>443</code> for HTTPS) instead of <code>4200</code>.</li>
    <li>Remove the local volumes from the frontend service in <code>docker-compose.yml</code>.</li>
</ul>

<h3>2.2 Backend API Security and Performance</h3>
<p>The FastAPI application must be optimized for production workloads.</p>
<ul>
    <li>Update the backend <code>Dockerfile</code> command to use Gunicorn with Uvicorn workers instead of running the Uvicorn shell script directly. Example: <code>CMD ["gunicorn", "app.main:app", "--workers", "4", "--worker-class", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000"]</code></li>
    <li>Remove the <code>--reload</code> flag.</li>
    <li>Remove the development volumes from the backend service in <code>docker-compose.yml</code> to prevent source code manipulation from the host.</li>
    <li>Configure the CORS middleware in <code>main.py</code>. Replace <code>allow_origins=["*"]</code> with the specific production domain.</li>
</ul>

<h3>2.3 Database and Secrets Management</h3>
<p>Security is paramount for the persistent layers.</p>
<ul>
    <li>Do not expose the Redis and PostgreSQL ports to the public network. Remove the <code>ports:</code> binding for both services in <code>docker-compose.yml</code> so they remain isolated within the internal Docker network.</li>
    <li>Migrate hardcoded credentials (such as <code>DB_USER</code> and <code>DB_PASS</code>) to Docker Secrets or an external secret manager (e.g., AWS Secrets Manager, HashiCorp Vault). Use an injected <code>.env</code> file in the interim.</li>
    <li>Ensure the PostgreSQL database volume is properly backed up using regular automated cron tasks attached to the persistence layer.</li>
</ul>

<hr>

<p><i>End of Manual.</i></p>
