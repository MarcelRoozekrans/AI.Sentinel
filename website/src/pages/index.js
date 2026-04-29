import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import styles from './index.module.css';

function HeroBanner() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <header className={clsx('hero', styles.heroBanner)}>
      <div className="container">
        <img src="img/logo.svg" alt="AI.Sentinel" className={styles.heroLogo} />
        <h1 className="hero__title">{siteConfig.title}</h1>
        <p className="hero__subtitle">{siteConfig.tagline}</p>
        <div className={styles.buttons}>
          <Link className="button button--secondary button--lg" to="/docs/getting-started/quick-start">
            Get Started
          </Link>
          <Link className="button button--outline button--lg" to="/docs/intro" style={{marginLeft: '1rem', color: 'white', borderColor: 'white'}}>
            Learn More
          </Link>
        </div>
      </div>
    </header>
  );
}

const features = [
  {
    title: '51 detectors out of the box',
    description: 'Prompt injection, jailbreaks, PII / credential leakage, hallucinated citations, repetition loops — security, hallucination, and operational coverage from day one.',
  },
  {
    title: 'Drop-in IChatClient middleware',
    description: 'Wraps any Microsoft.Extensions.AI client. Two pipeline passes per call (prompt + response). No provider-specific code.',
  },
  {
    title: 'Custom detector SDK',
    description: 'Write your own detector by implementing IDetector. Test it with DetectorTestBuilder + FakeEmbeddingGenerator — no API keys, deterministic results.',
  },
  {
    title: 'Embedded dashboard',
    description: 'Live audit feed, threat scores, severity timeline. HTMX + Server-Sent Events — no JS framework.',
  },
  {
    title: 'Per-pipeline configuration',
    description: 'Multiple isolated pipelines under string names — multi-endpoint, dev/staging/prod tiers. Per-detector tuning via opts.Configure<T>.',
  },
  {
    title: 'Audit forwarders',
    description: 'NDJSON file, SQLite, Azure Sentinel, OpenTelemetry — pick one or several. Hash-chained audit ensures tampering is detectable.',
  },
];

function Feature({title, description}) {
  return (
    <div className={clsx('col col--4')}>
      <div className="padding-horiz--md padding-vert--lg">
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
    </div>
  );
}

function FeaturesSection() {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {features.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}

function CodeExample() {
  return (
    <section className={styles.codeExample}>
      <div className="container">
        <h2 style={{textAlign: 'center', marginBottom: '2rem'}}>One line wires the middleware</h2>
        <div className="row">
          <div className="col col--6">
            <h3>Configure</h3>
            <pre className={styles.codeBlock}>
{`builder.Services.AddAISentinel(opts =>
{
    opts.OnCritical = SentinelAction.Quarantine;
    opts.OnHigh     = SentinelAction.Alert;
    opts.OnMedium   = SentinelAction.Log;
});`}
            </pre>
          </div>
          <div className="col col--6">
            <h3>Wire into your chat client</h3>
            <pre className={styles.codeBlock}>
{`builder.Services.AddChatClient(pipeline =>
    pipeline.UseAISentinel()
            .Use(new OpenAIChatClient(...)));

// optional embedded dashboard
app.UseAISentinel("/ai-sentinel");`}
            </pre>
          </div>
        </div>
      </div>
    </section>
  );
}

function PackagesSection() {
  return (
    <section className={styles.packages}>
      <div className="container">
        <h2 style={{textAlign: 'center', marginBottom: '2rem'}}>13 packages, one ecosystem</h2>
        <div className="row">
          <div className="col col--4">
            <div className={styles.packageCard}>
              <h3>AI.Sentinel</h3>
              <p>Core — pipeline, 51 detectors, intervention engine, audit store.</p>
            </div>
          </div>
          <div className="col col--4">
            <div className={styles.packageCard}>
              <h3>AI.Sentinel.Detectors.Sdk</h3>
              <p>SDK for writing + unit-testing custom detectors.</p>
            </div>
          </div>
          <div className="col col--4">
            <div className={styles.packageCard}>
              <h3>AI.Sentinel.AspNetCore</h3>
              <p>Embedded real-time dashboard. HTMX + SSE.</p>
            </div>
          </div>
          <div className="col col--4">
            <div className={styles.packageCard}>
              <h3>AI.Sentinel.Sqlite</h3>
              <p>Persistent SqliteAuditStore with hash-chain integrity.</p>
            </div>
          </div>
          <div className="col col--4">
            <div className={styles.packageCard}>
              <h3>AI.Sentinel.Mcp</h3>
              <p>Stdio MCP proxy — scans tools/call + prompts/get for any MCP host.</p>
            </div>
          </div>
          <div className="col col--4">
            <div className={styles.packageCard}>
              <h3>AI.Sentinel.ClaudeCode</h3>
              <p>Native hook adapter for Claude Code's settings.json.</p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

export default function Home() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout
      title="Security middleware for IChatClient"
      description="Security monitoring middleware for IChatClient — prompt injection, hallucination, and operational anomaly detection with an embedded dashboard.">
      <HeroBanner />
      <main>
        <FeaturesSection />
        <CodeExample />
        <PackagesSection />
      </main>
    </Layout>
  );
}
