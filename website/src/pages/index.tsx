import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import {
  ShieldCheck,
  ListChecks,
  KeyRound,
  RefreshCw,
  ArrowUpFromLine,
  GitBranchPlus,
  FileWarning,
  Globe,
} from 'lucide-react';

import styles from './index.module.css';

const FEATURES = [
  {
    Icon: ShieldCheck,
    color: '#3b82f6',
    title: 'OIDC / OAuth 2.0',
    description:
      'Intercepts every request in Traefik and validates OAuth tokens — no changes needed in your upstream services.',
  },
  {
    Icon: ListChecks,
    color: '#8b5cf6',
    title: 'Claim-Based Authorization',
    description:
      'Assert JWT claims with flexible AnyOf / AllOf rules and JSON-path selectors to control who can access what.',
  },
  {
    Icon: KeyRound,
    color: '#f59e0b',
    title: 'PKCE Support',
    description:
      'Enable PKCE for public clients (SPAs, CLIs) to protect against authorization code interception attacks.',
  },
  {
    Icon: RefreshCw,
    color: '#10b981',
    title: 'Token Auto-Renewal',
    description:
      'Tokens are transparently refreshed before they expire, keeping sessions alive without user interruption.',
  },
  {
    Icon: ArrowUpFromLine,
    color: '#f7921e',
    title: 'Header Forwarding',
    description:
      'Pass tokens or any JWT claim to your upstream service via custom headers using Go template expressions.',
  },
  {
    Icon: GitBranchPlus,
    color: '#06b6d4',
    title: 'Bypass Rules',
    description:
      'Skip authentication for public paths, specific hosts, or internal IP ranges using Traefik-style rules.',
  },
  {
    Icon: FileWarning,
    color: '#ef4444',
    title: 'Custom Error Pages',
    description:
      'Serve your own branded HTML for 401 Unauthenticated and 403 Unauthorized responses.',
  },
  {
    Icon: Globe,
    color: '#64748b',
    title: 'Multiple Identity Providers',
    description:
      'Works with any OIDC-compliant provider. Tested with 7+ popular providers out of the box.',
  },
];

const IDENTITY_PROVIDERS = [
  'Authentik',
  'Microsoft Entra ID',
  'Kanidm',
  'Keycloak',
  'Logto',
  'PocketID',
  'ZITADEL',
];


export default function Home(): JSX.Element {
  const { siteConfig } = useDocusaurusContext();
  return (
    <Layout
      title={siteConfig.title}
      description="A Traefik middleware plugin that secures your services with OIDC (OpenID Connect) authentication and claim-based authorization.">

      {/* ── Hero ─────────────────────────────────────────────── */}
      <section className={styles.hero}>
        <img className={styles.logo} alt="Traefik OIDC Auth logo" />
        <h1 className={styles.heroTitle}>{siteConfig.title}</h1>
        <p className={styles.heroSubtitle}>
          A Traefik middleware plugin that secures your services with&nbsp;
          <strong>OIDC (OpenID Connect)</strong> authentication and&nbsp;
          <strong>claim-based authorization</strong> — without modifying your upstream applications.
        </p>
        <div className={styles.heroCtas}>
          <Link className="button button--primary button--lg" to="/docs/getting-started">
            Get Started →
          </Link>
          <Link
            className="button button--secondary button--lg"
            href="https://github.com/sevensolutions/traefik-oidc-auth">
            GitHub
          </Link>
        </div>
        <div className={styles.sponsorWrapper}>
          <iframe
            src="https://github.com/sponsors/sevensolutions/button"
            title="Sponsor sevensolutions"
            height="32"
            width="114"
          />
        </div>
      </section>

      {/* ── Features ─────────────────────────────────────────── */}
      <section className={styles.section}>
        <div className={styles.sectionInner}>
          <h2 className={styles.sectionTitle}>Features</h2>
          <div className={styles.featuresGrid}>
            {FEATURES.map(({ Icon, color, title, description }) => (
              <div key={title} className={styles.featureCard}>
                <span className={styles.featureIconWrap} style={{ backgroundColor: color + '1f' }}>
                  <Icon size={22} color={color} strokeWidth={1.75} />
                </span>
                <h3 className={styles.featureTitle}>{title}</h3>
                <p className={styles.featureDescription}>{description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Identity Providers ───────────────────────────────── */}
      <section className={styles.sectionAlt}>
        <div className={styles.sectionInner}>
          <h2 className={styles.sectionTitle}>Supported Identity Providers</h2>
          <p className={styles.sectionSubtitle}>
            Works with any OIDC-compliant provider. Dedicated guides for:
          </p>
          <div className={styles.providerList}>
            {IDENTITY_PROVIDERS.map((name) => (
              <span key={name} className={styles.providerBadge}>{name}</span>
            ))}
          </div>
          <Link className={styles.sectionLink} to="/docs/identity-providers">
            View all provider guides →
          </Link>
        </div>
      </section>

      {/* ── Quick Start ──────────────────────────────────────── */}
      <section className={styles.section}>
        <div className={styles.sectionInner}>
          <div className={styles.ctaBanner}>
            <h2 className={styles.ctaTitle}>Ready to get started?</h2>
            <p className={styles.ctaSubtitle}>
              Follow the Getting Started guide to add OIDC authentication to any Traefik-proxied service in minutes.
            </p>
            <Link className="button button--primary button--lg" to="/docs/getting-started">
              Read the Getting Started Guide →
            </Link>
          </div>
        </div>
      </section>

    </Layout>
  );
}
