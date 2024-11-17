import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

const config: Config = {
  title: 'Traefik OIDC Authentication',
  tagline: 'Traefik OIDC Authentication Plugin',
  favicon: 'img/favicon.ico',

  // Set the production url of your site here
  url: 'https://traefik-oidc-auth.sevensolutions.cc',
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: '/',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'sevensolutions', // Usually your GitHub org/user name.
  projectName: 'traefik-oidc-auth', // Usually your repo name.

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl:
            'https://github.com/sevensolutions/traefik-oidc-auth/tree/main/website/',
        },
        theme: {
          customCss: './src/css/custom.css',
        }
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    // Replace with your project's social card
    image: 'img/social-card.jpg',
    navbar: {
      title: 'Traefik OIDC Authentication',
      logo: {
        alt: 'Traefik OIDC Authentication',
        src: 'img/logo.svg',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'gettingStartedSidebar',
          position: 'left',
          label: 'Getting Started',
        },
        {
          type: 'docSidebar',
          sidebarId: 'identityProvidersSidebar',
          position: 'left',
          label: 'Identity Providers',
        },
        {
          href: 'https://github.com/sevensolutions/traefik-oidc-auth',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {
              label: 'Getting Started',
              to: '/docs/intro',
            },
          ],
        },
        {
          title: 'More',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/sevensolutions/traefik-oidc-auth',
            },
            {
							label: 'Sponsor',
							href: "https://github.com/sponsors/sevensolutions"
						}
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} sevensolutions. Built with Docusaurus.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
