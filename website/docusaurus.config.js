// @ts-check
import {themes as prismThemes} from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'AI.Sentinel',
  tagline: 'Security monitoring middleware for IChatClient — prompt injection, hallucination, and operational anomaly detection',
  favicon: 'img/favicon.png',
  url: 'https://zeroalloc-net.github.io',
  baseUrl: '/AI.Sentinel/',
  organizationName: 'ZeroAlloc-Net',
  projectName: 'AI.Sentinel',
  trailingSlash: false,
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',

  headTags: [
    {
      tagName: 'meta',
      attributes: { property: 'og:image', content: 'https://zeroalloc-net.github.io/AI.Sentinel/img/logo.png' },
    },
    {
      tagName: 'meta',
      attributes: { property: 'og:title', content: 'AI.Sentinel' },
    },
    {
      tagName: 'meta',
      attributes: { property: 'og:description', content: 'Security monitoring middleware for IChatClient — prompt injection, hallucination, and operational anomaly detection' },
    },
    {
      tagName: 'meta',
      attributes: { name: 'twitter:card', content: 'summary_large_image' },
    },
  ],

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: './sidebars.js',
          editUrl: 'https://github.com/ZeroAlloc-Net/AI.Sentinel/tree/main/website/',
          routeBasePath: 'docs',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      navbar: {
        title: 'AI.Sentinel',
        logo: {
          alt: 'AI.Sentinel Logo',
          src: 'img/logo.svg',
          href: '/AI.Sentinel/',
        },
        items: [
          {
            type: 'docSidebar',
            sidebarId: 'docs',
            position: 'left',
            label: 'Docs',
          },
          {
            href: 'https://github.com/ZeroAlloc-Net/AI.Sentinel',
            label: 'GitHub',
            position: 'right',
          },
          {
            href: 'https://www.nuget.org/packages/AI.Sentinel',
            label: 'NuGet',
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
              { label: 'Introduction', to: '/docs/intro' },
              { label: 'Quick start', to: '/docs/getting-started/quick-start' },
              { label: 'Detector reference', to: '/docs/detectors/overview' },
              { label: 'Custom detectors', to: '/docs/custom-detectors/sdk-overview' },
            ],
          },
          {
            title: 'Community',
            items: [
              { label: 'GitHub', href: 'https://github.com/ZeroAlloc-Net/AI.Sentinel' },
              { label: 'Issues', href: 'https://github.com/ZeroAlloc-Net/AI.Sentinel/issues' },
              { label: 'Discussions', href: 'https://github.com/ZeroAlloc-Net/AI.Sentinel/discussions' },
            ],
          },
          {
            title: 'More',
            items: [
              { label: 'NuGet — AI.Sentinel', href: 'https://www.nuget.org/packages/AI.Sentinel' },
              { label: 'NuGet — AI.Sentinel.Detectors.Sdk', href: 'https://www.nuget.org/packages/AI.Sentinel.Detectors.Sdk' },
              { label: 'License (MIT)', href: 'https://github.com/ZeroAlloc-Net/AI.Sentinel/blob/main/LICENSE' },
            ],
          },
        ],
        copyright: `Copyright ${new Date().getFullYear()} ZeroAlloc-Net. Built with Docusaurus.`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ['csharp', 'markup', 'bash', 'json', 'yaml'],
      },
    }),
};

export default config;
