/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  docs: [
    'intro',
    {
      type: 'category',
      label: 'Getting Started',
      items: [
        'getting-started/installation',
        'getting-started/quick-start',
        'getting-started/dashboard',
      ],
    },
    {
      type: 'category',
      label: 'Core Concepts',
      items: [
        'core-concepts/architecture',
        'core-concepts/detection-pipeline',
        'core-concepts/intervention-engine',
        'core-concepts/audit-store',
        'core-concepts/severity-model',
      ],
    },
    {
      type: 'category',
      label: 'Detectors',
      items: [
        'detectors/overview',
        'detectors/security',
        'detectors/hallucination',
        'detectors/operational',
      ],
    },
    {
      type: 'category',
      label: 'Custom Detectors',
      items: [
        'custom-detectors/sdk-overview',
        'custom-detectors/writing-a-detector',
        'custom-detectors/detector-test-builder',
      ],
    },
    {
      type: 'category',
      label: 'Configuration',
      items: [
        'configuration/named-pipelines',
        'configuration/fluent-config',
        'configuration/embedding-cache',
      ],
    },
    {
      type: 'category',
      label: 'Audit Forwarders',
      items: [
        'audit-forwarders/overview',
        'audit-forwarders/ndjson',
        'audit-forwarders/sqlite',
        'audit-forwarders/azure-sentinel',
        'audit-forwarders/opentelemetry',
      ],
    },
    {
      type: 'category',
      label: 'Integrations',
      items: [
        'integrations/claude-code',
        'integrations/copilot',
        'integrations/mcp-proxy',
      ],
    },
    {
      type: 'category',
      label: 'Authorization',
      items: [
        'authorization/overview',
        'authorization/policies',
      ],
    },
    {
      type: 'category',
      label: 'Approvals',
      items: [
        'approvals/overview',
        'approvals/in-memory',
        'approvals/sqlite',
        'approvals/entra-pim',
        'approvals/dashboard',
        'approvals/cli-config',
      ],
    },
    {
      type: 'category',
      label: 'Cookbook',
      items: [
        'cookbook/multi-tenant',
        'cookbook/dev-staging-prod',
      ],
    },
  ],
};

export default sidebars;
