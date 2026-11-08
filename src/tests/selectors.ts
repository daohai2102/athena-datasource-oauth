import { E2ESelectors } from '@grafana/e2e-selectors';

export const Components = {
  ConfigEditor: {
    AuthenticationProvider: {
      input: 'Authentication Provider',
    },
    SecretKey: {
      input: 'Secret Access Key',
    },
    AccessKey: {
      input: 'Access Key ID',
    },
    DefaultRegion: {
      input: 'Default Region',
    },
    catalog: {
      input: 'Data source',
      wrapper: 'data-testid onloadcatalog',
    },
    database: {
      input: 'Database',
      wrapper: 'data-testid onloaddatabase',
    },
    workgroup: {
      input: 'Workgroup',
      wrapper: 'data-testid onloadworkgroup',
    },
    OutputLocation: {
      input: 'Output Location',
      wrapper: 'data-testid onloadoutputlocation',
    },
    region: {
      input: 'Region',
      wrapper: 'data-testid onloadregion',
    },
    table: {
      input: 'Table',
      wrapper: 'data-testid onloadtable',
    },
    column: {
      input: 'Column',
      wrapper: 'data-testid onloadcolumn',
    },
    // =========================================================================
    // [DOWNSTREAM: daohai2102/athena-datasource-oauth]
    // =========================================================================
    OAuthPassThru: {
      input: 'Forward OAuth Identity',
      wrapper: 'oauth-pass-thru-switch',
    },
    OAuthRoleArn: {
      input: 'OAuth Role ARN',
      wrapper: 'oauth-role-arn-input',
    },
    OAuthRoleSessionName: {
      input: 'Role Session Name',
      wrapper: 'oauth-role-session-name-input',
    },
    // =========================================================================
    // [END DOWNSTREAM: daohai2102/athena-datasource-oauth]
    // =========================================================================
  },
  QueryEditor: {
    CodeEditor: {
      container: 'data-testid Code editor container',
    },
    TableView: {
      input: 'toggle-table-view',
    },
  },
  RefreshPicker: {
    runButton: 'RefreshPicker run button',
  },
};

export const selectors: { components: E2ESelectors<typeof Components> } = {
  components: Components,
};
