// =========================================================================
// [DOWNSTREAM: daohai2102/athena-datasource-oauth]
// This component is downstream-specific for the OAuth Authentication UI.
// Isolated into its own file to keep upstream ConfigEditor.tsx clean and
// avoid merge conflicts during upstream synchronization (grafana/athena-datasource).
// =========================================================================

import React, { FormEvent } from 'react';
import { DataSourceSettings } from '@grafana/data';
import { ConfigSection } from '@grafana/plugin-ui';
import { Field, Input, Switch } from '@grafana/ui';
import { selectors } from 'tests/selectors';
import { AthenaDataSourceOptions, AthenaDataSourceSecureJsonData } from './types';

export interface OAuthSectionProps {
  options: DataSourceSettings<AthenaDataSourceOptions, AthenaDataSourceSecureJsonData>;
  onOptionsChange: (options: DataSourceSettings<AthenaDataSourceOptions, AthenaDataSourceSecureJsonData>) => void;
}

export function OAuthSection({ options, onOptionsChange }: OAuthSectionProps) {
  const onToggleOAuthPassThru = () => {
    onOptionsChange({
      ...options,
      jsonData: {
        ...options.jsonData,
        oauthPassThru: !options.jsonData.oauthPassThru,
      },
    });
  };

  const onChangeOAuthRoleArn = (e: FormEvent<HTMLInputElement>) => {
    onOptionsChange({
      ...options,
      jsonData: {
        ...options.jsonData,
        oauthRoleArn: e.currentTarget.value,
      },
    });
  };

  const onChangeOAuthRoleSessionName = (e: FormEvent<HTMLInputElement>) => {
    onOptionsChange({
      ...options,
      jsonData: {
        ...options.jsonData,
        oauthRoleSessionName: e.currentTarget.value,
      },
    });
  };

  return (
    <ConfigSection title="OAuth Authentication (Web Identity)">
      <Field
        label={selectors.components.ConfigEditor.OAuthPassThru.input}
        description="Forward the logged-in user's OAuth/OIDC identity (X-Id-Token or Authorization Bearer) to authenticate queries with AWS STS AssumeRoleWithWebIdentity."
        htmlFor="oauthPassThru"
      >
        <Switch
          id="oauthPassThru"
          aria-label={selectors.components.ConfigEditor.OAuthPassThru.input}
          data-testid={selectors.components.ConfigEditor.OAuthPassThru.wrapper}
          value={options.jsonData.oauthPassThru ?? false}
          onChange={onToggleOAuthPassThru}
        />
      </Field>
      {options.jsonData.oauthPassThru && (
        <>
          <Field
            label={selectors.components.ConfigEditor.OAuthRoleArn.input}
            description="The IAM Role ARN to assume using the Web Identity Token. If left blank, Assume Role ARN from Connection Config will be used."
            htmlFor="oauthRoleArn"
          >
            <Input
              id="oauthRoleArn"
              placeholder="arn:aws:iam::123456789012:role/AthenaUserRole"
              value={options.jsonData.oauthRoleArn ?? ''}
              onChange={onChangeOAuthRoleArn}
              data-testid={selectors.components.ConfigEditor.OAuthRoleArn.wrapper}
            />
          </Field>
          <Field
            label={selectors.components.ConfigEditor.OAuthRoleSessionName.input}
            description="Optional. Role session name for STS AssumeRoleWithWebIdentity. Can be a prefix (e.g. 'my-team') or a template (e.g. 'grafana-${USER}'). Defaults to 'grafana-<username>'."
            htmlFor="oauthRoleSessionName"
          >
            <Input
              id="oauthRoleSessionName"
              placeholder="e.g. grafana-${USER}"
              value={options.jsonData.oauthRoleSessionName ?? ''}
              onChange={onChangeOAuthRoleSessionName}
              data-testid={selectors.components.ConfigEditor.OAuthRoleSessionName.wrapper}
            />
          </Field>
        </>
      )}
    </ConfigSection>
  );
}
