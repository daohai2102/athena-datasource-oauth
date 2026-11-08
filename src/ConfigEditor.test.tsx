import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ConfigEditor } from './ConfigEditor';
import { mockDatasourceOptions } from './__mocks__/datasource';
import { select } from 'react-select-event';
import { selectors } from 'tests/selectors';
import { AwsAuthType } from '@grafana/aws-sdk';
import * as runtime from '@grafana/runtime';
import userEvent from '@testing-library/user-event';

jest.mock('@grafana/runtime', () => ({
  ...jest.requireActual('@grafana/runtime'),
  usePluginInteractionReporter: () => jest.fn(),
  getAppEvents: () => ({
    subscribe: () => ({ unsubscribe: jest.fn() }),
  }),
  getBackendSrv: jest.fn(),
}));

const resourceName = 'foo';
const props = mockDatasourceOptions;

const setUpMockBackendServer = (mockBackendSrv: { put: () => void; post: () => void }) => {
  jest.mocked(runtime.getBackendSrv).mockReturnValue(mockBackendSrv as unknown as runtime.BackendSrv);
};

describe('ConfigEditor', () => {
  it('should save and request catalogs', async () => {
    setUpMockBackendServer({
      put: jest.fn().mockResolvedValue({ datasource: {} }),
      post: jest.fn().mockResolvedValue([resourceName]),
    });

    const onChange = jest.fn();
    render(<ConfigEditor {...props} onOptionsChange={onChange} />);

    const selectEl = screen.getByLabelText(selectors.components.ConfigEditor.catalog.input);
    expect(selectEl).toBeInTheDocument();

    await waitFor(() => select(selectEl, resourceName, { container: document.body }));

    expect(onChange).toHaveBeenCalledWith({
      ...props.options,
      jsonData: { ...props.options.jsonData, catalog: resourceName },
    });
  });

  it('should save and request databases', async () => {
    setUpMockBackendServer({
      put: jest.fn().mockResolvedValue({ datasource: {} }),
      post: jest.fn().mockResolvedValue([resourceName]),
    });

    const onChange = jest.fn();
    render(<ConfigEditor {...props} onOptionsChange={onChange} />);

    const selectEl = screen.getByLabelText(selectors.components.ConfigEditor.database.input);
    expect(selectEl).toBeInTheDocument();

    await waitFor(() => select(selectEl, resourceName, { container: document.body }));

    expect(onChange).toHaveBeenCalledWith({
      ...props.options,
      jsonData: { ...props.options.jsonData, database: resourceName },
    });
  });

  it('should save and request workgroups', async () => {
    setUpMockBackendServer({
      put: jest.fn().mockResolvedValue({ datasource: {} }),
      post: jest.fn().mockResolvedValue([resourceName]),
    });

    const onChange = jest.fn();
    render(<ConfigEditor {...props} onOptionsChange={onChange} />);

    const selectEl = screen.getByLabelText(selectors.components.ConfigEditor.workgroup.input);
    expect(selectEl).toBeInTheDocument();

    await waitFor(() => select(selectEl, resourceName, { container: document.body }));

    expect(onChange).toHaveBeenCalledWith({
      ...props.options,
      jsonData: { ...props.options.jsonData, workgroup: resourceName },
    });
  });

  it('should use an output location', async () => {
    setUpMockBackendServer({
      put: jest.fn().mockResolvedValue({ datasource: {} }),
      post: jest.fn().mockResolvedValue([resourceName]),
    });

    const onChange = jest.fn();
    render(<ConfigEditor {...props} onOptionsChange={onChange} />);
    const input = screen.getByTestId(selectors.components.ConfigEditor.OutputLocation.wrapper);
    const bucket = 's3://foo';
    fireEvent.change(input, { target: { value: bucket } });
    expect(onChange).toHaveBeenCalledWith({
      ...props.options,
      jsonData: { ...props.options.jsonData, outputLocation: bucket },
    });
  });

  // =========================================================================
  // [DOWNSTREAM: daohai2102/athena-datasource-oauth]
  // Test for toggling Forward OAuth Identity and updating role ARN / session name.
  // =========================================================================
  it('should toggle Forward OAuth Identity and update role arn / session name', async () => {
    setUpMockBackendServer({
      put: jest.fn().mockResolvedValue({ datasource: {} }),
      post: jest.fn().mockResolvedValue([resourceName]),
    });

    const onChange = jest.fn();
    const { rerender } = render(<ConfigEditor {...props} onOptionsChange={onChange} />);

    const switchEl = screen.getByTestId(selectors.components.ConfigEditor.OAuthPassThru.wrapper);
    expect(switchEl).toBeInTheDocument();
    fireEvent.click(switchEl);

    expect(onChange).toHaveBeenCalledWith({
      ...props.options,
      jsonData: { ...props.options.jsonData, oauthPassThru: true },
    });

    rerender(
      <ConfigEditor
        {...props}
        options={{
          ...props.options,
          jsonData: { ...props.options.jsonData, oauthPassThru: true },
        }}
        onOptionsChange={onChange}
      />
    );

    const roleArnInput = screen.getByTestId(selectors.components.ConfigEditor.OAuthRoleArn.wrapper);
    expect(roleArnInput).toBeInTheDocument();
    fireEvent.change(roleArnInput, { target: { value: 'arn:aws:iam::123456789012:role/AthenaUserRole' } });
    expect(onChange).toHaveBeenCalledWith({
      ...props.options,
      jsonData: {
        ...props.options.jsonData,
        oauthPassThru: true,
        oauthRoleArn: 'arn:aws:iam::123456789012:role/AthenaUserRole',
      },
    });

    const sessionNameInput = screen.getByTestId(selectors.components.ConfigEditor.OAuthRoleSessionName.wrapper);
    expect(sessionNameInput).toBeInTheDocument();
    fireEvent.change(sessionNameInput, { target: { value: 'my-session' } });
    expect(onChange).toHaveBeenCalledWith({
      ...props.options,
      jsonData: {
        ...props.options.jsonData,
        oauthPassThru: true,
        oauthRoleSessionName: 'my-session',
      },
    });
  });
  // =========================================================================
  // [END DOWNSTREAM: daohai2102/athena-datasource-oauth]
  // =========================================================================

  it('should fetch and display externalId when the auth type is grafana_assume_role', async () => {
    setUpMockBackendServer({
      put: jest.fn().mockResolvedValue({ datasource: {} }),
      post: jest.fn().mockResolvedValue({ externalId: 'fake-external-id' }),
    });

    render(
      <ConfigEditor
        {...props}
        options={{
          ...props.options,
          jsonData: {
            ...props.options.jsonData,
            authType: AwsAuthType.GrafanaAssumeRole,
          },
        }}
      />
    );

    // The selected option and the link to the docs both have the same text
    expect(screen.queryAllByText('Grafana Assume Role').length).toBe(2);
    expect(screen.getByRole('link', { name: 'Grafana Assume Role' })).toBeInTheDocument();
    const instructionsButton = await screen.findByRole('button', {
      name: /How to create an IAM role for grafana to assume/i,
    });
    await userEvent.click(instructionsButton);
    expect(screen.queryByText('fake-external-id')).toBeInTheDocument();
  });

  it('gracefully handles when the fetch for external id throws an error', async () => {
    setUpMockBackendServer({
      put: jest.fn().mockResolvedValue({ datasource: {} }),
      post: jest.fn().mockRejectedValue('the server exploded for some reason'),
    });

    render(
      <ConfigEditor
        {...props}
        options={{
          ...props.options,
          jsonData: {
            ...props.options.jsonData,
            authType: AwsAuthType.GrafanaAssumeRole,
          },
        }}
      />
    );

    // The selected option and the link to the docs both have the same text
    expect(screen.queryAllByText('Grafana Assume Role').length).toBe(2);
    expect(screen.getByRole('link', { name: 'Grafana Assume Role' })).toBeInTheDocument();
    const instructionsButton = await screen.findByRole('button', {
      name: /How to create an IAM role for grafana to assume/i,
    });
    await userEvent.click(instructionsButton);
    expect(screen.queryByText('External Id is currently unavailable')).toBeInTheDocument();
  });

  it('gracefully handles when the fetch for external id return an empty string', async () => {
    setUpMockBackendServer({
      put: jest.fn().mockResolvedValue({ datasource: {} }),
      post: jest.fn().mockResolvedValue({ externalId: '' }),
    });

    render(
      <ConfigEditor
        {...props}
        options={{
          ...props.options,
          jsonData: {
            ...props.options.jsonData,
            authType: AwsAuthType.GrafanaAssumeRole,
          },
        }}
      />
    );

    // The selected option and the link to the docs both have the same text
    expect(screen.queryAllByText('Grafana Assume Role').length).toBe(2);
    expect(screen.getByRole('link', { name: 'Grafana Assume Role' })).toBeInTheDocument();
    const instructionsButton = await screen.findByRole('button', {
      name: /How to create an IAM role for grafana to assume/i,
    });
    await userEvent.click(instructionsButton);
    expect(screen.queryByText('External Id is currently unavailable')).toBeInTheDocument();
  });

  it('merges grafanaExternalId from save response into options', async () => {
    const mintedExternalId = 'stack-uid-abcdef0123456789';
    const putMock = jest.fn().mockResolvedValue({
      datasource: {
        version: 2,
        jsonData: {
          grafanaExternalId: mintedExternalId,
          usePerDatasourceExternalId: true,
        },
      },
    });

    setUpMockBackendServer({
      put: putMock,
      post: jest.fn().mockResolvedValue([resourceName]),
    });

    const onChange = jest.fn();
    render(
      <ConfigEditor
        {...props}
        options={{
          ...props.options,
          jsonData: {
            ...props.options.jsonData,
            authType: AwsAuthType.GrafanaAssumeRole,
          },
        }}
        onOptionsChange={onChange}
      />
    );

    // Changing region resets saved=false via ConnectionConfig onOptionsChange wrapper.
    const regionSelect = document.getElementById('defaultRegion');
    expect(regionSelect).toBeInTheDocument();
    await select(regionSelect!, 'us-west-2', { container: document.body });

    const selectEl = screen.getByLabelText(selectors.components.ConfigEditor.catalog.input);
    await waitFor(() => select(selectEl, resourceName, { container: document.body }));

    expect(putMock).toHaveBeenCalled();
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({
        version: 2,
        jsonData: expect.objectContaining({
          grafanaExternalId: mintedExternalId,
          usePerDatasourceExternalId: true,
        }),
      })
    );
  });
});
