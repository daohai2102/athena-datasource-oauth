package main

import (
	"context"
	"os"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/instancemgmt"

	"github.com/grafana/athena-datasource/pkg/athena"
	// =========================================================================
	// [DOWNSTREAM: daohai2102/athena-datasource-oauth]
	// =========================================================================
	"github.com/grafana/athena-datasource/pkg/athena/oauth"
	// =========================================================================
	// [END DOWNSTREAM: daohai2102/athena-datasource-oauth]
	// =========================================================================
	"github.com/grafana/athena-datasource/pkg/athena/routes"
	"github.com/grafana/grafana-aws-sdk/pkg/awsds"
	"github.com/grafana/grafana-plugin-sdk-go/backend/datasource"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
)

func main() {
	// Start listening to requests sent from Grafana.
	if err := datasource.Manage(
		"grafana-athena-datasource",
		MakeDatasourceFactory(),
		datasource.ManageOpts{},
	); err != nil {
		log.DefaultLogger.Error(err.Error())
		os.Exit(1)
	}
}

func MakeDatasourceFactory() datasource.InstanceFactoryFunc {
	return func(ctx context.Context, settings backend.DataSourceInstanceSettings) (instancemgmt.Instance, error) {
		log.DefaultLogger.FromContext(ctx).Debug("building new datasource instance")
		s := athena.New()
		ds := awsds.NewAsyncAWSDatasource(s)
		ds.Completable = s
		ds.EnableMultipleConnections = true
		ds.CustomRoutes = routes.New(s).Routes()
		// =========================================================================
		// [DOWNSTREAM: daohai2102/athena-datasource-oauth]
		// Wrap datasource instance with OAuth pass-through proxy to inject token
		// context and isolate query connections per user.
		// Implementation is isolated in pkg/athena/oauth/datasource.go to prevent
		// upstream merge conflicts in main.go.
		// =========================================================================
		return oauth.WrapDatasource(ds.NewDatasource(ctx, settings))
		// =========================================================================
		// [END DOWNSTREAM: daohai2102/athena-datasource-oauth]
		// =========================================================================
	}
}
