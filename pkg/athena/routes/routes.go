package routes

import (
	"net/http"

	"github.com/grafana/athena-datasource/pkg/athena"
	// =========================================================================
	// [DOWNSTREAM: daohai2102/athena-datasource-oauth]
	// =========================================================================
	"github.com/grafana/athena-datasource/pkg/athena/oauth"
	// =========================================================================
	// [END DOWNSTREAM: daohai2102/athena-datasource-oauth]
	// =========================================================================
	"github.com/grafana/grafana-aws-sdk/pkg/awsds"
	"github.com/grafana/grafana-aws-sdk/pkg/sql/routes"
)

type AthenaResourceHandler struct {
	routes.ResourceHandler
	athena athena.AthenaDatasourceIface
}

func New(api athena.AthenaDatasourceIface) *AthenaResourceHandler {
	return &AthenaResourceHandler{routes.ResourceHandler{API: api}, api}
}

func (r *AthenaResourceHandler) catalogs(rw http.ResponseWriter, req *http.Request) {
	reqBody, err := routes.ParseBody(req.Body)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		routes.Write(rw, []byte(err.Error()))
		return
	}
	res, err := r.athena.DataCatalogs(req.Context(), reqBody)
	routes.SendResources(rw, res, err)
}

func (r *AthenaResourceHandler) workgroups(rw http.ResponseWriter, req *http.Request) {
	reqBody, err := routes.ParseBody(req.Body)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		routes.Write(rw, []byte(err.Error()))
		return
	}
	res, err := r.athena.Workgroups(req.Context(), reqBody)
	routes.SendResources(rw, res, err)
}

func (r *AthenaResourceHandler) workgroupEngineVersion(rw http.ResponseWriter, req *http.Request) {
	reqBody, err := routes.ParseBody(req.Body)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		routes.Write(rw, []byte(err.Error()))
		return
	}
	res, err := r.athena.WorkgroupEngineVersion(req.Context(), reqBody)
	routes.SendResources(rw, res, err)
}

type ExternalIdResponse struct {
	ExternalId string `json:"externalId"`
}

func (r *AthenaResourceHandler) externalId(rw http.ResponseWriter, req *http.Request) {
	authSettings, _ := awsds.ReadAuthSettingsFromContext(req.Context())
	res := ExternalIdResponse{
		ExternalId: authSettings.ExternalID,
	}
	routes.SendResources(rw, res, nil)
}

func (r *AthenaResourceHandler) Routes() map[string]func(http.ResponseWriter, *http.Request) {
	routes := r.DefaultRoutes()
	routes["/catalogs"] = r.catalogs
	routes["/workgroups"] = r.workgroups
	routes["/workgroupEngineVersion"] = r.workgroupEngineVersion
	routes["/externalId"] = r.externalId

	// =========================================================================
	// [DOWNSTREAM: daohai2102/athena-datasource-oauth]
	// Wrap resource routes to extract and forward OAuth identity token in context.
	// Implementation isolated in pkg/athena/oauth/routes.go to prevent merge
	// conflicts when syncing with upstream (grafana/athena-datasource).
	// =========================================================================
	return oauth.WrapRoutes(routes)
	// =========================================================================
	// [END DOWNSTREAM: daohai2102/athena-datasource-oauth]
	// =========================================================================
}
