package resources

import (
	"context"
	"testing"

	projectconfig "github.com/cmstar/jumpaccess/internal/config"
	"github.com/cmstar/jumpaccess/internal/credential"
	"github.com/cmstar/jumpaccess/internal/jumpserver"
)

type staticConfig struct{ value projectconfig.Config }

func (s staticConfig) Load() (projectconfig.Config, error) { return s.value, nil }

type staticSessions struct{}

type foreignSessions struct{}

func (foreignSessions) Ensure(context.Context, string, string) (credential.Session, error) {
	return credential.Session{Token: credential.Token{AccessToken: "fixture", Site: "https://old.example.test"}}, nil
}

func TestResourceRequestsRejectCredentialFromAnotherSite(t *testing.T) {
	configuration := projectconfig.Default()
	configuration.CurrentProfile = "work"
	configuration.Profiles["work"] = projectconfig.Profile{URL: "https://new.example.test"}
	called := false
	service := Service{Config: staticConfig{value: configuration}, Sessions: foreignSessions{}, NewAPI: func(string, credential.Session, string) (API, error) { called = true; return fakeAPI{}, nil }}
	if _, err := service.ListOrganizations(context.Background(), "work"); err == nil || called {
		t.Fatal("foreign credential reached API factory")
	}
}

func (staticSessions) Ensure(context.Context, string, string) (credential.Session, error) {
	return credential.Session{Token: credential.Token{AccessToken: "access", Site: "https://jump.example.test"}}, nil
}

type fakeAPI struct {
	organizations []jumpserver.Organization
	page          jumpserver.AssetPage
	detail        jumpserver.AssetDetail
	assetQuery    *jumpserver.AssetQuery
}

func (f fakeAPI) ListOrganizations(context.Context) ([]jumpserver.Organization, error) {
	return f.organizations, nil
}

func (f fakeAPI) ListAssets(_ context.Context, query jumpserver.AssetQuery) (jumpserver.AssetPage, error) {
	if f.assetQuery != nil {
		*f.assetQuery = query
	}
	return f.page, nil
}

func (f fakeAPI) GetAsset(context.Context, string) (jumpserver.AssetDetail, error) {
	return f.detail, nil
}

func (f fakeAPI) ValidateSession(context.Context) (string, error) {
	return "root", nil
}

func TestServiceListsResourcesUsingSelectedProfileAndOrganization(t *testing.T) {
	configuration := projectconfig.Default()
	configuration.CurrentProfile = "work"
	configuration.Profiles["work"] = projectconfig.Profile{URL: "https://jump.example.test", Organization: "org-default"}
	var assetQuery jumpserver.AssetQuery
	api := fakeAPI{
		organizations: []jumpserver.Organization{{ID: "org-1", Name: "One"}},
		page:          jumpserver.AssetPage{Results: []jumpserver.Asset{{ID: "asset-1", Name: "web"}}},
		assetQuery:    &assetQuery,
	}
	service := Service{
		Config: staticConfig{value: configuration}, Sessions: staticSessions{},
		NewAPI: func(site string, session credential.Session, organization string) (API, error) {
			if site != "https://jump.example.test" || session.Token.AccessToken != "access" || (organization != "org-explicit" && organization != "") {
				t.Fatalf("factory args = %q %q %q", site, session.Token.AccessToken, organization)
			}
			return api, nil
		},
	}

	assets, err := service.ListAssets(context.Background(), "", "org-explicit", "web", 200, 25)
	if err != nil || len(assets.Results) != 1 {
		t.Fatalf("ListAssets = %#v, %v", assets, err)
	}
	if assetQuery.Search != "web" || assetQuery.Offset != 200 || assetQuery.Limit != 25 {
		t.Fatalf("asset query = %#v, want search web, offset 200, limit 25", assetQuery)
	}
	organizations, err := service.ListOrganizations(context.Background(), "")
	if err != nil || len(organizations) != 1 {
		t.Fatalf("ListOrganizations = %#v, %v", organizations, err)
	}
}

func TestServiceFindAssetReturnsExactDetailForAccountDiscovery(t *testing.T) {
	configuration := projectconfig.Default()
	configuration.CurrentProfile = "work"
	configuration.Profiles["work"] = projectconfig.Profile{URL: "https://jump.example.test"}
	api := fakeAPI{
		page:   jumpserver.AssetPage{Results: []jumpserver.Asset{{ID: "asset-1", Name: "web"}}},
		detail: jumpserver.AssetDetail{Asset: jumpserver.Asset{ID: "asset-1", Name: "web"}, Accounts: []jumpserver.Account{{ID: "account-1", Username: "root"}}},
	}
	service := Service{Config: staticConfig{value: configuration}, Sessions: staticSessions{}, NewAPI: func(string, credential.Session, string) (API, error) { return api, nil }}

	asset, err := service.FindAsset(context.Background(), "", "", "web")
	if err != nil {
		t.Fatal(err)
	}
	if asset.ID != "asset-1" || len(asset.Accounts) != 1 || asset.Accounts[0].Username != "root" {
		t.Fatalf("asset = %#v", asset)
	}
}

func TestGetAssetByIDNeverFallsBackToNameSearch(t *testing.T) {
	configuration := projectconfig.Default()
	configuration.Profiles["work"] = projectconfig.Profile{URL: "https://jump.example.test"}
	query := jumpserver.AssetQuery{}
	api := fakeAPI{detail: jumpserver.AssetDetail{Asset: jumpserver.Asset{ID: "asset-1"}}, assetQuery: &query}
	service := Service{Config: staticConfig{value: configuration}, Sessions: staticSessions{}, NewAPI: func(string, credential.Session, string) (API, error) { return api, nil }}
	asset, err := service.GetAssetByID(context.Background(), "work", "org", "asset-1")
	if err != nil || asset.ID != "asset-1" || query != (jumpserver.AssetQuery{}) {
		t.Fatal("按 ID 查询改变为名称搜索", err)
	}
	if _, err := service.GetAssetByID(context.Background(), "work", "org", "other"); err == nil {
		t.Fatal("没有核对返回的资产 ID")
	}
}
