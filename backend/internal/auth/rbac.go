package auth

import "github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"

// DefaultRoleSpec defines one of the 4 built-in RBAC roles required by API_CONTRACT.md.
type DefaultRoleSpec struct {
	Slug        string
	Name        string
	Description string
	Permissions []string
}

// DemoAccount describes a seeded demo account exposed via /api/v1/auth/demo-accounts when DZIECIOL_SEED_DEMO=true.
type DemoAccount struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Email       string `json:"email"`
	RoleSlug    string `json:"role_slug"`
	RoleName    string `json:"role_name"`
	Description string `json:"description"`
}

// DefaultRoles lists the 4 mandatory seeded roles.
var DefaultRoles = []DefaultRoleSpec{
	{
		Slug:        "admin",
		Name:        "Administracja",
		Description: "Full administrative access (users, roles, encryption, audit, all modules)",
		Permissions: []string{"*"},
	},
	{
		Slug:        "operator",
		Name:        "Dodawanie, usuwanie, modyfikacja",
		Description: "Manage scans, assets, signatures, import/export and the DefectDojo integration",
		Permissions: []string{
			domain.PermDashboardRead,
			domain.PermAssetsRead,
			domain.PermAssetsWrite,
			domain.PermAssetsDelete,
			domain.PermScansRead,
			domain.PermScansWrite,
			domain.PermScansDelete,
			domain.PermScansRun,
			domain.PermSignaturesRead,
			domain.PermSignaturesWrite,
			domain.PermSignaturesDelete,
			domain.PermImportWrite,
			domain.PermExportRead,
			domain.PermDefectDojoPush,
		},
	},
	{
		Slug:        "analyst",
		Name:        "Modyfikacja i odczyt",
		Description: "Browse assets and scans; edit analyst overrides, metadata and signatures",
		Permissions: []string{
			domain.PermDashboardRead,
			domain.PermAssetsRead,
			domain.PermAssetsWrite,
			domain.PermScansRead,
			domain.PermScansWrite,
			domain.PermSignaturesRead,
			domain.PermSignaturesWrite,
			domain.PermExportRead,
		},
	},
	{
		Slug:        "viewer",
		Name:        "Odczyt",
		Description: "Read-only access to the dashboard, graph, assets, scans, signatures and exports",
		Permissions: []string{
			domain.PermDashboardRead,
			domain.PermAssetsRead,
			domain.PermScansRead,
			domain.PermSignaturesRead,
			domain.PermExportRead,
		},
	},
}

// DemoAccounts lists the 4 seeded accounts when DZIECIOL_SEED_DEMO=true.
var DemoAccounts = []DemoAccount{
	{
		Username:    "admin",
		Password:    "Admin123!",
		Email:       "admin@cbi.agh.edu.pl",
		RoleSlug:    "admin",
		RoleName:    "Administracja",
		Description: "Full administrative access",
	},
	{
		Username:    "operator",
		Password:    "Operator123!",
		Email:       "operator@cbi.agh.edu.pl",
		RoleSlug:    "operator",
		RoleName:    "Dodawanie, usuwanie, modyfikacja",
		Description: "Run scans, import, delete, DefectDojo",
	},
	{
		Username:    "analyst",
		Password:    "Analyst123!",
		Email:       "analyst@cbi.agh.edu.pl",
		RoleSlug:    "analyst",
		RoleName:    "Modyfikacja i odczyt",
		Description: "Read and edit assets, overrides and signatures",
	},
	{
		Username:    "viewer",
		Password:    "Viewer123!",
		Email:       "viewer@cbi.agh.edu.pl",
		RoleSlug:    "viewer",
		RoleName:    "Odczyt",
		Description: "Read-only and report export",
	},
}

// HasPermission returns true if perms grants required (either directly or via "*").
func HasPermission(perms []string, required string) bool {
	if required == "" {
		return true
	}
	for _, p := range perms {
		if p == "*" || p == required {
			return true
		}
	}
	return false
}
