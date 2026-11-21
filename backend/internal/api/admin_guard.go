package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/auth"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

const minPasswordLen = 8

var errLastAdmin = errors.New("operacja odebrałaby dostęp ostatniemu administratorowi - najpierw nadaj rolę administratora innemu aktywnemu kontu / this would leave no active administrator")

// guardLastAdmin simulates a user or role change and refuses it if no active account would
// keep the admin.users permission afterwards (nobody could manage accounts any more).
// mutateUser may change or drop (return false) a user; mutateRole may change a role.
func (s *Server) guardLastAdmin(ctx context.Context, mutateUser func(*domain.User) bool, mutateRole func(*domain.Role)) error {
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return err
	}
	roles, err := s.store.ListRoles(ctx)
	if err != nil {
		return err
	}
	perms := make(map[string][]string, len(roles))
	for i := range roles {
		if mutateRole != nil {
			mutateRole(&roles[i])
		}
		perms[roles[i].ID] = roles[i].Permissions
	}
	for i := range users {
		u := users[i]
		if mutateUser != nil && !mutateUser(&u) {
			continue
		}
		if u.Active && auth.HasPermission(perms[u.RoleID], domain.PermAdminUsers) {
			return nil
		}
	}
	return errLastAdmin
}

func writeGuardErr(w http.ResponseWriter, err error) {
	if errors.Is(err, errLastAdmin) {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeStoreErr(w, err)
}
