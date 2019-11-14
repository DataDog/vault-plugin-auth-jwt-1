package jwtauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	directory "google.golang.org/api/admin/directory/v1"

	"golang.org/x/oauth2/jwt"
)

// tryToAddGSuiteMetadata adds claims from gsuite metadata for department and teams
func (b *jwtAuthBackend) tryToAddGSuiteMetadata(config *jwtConfig, claims map[string]interface{}) error {
	// if config is not defined, skip
	if config.GSuiteServiceAccountEmail == "" || config.GSuiteServiceAccountPrivateKeyID == "" ||
		config.GSuiteServiceAccountPrivateKey == "" || config.GSuiteImpersonateEmail == "" {

		b.Logger().Warn("skipping gsuite metadata, config missing")
		return nil
	}

	svc, err := newGSuiteDirectoryClient(
		config.GSuiteImpersonateEmail, config.GSuiteServiceAccountEmail,
		config.GSuiteServiceAccountPrivateKeyID, config.GSuiteServiceAccountPrivateKey)
	if err != nil {
		return err
	}

	userEmail, haveUserEmail := claims["email"].(string)
	if !haveUserEmail {
		return errors.New("email claim missing or malformed")
	}

	user, err := getGSuiteUser(svc, userEmail)
	if err != nil {
		return err
	}

	emailParts := strings.Split(userEmail, "@")
	if len(emailParts) < 1 {
		return errors.New("email malformed")
	}
	claims["gsuite_username"] = emailParts[0]

	metadataAttributes := []interface{}{}

	dept := extractDepartmentFromUser(user)
	claims["gsuite_department"] = dept

	deptPrefix := "dept-"
	if !strings.HasPrefix(dept, deptPrefix) {
		dept = deptPrefix + dept
	}
	metadataAttributes = append(metadataAttributes, "gsuite-"+dept)

	teamPrefix := "team-"
	teams := []interface{}{}
	for _, team := range extractTeamsFromUser(user) {
		teams = append(teams, team)

		if !strings.HasPrefix(team, teamPrefix) {
			team = teamPrefix + team
		}
		metadataAttributes = append(metadataAttributes, "gsuite-"+team)
	}
	claims["gsuite_teams"] = teams

	groups, err := googleGroups(user, svc)
	if err != nil {
		return errors.New("Unable to lookup group memeberships of user")
	}
	metadataAttributes = append(metadataAttributes, groups)

	b.Logger().Debug("gsuite_metadata claims: %v", metadataAttributes)
	claims["gsuite_metadata"] = metadataAttributes
	return nil
}

func newGSuiteDirectoryClient(impersonateEmail, serviceAccountEmail, serviceAccountPrivateKeyID, serviceAccountPrivateKey string) (*directory.Service, error) {
	tokenURI := "https://accounts.google.com/o/oauth2/token"

	config := &jwt.Config{
		Email:        serviceAccountEmail,
		PrivateKey:   []byte(strings.ReplaceAll(serviceAccountPrivateKey, `\n`, "\n")),
		PrivateKeyID: serviceAccountPrivateKeyID,

		// Docs: https://developers.google.com/identity/protocols/OAuth2ServiceAccount#delegatingauthority
		Scopes:   []string{directory.AdminDirectoryUserReadonlyScope},
		Subject:  impersonateEmail,
		TokenURL: tokenURI,
	}
	return directory.New(config.Client(context.Background()))
}

func getGSuiteUser(svc *directory.Service, email string) (*directory.User, error) {
	user, err := svc.Users.Get(email).Projection("full").Do()
	if err != nil {
		return nil, err
	}

	if user.Suspended {
		return nil, errors.New("user is suspended")
	}

	return user, nil
}

// returns the normalized name for the user's primary department.
// if there is no department, an empty string is returned.
func extractDepartmentFromUser(u *directory.User) string {
	orgType := reflect.TypeOf(u.Organizations)

	if orgType == nil {
		return ""
	}

	if orgType.Kind() != reflect.Slice {
		return ""
	}

	data := reflect.Indirect(reflect.ValueOf(u.Organizations))
	for i := 0; i < reflect.ValueOf(u.Organizations).Len(); i++ {
		org, ok := data.Index(i).Interface().(map[string]interface{})
		if !ok {
			continue
		}

		primary, ok := org["primary"].(bool)
		if !ok || !primary {
			continue
		}

		dept, ok := org["department"].(string)
		if ok {
			return normalize(dept)
		}
	}

	return ""
}

// returns a list of teams from the users gsuite metadata
func extractTeamsFromUser(u *directory.User) []string {
	return extractAttributes(u, "Additional_Information", "Teams")
}

// returns a normalized list of the users custom attributes by category and name
func extractAttributes(u *directory.User, category, name string) []string {
	if u == nil || len(u.CustomSchemas) == 0 {
		return nil
	}

	// return if the user has no custom schemas for the requested key
	raw, ok := u.CustomSchemas[category]
	if !ok {
		return nil
	}

	// Google stores the schema/attribute as a raw json blob with no
	// hint as to whether it's an object or list of objects
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil
	}

	var attrs []string

	for k, v := range decoded {
		if k != name {
			continue
		}

		typeOf := reflect.TypeOf(v)

		if typeOf == nil {
			continue
		}

		kind := typeOf.Kind()

		switch kind {
		case reflect.Bool:
			// convert bool to string
			attrs = append(attrs, normalize(fmt.Sprintf("%t", v)))
			return attrs
		case reflect.String:
			attrs = append(attrs, normalize(v.(string)))
			return attrs
		case reflect.Slice:
			data := reflect.Indirect(reflect.ValueOf(v))

			for i := 0; i < reflect.ValueOf(v).Len(); i++ {
				attr, ok := data.Index(i).Interface().(map[string]interface{})
				if !ok {
					continue
				}

				a, ok := attr["value"]
				if !ok {
					continue
				}

				str, ok := a.(string)
				if ok {
					attrs = append(attrs, normalize(str))
				}
			}
		default:
			// there shouldn't be other kinds
		}
	}

	return attrs
}

// googleGroups returns a list of Google groups that email is a member of.
func googleGroups(u *directory.User, client *directory.Service) ([]string, error) {
	groupsList, err := client.Groups.List().UserKey(u.Id).Do()
	if err != nil {
		return nil, err
	}

	var groups []string
	for _, g := range groupsList.Groups {
		groups = append(groups, g.Name)
	}

	// Populate policies if the equivalent Google group exists
	var claims []string
	groupPrefix := "gsuite-group-"
	for _, group := range groups {
		if !strings.HasPrefix(group, groupPrefix) {
			group = groupPrefix + group
		}

		claims = append(claims, normalize(group))
	}

	return claims, nil
}

// returns the lowercased string with all spaces removed and underscores converted to dashes
func normalize(s string) string {
	s = strings.ToLower(s)
	s = strings.Replace(s, " ", "", -1)
	s = strings.Replace(s, "_", "-", -1)

	return s
}
