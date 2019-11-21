package jwtauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	log "github.com/hashicorp/go-hclog"
	directory "google.golang.org/api/admin/directory/v1"

	"golang.org/x/oauth2/jwt"
)

const tokenURI = "https://accounts.google.com/o/oauth2/token"
const groupClaimPrefix = "gsuite-group-"

// tryToAddGSuiteMetadata adds claims from gsuite metadata for department and teams
func (b *jwtAuthBackend) tryToAddGSuiteMetadata(config *jwtConfig, claims map[string]interface{}) error {
	b.Logger().Trace("Attempting to enhance claims with Gsuite based data")

	// if config is not defined, skip
	if !b.checkGsuiteCredentialsAreConfigured(config) {
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

	email, err := parseEmail(userEmail)
	claims["gsuite_username"] = email.localpart

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

	client := &directoryClient {
		log: b.Logger(),
		service: svc,
	}
	groups, err := client.groupClaimsFor(user)
	if err != nil {
		return fmt.Errorf("unable to lookup group memberships of user (%e)", err)
	}

	for _, group := range groups {
		metadataAttributes = append(metadataAttributes, group)
	}

	claims["gsuite_metadata"] = metadataAttributes
	b.Logger().Trace("claims for " + userEmail, "values", claims)
	return nil
}

// it would be more ideal to just do this configuration when the jwtAuthConfig backend is initialized
// and store that result once, or swap in a no-op function in place of an "enhance" function based on that result
// but in the interest of maximizing how many of our forked changes are in files that are not part of the upstream
// fork, to make patching in updates less of a headache, this is currently called once per login request to
// this backend
func (b *jwtAuthBackend) checkGsuiteCredentialsAreConfigured(config *jwtConfig) bool {
	configured := true

	if config.GSuiteServiceAccountEmail == "" {
		b.Logger().Warn("Skipping Gsuite based claims enhancement: `gsuite_service_account_email` not configured")
		configured = false
	}

	if config.GSuiteServiceAccountPrivateKeyID == "" {
		b.Logger().Warn("Skipping Gsuite based claims enhancement: `gsuite_service_account_private_key_id` not configured")
		configured = false
	}

	if config.GSuiteServiceAccountPrivateKey == "" {
		b.Logger().Warn("Skipping Gsuite based claims enhancement: `gsuite_service_account_private_key` not configured")
		configured = false
	}

	if config.GSuiteImpersonateEmail == "" {
		b.Logger().Warn("Skipping Gsuite based claims enhancement: `gsuite_impersonate_email` not configured")
		configured = false
	}

	return configured
}

func newGSuiteDirectoryClient(impersonateEmail, serviceAccountEmail, serviceAccountPrivateKeyID, serviceAccountPrivateKey string) (*directory.Service, error) {
	config := &jwt.Config{
		Email:        serviceAccountEmail,
		PrivateKey:   []byte(strings.ReplaceAll(serviceAccountPrivateKey, `\n`, "\n")),
		PrivateKeyID: serviceAccountPrivateKeyID,

		// Docs: https://developers.google.com/identity/protocols/OAuth2ServiceAccount#delegatingauthority
		Scopes:   []string{
			directory.AdminDirectoryUserReadonlyScope,
			directory.AdminDirectoryGroupReadonlyScope,
		},
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

type directoryClient struct {
	service *directory.Service
	log log.Logger
}

// googleGroups returns a list of Google groups that email is a member of.
func (client *directoryClient) groupClaimsFor(u *directory.User) ([]string, error) {
	groupsList, err := client.service.Groups.List().UserKey(u.Id).Do()
	if err != nil {
		return nil, err
	}

	var claims []string
	for _, g := range groupsList.Groups {
		client.log.Trace("Processing group", "name", g.Name, "email", g.Email)
		email, err := parseEmail(g.Email)
		if err != nil {
			return nil, err
		}

		// The API call we use does not appear to return external group memberships,
		// such as the Vault public mailing list, at this time. But for the sake of
		// guarding against future Google "feature enhancements" we only include group
		// claims that are from the datadoghq.com domain
		if email.domain != "datadoghq.com" {
			client.log.Warn("Found unexpected group membership for non-datadoghq.com domain",
				"user", u.Name.FullName, "group address", g.Email, "group name", g.Name)
			break
		}

		group := email.localpart
		claim := normalize(groupClaimPrefix + group)
		claims = append(claims, claim)
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

type email struct {
	localpart string
	domain string
}

func parseEmail(e string) (email, error) {
	var parsed email
	emailParts := strings.Split(e, "@")
	if len(emailParts) < 1 {
		return parsed, fmt.Errorf("email malformed (%s)", e)
	}

	return email{
		localpart: emailParts[0],
		domain: emailParts[1],
	}, nil
}