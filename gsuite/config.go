package gsuite

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/helper/logging"
	"github.com/hashicorp/terraform-plugin-sdk/helper/pathorcontents"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"

	directory "google.golang.org/api/admin/directory/v1"
	groupSettings "google.golang.org/api/groupssettings/v1"
)

var defaultOauthScopes = []string{
	directory.AdminDirectoryGroupScope,
	directory.AdminDirectoryUserScope,
	directory.AdminDirectoryUserschemaScope,
}

// Config is the structure used to instantiate the GSuite provider.
type Config struct {
	Credentials string

	AccessToken string

	// Only users with access to the Admin APIs can access the Admin SDK Directory API,
	// therefore the service account needs to impersonate one of those users to access the Admin SDK Directory API.
	// See https://developers.google.com/admin-sdk/directory/v1/guides/delegation
	ImpersonatedUserEmail string

	CustomerId string

	OauthScopes []string

	directory     *directory.Service
	groupSettings *groupSettings.Service

	tokenSource oauth2.TokenSource
}

// loadAndValidate loads the application default credentials from the
// environment and creates a client for communicating with Google APIs.
func (c *Config) loadAndValidate(terraformVersion string) error {
	log.Println("[INFO] Building gsuite client config structure")
	var account accountFile

	oauthScopes := c.OauthScopes

	var client *http.Client
	if c.AccessToken != "" {
		tokenSource, err := c.getTokenSource(oauthScopes)
		if err != nil {
			return err
		}
		c.tokenSource = tokenSource
		client = oauth2.NewClient(context.Background(), tokenSource)
	} else if c.Credentials != "" {
		if c.ImpersonatedUserEmail == "" {
			return fmt.Errorf("required field missing: impersonated_user_email")
		}

		contents, _, err := pathorcontents.Read(c.Credentials)
		if err != nil {
			return fmt.Errorf("Error loading credentials: %s", err)
		}

		// Assume account_file is a JSON string
		if err := parseJSON(&account, contents); err != nil {
			return fmt.Errorf("Error parsing credentials '%s': %s", contents, err)
		}

		// Get the token for use in our requests
		log.Printf("[INFO] Requesting Google token...")
		log.Printf("[INFO]   -- Email: %s", account.ClientEmail)
		log.Printf("[INFO]   -- Scopes: %s", oauthScopes)
		log.Printf("[INFO]   -- Private Key Length: %d", len(account.PrivateKey))

		conf := jwt.Config{
			Email:      account.ClientEmail,
			PrivateKey: []byte(account.PrivateKey),
			Scopes:     oauthScopes,
			TokenURL:   "https://oauth2.googleapis.com/token",
		}

		conf.Subject = c.ImpersonatedUserEmail

		// Initiate an http.Client. The following GET request will be
		// authorized and authenticated on the behalf of
		// your service account.
		client = conf.Client(context.Background())
	} else {
		log.Printf("[INFO] Authenticating using DefaultClient")
		err := error(nil)
		client, err = google.DefaultClient(context.Background(), oauthScopes...)
		if err != nil {
			return errors.Wrap(err, "failed to create client")
		}
	}

	// Use a custom user-agent string. This helps google with analytics and it's
	// just a nice thing to do.
	client.Transport = logging.NewTransport("Google", client.Transport)
	userAgent := fmt.Sprintf("(%s %s) Terraform/%s",
		runtime.GOOS, runtime.GOARCH, terraformVersion)

	// Each individual request should return within 30s - timeouts will be retried.
	// This is a timeout for, e.g. a single GET request of an operation - not a
	// timeout for the maximum amount of time a logical request can take.
	client.Timeout, _ = time.ParseDuration("30s")

	// Create the directory service.
	directorySvc, err := directory.New(client)
	if err != nil {
		return nil
	}
	directorySvc.UserAgent = userAgent
	c.directory = directorySvc

	// Create the groupSettings service.
	groupSettingsSvc, err := groupSettings.New(client)
	if err != nil {
		return nil
	}
	groupSettingsSvc.UserAgent = userAgent
	c.groupSettings = groupSettingsSvc

	return nil
}

// accountFile represents the structure of the account file JSON file.
type accountFile struct {
	PrivateKeyId string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	ClientId     string `json:"client_id"`
}

func parseJSON(result interface{}, contents string) error {
	r := strings.NewReader(contents)
	dec := json.NewDecoder(r)

	return dec.Decode(result)
}

func (c *Config) getTokenSource(oauthScopes []string) (oauth2.TokenSource, error) {
	contents, _, err := pathorcontents.Read(c.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("Error loading access token: %s", err)
	}

	log.Printf("[INFO] Authenticating using configured Google JSON 'access_token'")
	token := &oauth2.Token{AccessToken: contents}

	return oauth2.StaticTokenSource(token), nil
}
