// Package oauth provides an HTTP handler to handle OAuth2
// redirect and callback requests for the bebop web app.
package oauth

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"golang.org/x/oauth2"

	"github.com/disintegration/bebop/jwt"
	"github.com/disintegration/bebop/store"
)


const clientTimeout = 10 * time.Second

// Config is a configuration of an OAuth handler.
type Config struct {
	Logger     *log.Logger
	UserStore  store.UserStore
	JWTService jwt.Service
	MountURL   string
	CookiePath string
}

// Handler handles oauth2 authentication requests.
type Handler struct {
	*Config
	providers map[string]*provider
	router    chi.Router
}

//Email request signin and signup structure
type EmaiRequest struct {
	Email   *string `json:"email"`
	Password *string `json:"password"`
}

// New creates a new handler based on the given config.
func New(config *Config) *Handler {
	h := &Handler{Config: config}
	h.providers = make(map[string]*provider)
	h.router = chi.NewRouter()
	h.router.Get("/begin/{provider}", h.handleBegin)
	h.router.Get("/end/{provider}", h.handleEnd)
	h.router.Post("/emailSignUp", h.handleEmailSignUp)
	h.router.Post("/emailSignIn", h.handleEmailSignIn)

	return h
}

//Server requests
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.router.ServeHTTP(w, r)
}

// AddProvider adds a new provider to oauth handler.
func (h *Handler) AddProvider(name, id, secret string) error {
	h.Logger.Printf("in AddProvider")
	h.Logger.Printf(name)
	pc, ok := providerConfigs[name]
	if !ok {
		return fmt.Errorf("oauth: unknown provider: %q", name)
	}

	if id == "" {
		return fmt.Errorf("oauth: empty client id of provider %q", name)
	} else if secret == "" {
		return fmt.Errorf("oauth: empty client secret of provider %q", name)
	} else if h.providers == nil {
		h.providers = make(map[string]*provider)
	}

	h.providers[name] = &provider{
		config: &oauth2.Config{
			ClientID:     id,
			ClientSecret: secret,
			RedirectURL:  h.MountURL + "/end/" + name,
			Endpoint:     pc.endpoint,
			Scopes:       pc.scopes,
		},
		getUser: pc.getUser,
	}

	return nil
}

func (h *Handler) handleEmailSignIn(w http.ResponseWriter, r *http.Request) {
	req := EmaiRequest{}
	if !validEmailReqest(w, &r, &req) {
		return
	}

	SetStateCookie(&h, w, 3600)
	h.Logger.Printf("email")
	h.Logger.Printf(*req.Email)

	user, err := h.UserStore.GetByEmailPassword(*req.Email, *req.Password)
	switch err {
		case nil:
			if user.Blocked {
				h.renderOAuthResult(w, "error:UserBlocked")
				return
			}

			authToken, tokenErr := h.JWTService.Create(user.ID)
			if tokenErr != nil {
				h.handleError(w, "failed to create auth token: %s", tokenErr)
				return
			}
			SetResultCookie(&h, w, "success:"+authToken, 3600)
			h.Logger.Printf("redir url: %s", w)
			fmt.Fprint(w, `success`)
			return

		case store.ErrNotFound:
			fmt.Fprint(w, `Incorrect email or password`)
			return

		default:
			h.handleError(w, "failed to get user by auth: %s", err)
			return
	}
}

func (h *Handler) handleEmailSignUp(w http.ResponseWriter, r *http.Request) {
	req := EmaiRequest{}
	if !validEmailReqest(w, &r, &req) {
		return
	}

	SetStateCookie(&h, w, 3600)
	h.Logger.Printf("email")
	h.Logger.Printf(*req.Email)

	user, err := h.UserStore.GetByEmailPassword(*req.Email,*req.Password)
	switch err {
		case nil:
			if user.Blocked {
				h.renderOAuthResult(w, "error:UserBlocked")
				return
			}

			h.handleError(w, "error:UserAlreayRegistred")
			return

		case store.ErrNotFound:
			userID, err := h.UserStore.New("email", *req.Email, *req.Password)
			if err != nil {
				h.handleError(w, "failed to create user: %s", err)
				return
			}

			authToken, err = h.JWTService.Create(userID)
			if err != nil {
				h.handleError(w, "failed to create auth token: %s", err)
				return
			}
			SetResultCookie(&h, w, "success:"+authToken, 3600)
			h.Logger.Printf("redir url: %s", w)
			fmt.Fprint(w, `success`)
			return

		default:
			h.handleError(w, "failed to get user by auth: %s", err)
			return
	}
}

func (h *Handler) handleBegin(w http.ResponseWriter, r *http.Request) {
	h.Logger.Printf("in handleBegin")
	providerName := chi.URLParam(r, "provider")
	provider, ok := h.providers[providerName]
	if !ok {
		http.NotFound(w, r)
		return
	}

	redirectURL := "localhost:5000/#"
	if providerName != "email" {
		redirectURL = provider.config.AuthCodeURL(state)
	}

	SetStateCookie(&h, w, 3600)
	h.Logger.Printf("path: %s", h.CookiePath)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (h *Handler) handleEnd(w http.ResponseWriter, r *http.Request) {
	h.Logger.Printf("in handleEnd")
	providerName := chi.URLParam(r, "provider")
	h.Logger.Printf("providerName: %s", providerName)

	provider, ok := h.providers[providerName]
	if !ok {
		h.Logger.Printf("in not found")
		http.NotFound(w, r)
		return
	}

	cookie, err := r.Cookie(STATE_COOKIE)
	if err != nil {
		h.handleError(w, "failed to get oauth state cookie: %s", err)
		return
	}

	state := cookie.Value
	if state == "" {
		h.handleError(w, "empty oauth state cookie")
		return
	}

	queryState := r.URL.Query().Get("state")
	h.Logger.Printf("queryState: %s", queryState)
	h.Logger.Printf("state: %s", state)
	if queryState != state {
		h.handleError(w, "bad state value")
		return
	}

	queryCode := r.URL.Query().Get("code")
	if queryCode == "" {
		h.handleError(w, "empty code value")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), clientTimeout)
	defer cancel()

	token, err := provider.config.Exchange(ctx, queryCode)
	if err != nil {
		h.handleError(w, "exchange failed: %s", err)
		return
	} else if !token.Valid() {
		h.handleError(w, "invalid token")
		return
	}

	u, err := provider.getUser(provider.config.Client(ctx, token))
	if err != nil {
		h.handleError(w, "get provider user: %s", err)
		return
	} else if u.id == "" {
		h.handleError(w, "provider user id is empty")
		return
	}


	user, err := h.UserStore.GetByAuth(providerName, u.id)
	switch err {
		case nil:
			if user.Blocked {
				h.renderOAuthResult(w, "error:UserBlocked")
				return
			}

			authToken, err := h.JWTService.Create(user.ID)
			if err != nil {
				h.handleError(w, "failed to create auth token: %s", err)
				return
			}
			h.renderOAuthResult(w, "success:"+authToken)
			return

		case store.ErrNotFound:
			userID, err := h.UserStore.New(providerName, u.id, "")
			if err != nil {
				h.handleError(w, "failed to create user: %s", err)
				return
			}

			authToken, err = h.JWTService.Create(userID)
			if err != nil {
				h.handleError(w, "failed to create auth token: %s", err)
				return
			}
			h.renderOAuthResult(w, "success:"+authToken)
			return

		default:
			h.handleError(w, "failed to get user by auth: %s", err)
			return
	}
}

func (h *Handler) renderOAuthResult(w http.ResponseWriter, message string) {
	SetResultCookie(&h, w, message, 600)
	h.Logger.Printf("redir url: %s", w)
	fmt.Fprint(w, `<!doctype html><title>OAuth</title><script>try {opener.bebopOAuthEnd()} finally {window.close()}</script>`)
}

func (h *Handler) renderError(w http.ResponseWriter, status int, code, message string) {
	response := struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{}
	response.Error.Code = code
	response.Error.Message = message
	h.render(w, status, response)
}

func (h *Handler) render(w http.ResponseWriter, status int, data interface{}) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		h.logError("marshal json: %s", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(jsonData)
}

func (h *Handler) logError(format string, a ...interface{}) {
	pc, _, _, _ := runtime.Caller(1)
	callerNameSplit := strings.Split(runtime.FuncForPC(pc).Name(), ".")
	funcName := callerNameSplit[len(callerNameSplit)-1]
	h.Logger.Printf("ERROR: %s: %s", funcName, fmt.Sprintf(format, a...))
}

func (h *Handler) handleError(w http.ResponseWriter, format string, a ...interface{}) {
	logError(format, a)
	h.renderOAuthResult(w, "error:Other")
}
