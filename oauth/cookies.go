package oauth

import (
  "net/http"
  "github.com/satori/go.uuid"
  "strings"
)


const (
  STATE_COOKIE = "bebop_oauth_state"
  RESULT_COOKIE = "bebop_oauth_state"
)

func SetStateCookie(h *Handler, w http.ResponseWriter, maxAge int) {
  setCookie(&h, w, RESULT_COOKIE, genUnicOperationId(), maxAge)
}

func SetResultCookie(h *Handler, w http.ResponseWriter, res string, maxAge int) {
  setCookie(&h, w, RESULT_COOKIE, res, maxAge)
}

func setCookie(h *Handler, w http.ResponseWriter, name string, value string, maxAge int) {
  http.SetCookie(w, &http.Cookie{
    Name:     name,
		Value:    value,
		Path:     h.CookiePath,
		Secure:   strings.HasPrefix(h.MountURL, "https"),
		MaxAge:   maxAge,
	})
}

func genUnicOperationId() string {
	return uuid.NewV4().String()
}
