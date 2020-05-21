package oauth

import (
  "regexp"
  "unicode/utf8"
  "net/http"
  "io"
	"encoding/json"
)


var emailRegularTemplate = regexp.MustCompile(`^([a-zA-Z0-9._-]+@([a-zA-Z0-9_-]+\.)+[a-zA-Z0-9_-]+)$`)

func ValidEmailReqest(h *Handler, w http.ResponseWriter, r *http.Request, req *EmaiRequest) bool {
	if h.parseRequest(r, &req) != nil {
		h.renderError(w, http.StatusBadRequest, "BadRequest", "Invalid request body")
		return false
	} else if req.Email == nil || !validEmail(*req.Email) {
	 	h.renderError(w, http.StatusBadRequest, "BadRequest", "Invalid email format")
	 	return false
	} else if req.Password == nil || !validPassword(*req.Password) {
 		h.renderError(w, http.StatusBadRequest, "BadRequest", "Invalid password format")
		return false
	}

	return true
}

func validEmail(email string) bool {
	if !utf8.ValidString(email) {
		return false
	}
	return len(emailRegularTemplate.FindAll([]byte(email), -1)) == 1
}

func validPassword(pass string) bool {
	if !utf8.ValidString(pass) {
		return false
	}
	return len(pass) > 5
}

func (h *Handler) parseRequest(r *http.Request, data interface{}) error {
	lr := io.LimitReader(r.Body, 16777216)
	return json.NewDecoder(lr).Decode(data)
}
