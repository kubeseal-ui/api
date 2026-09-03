package handlers

import (
	"encoding/json"
	"net/http"

	handlermw "github.com/kubeseal-ui/api/internal/middleware"
)

type errorBody struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: apiError{Code: code, Message: message, RequestID: requestID(r)}})
}

func requestID(r *http.Request) string {
	if id := handlermw.RequestIDFromContext(r.Context()); id != "" {
		return id
	}
	return r.Header.Get("X-Request-Id")
}
