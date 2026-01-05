package mgt

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strconv"
)

var translationRegex = regexp.MustCompile(`\{\{t\(([^:]+):([^:]+)\)\}\}`)

type responseWriter struct {
	http.ResponseWriter
	status int
	body   *bytes.Buffer
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	rw.body.Write(b)
	return len(b), nil
}

func recursiveTranslate(v interface{}, i18nService I18nServiceInterface, language string) interface{} {
	switch val := v.(type) {
	case string:
		matches := translationRegex.FindStringSubmatch(val)
		if len(matches) == 3 {
			namespace := matches[1]
			key := matches[2]
			translation, err := i18nService.ResolveTranslationsForKey(language, namespace, key)
			if err != nil {
				return val
			}
			return translation.Value
		}
		return val
	case map[string]interface{}:
		newMap := make(map[string]interface{})
		for k, v := range val {
			newMap[k] = recursiveTranslate(v, i18nService, language)
		}
		return newMap
	case []interface{}:
		newSlice := make([]interface{}, len(val))
		for i, v := range val {
			newSlice[i] = recursiveTranslate(v, i18nService, language)
		}
		return newSlice
	default:
		return val
	}
}

// middleware returns an HTTP middleware function that applies security checks to requests.
func I18nMiddleware(next http.Handler, i18nService I18nServiceInterface) (http.Handler, error) {
	if i18nService == nil {
		return nil, errors.New("i18n service cannot be nil")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		preferredLang := r.Header.Get("X-Preferred-Lang")
		if preferredLang == "" {
			next.ServeHTTP(w, r)
			return
		}

		rw := &responseWriter{
			ResponseWriter: w,
			status:         http.StatusOK,
			body:           &bytes.Buffer{},
		}

		next.ServeHTTP(rw, r)

		var response interface{}
		if err := json.Unmarshal(rw.body.Bytes(), &response); err != nil {
			// Not JSON or empty, write original
			log.Printf("Failed to unmarshal response: %v", err)
			w.WriteHeader(rw.status)
			w.Write(rw.body.Bytes())
			return
		}

		// Recursively translate
		newResponse := recursiveTranslate(response, i18nService, preferredLang)

		newBody, err := json.Marshal(newResponse)
		if err != nil {
			log.Printf("Failed to marshal new response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Length", strconv.Itoa(len(newBody)))
		w.WriteHeader(rw.status)
		w.Write(newBody)
	}), nil
}
