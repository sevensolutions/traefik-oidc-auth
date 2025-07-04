package errorPages

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
	"os"
	"strings"

	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
)

type ProblemDetails struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

func WriteError(logger *logging.Logger, page *ErrorPageConfig, rw http.ResponseWriter, req *http.Request, data map[string]interface{}) {
	if page.RedirectTo != "" {
		http.Redirect(rw, req, page.RedirectTo, http.StatusFound)
		return
	}

	acceptHeader := req.Header.Get("Accept")

	if strings.HasPrefix(acceptHeader, "application/json") {
		problemDetails := ProblemDetails{
			Type:   data["statusType"].(string),
			Title:  data["statusName"].(string),
			Detail: data["description"].(string),
		}

		writeProblemDetail(logger, problemDetails, rw, data["statusCode"].(int))
	} else {
		html, err := renderPage(logger, page, data)
		if err != nil {
			logger.Log(logging.LevelError, "Error while rendering unauthorized page", err.Error())
			http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}

		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.WriteHeader(data["statusCode"].(int))
		rw.Write([]byte(html))
	}
}

func writeProblemDetail(logger *logging.Logger, problem ProblemDetails, rw http.ResponseWriter, statusCode int) {
	json, err := json.Marshal(problem)
	if err != nil {
		logger.Log(logging.LevelError, err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-Type", "application/json+problem")
	rw.WriteHeader(statusCode)
	rw.Write([]byte(json))
}

func renderPage(logger *logging.Logger, page *ErrorPageConfig, evalContext map[string]interface{}) (string, error) {
	htmlTemplate := `<!DOCTYPE html>
<html>
<head>
  <title>{{ .statusName }}</title>
  <style>
    body {
      width: 100vw;
      height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      font-family: 'Gill Sans', 'Gill Sans MT', Calibri, 'Trebuchet MS', sans-serif
    }
    h1 {
      all: unset;
      text-align: center;
      font-size: 3em;
      font-weight: bold;
      margin-bottom: 0.5em;
    }
    h2 {
      all: unset;
      text-align: center;
      white-space: break-spaces;
    }
    .container {
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
    }
    .error-code {
      color: orange;
      font-size: 1.5em;
    }
    .button-container {
      margin-top: 3em;
      display: flex;
      flex-direction: row;
      align-items: center;
      gap: 2em;
    }
    .button-primary {
      all: unset;
      background-color: orange;
      color: white;
      cursor: pointer;
      padding: 1em;
      border-radius: 0.25em;
      min-width: 5em;
      text-align: center;
    }
    .button-secondary {
      all: unset;
      color: orange;
      cursor: pointer;
    }
    .footer {
      position: absolute;
      bottom: 2em;
      color: #aaa;
      font-weight: 100;
    }
    .footer a {
      all: unset;
      cursor: pointer;
    }
  </style>
</head>

<body>
  <div class="container">
    <span class="error-code">{{ .statusCode }}</span>
    <h1>{{ .statusName }}</h1>
    <h2>{{ .description }}</h2>
    
    <div class="button-container">
      {{ if .primaryButtonUrl }}
      <a href="{{ .primaryButtonUrl }}" class="button-primary">{{ .primaryButtonText }}</a>
      {{ end }}
      {{ if .secondaryButtonUrl }}
      <a href="{{ .secondaryButtonUrl }}" class="button-secondary">{{ .secondaryButtonText }}</a>
      {{ end }}
    </div>

    <div class="footer">
      <a href="https://traefik-oidc-auth.sevensolutions.cc/" target="_blank">Powered by traefik-oidc-auth</a>
    </div>
  </div>
</body>
</html>`

	if page.FilePath != "" {
		templateData, err := os.ReadFile(page.FilePath)
		if err != nil {
			logger.Log(logging.LevelWarn, "Error while reading error page file \"%s\": %s", page.FilePath, err.Error())
		} else {
			htmlTemplate = string(templateData)
		}
	}

	tpl, err := template.New("").Parse(htmlTemplate)
	if err != nil {
		return "", err
	}

	var renderedValue bytes.Buffer
	err = tpl.Execute(&renderedValue, evalContext)
	if err != nil {
		return "", err
	}

	return renderedValue.String(), nil
}
