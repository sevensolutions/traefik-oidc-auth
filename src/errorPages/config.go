package errorPages

type ErrorPagesConfig struct {
	Unauthenticated *ErrorPageConfig `json:"unauthenticated"`
	Unauthorized    *ErrorPageConfig `json:"unauthorized"`
}

type ErrorPageConfig struct {
	FilePath   string `json:"file_path"`
	RedirectTo string `json:"redirect_to"`
}
