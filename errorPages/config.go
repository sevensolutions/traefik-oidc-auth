package errorPages

type ErrorPagesConfig struct {
	Unauthorized *ErrorPageConfig `json:"unauthorized"`
}

type ErrorPageConfig struct {
	FilePath string `json:"file_path"`
}
