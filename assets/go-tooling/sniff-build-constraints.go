// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license included in
// LICENSES/Go-BSD-3-Clause.txt.
//
// Sniff adapted Go's build-header scanner to expose the exact constraint tags
// parsed by the invoking Go toolchain's go/build/constraint package.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/build/constraint"
	"io"
	"os"
	"path/filepath"
	"sort"
)

const schemaVersion = 1

var (
	slashSlash            = []byte("//")
	slashStar             = []byte("/*")
	starSlash             = []byte("*/")
	goBuildComment        = []byte("//go:build")
	errMultipleGoBuild    = errors.New("multiple //go:build comments")
)

type request struct {
	SchemaVersion         int      `json:"schema_version"`
	SourceRepositoryPaths []string `json:"source_repository_paths"`
}

type fileTags struct {
	RepositoryPath string   `json:"repository_path"`
	Tags           []string `json:"tags"`
}

type response struct {
	SchemaVersion int        `json:"schema_version"`
	Files         []fileTags `json:"files"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 {
		return errors.New("constraint discovery requires exactly one request path")
	}
	input, err := os.Open(os.Args[1])
	if err != nil {
		return fmt.Errorf("open constraint request: %w", err)
	}
	defer input.Close()

	var req request
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return fmt.Errorf("decode constraint request: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	if req.SchemaVersion != schemaVersion {
		return fmt.Errorf("unsupported constraint request schema %d", req.SchemaVersion)
	}

	result := response{SchemaVersion: schemaVersion, Files: make([]fileTags, 0, len(req.SourceRepositoryPaths))}
	previous := ""
	for _, path := range req.SourceRepositoryPaths {
		if path == "" || filepath.IsAbs(path) || !filepath.IsLocal(filepath.FromSlash(path)) || (previous != "" && previous >= path) {
			return fmt.Errorf("unsafe or unordered source path %q", path)
		}
		previous = path
		tags, err := tagsForFile(filepath.FromSlash(path))
		if err != nil {
			return fmt.Errorf("inspect %s: %w", path, err)
		}
		result.Files = append(result.Files, fileTags{RepositoryPath: path, Tags: tags})
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("encode constraint response: %w", err)
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("constraint request contains trailing JSON")
		}
		return fmt.Errorf("decode trailing constraint request data: %w", err)
	}
	return nil
}

func tagsForFile(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	header, goBuild, err := parseFileHeader(content)
	if err != nil {
		return nil, err
	}
	tags := make(map[string]struct{})
	if goBuild != nil {
		expr, err := constraint.Parse(string(goBuild))
		if err != nil {
			return nil, fmt.Errorf("parse //go:build line: %w", err)
		}
		collectTags(expr, tags)
	} else {
		for len(header) > 0 {
			line := header
			if i := bytes.IndexByte(line, '\n'); i >= 0 {
				line, header = line[:i], header[i+1:]
			} else {
				header = header[len(header):]
			}
			text := string(bytes.TrimSpace(line))
			if !constraint.IsPlusBuild(text) {
				continue
			}
			expr, err := constraint.Parse(text)
			if err == nil {
				collectTags(expr, tags)
			}
		}
	}

	result := make([]string, 0, len(tags))
	for tag := range tags {
		result = append(result, tag)
	}
	sort.Strings(result)
	return result, nil
}

func collectTags(expr constraint.Expr, tags map[string]struct{}) {
	switch expr := expr.(type) {
	case *constraint.TagExpr:
		tags[expr.Tag] = struct{}{}
	case *constraint.NotExpr:
		collectTags(expr.X, tags)
	case *constraint.AndExpr:
		collectTags(expr.X, tags)
		collectTags(expr.Y, tags)
	case *constraint.OrExpr:
		collectTags(expr.X, tags)
		collectTags(expr.Y, tags)
	}
}

func isGoBuildComment(line []byte) bool {
	if !bytes.HasPrefix(line, goBuildComment) {
		return false
	}
	line = bytes.TrimSpace(line)
	rest := line[len(goBuildComment):]
	return len(rest) == 0 || len(bytes.TrimSpace(rest)) < len(rest)
}

// parseFileHeader is adapted from Go's go/build.parseFileHeader so directive
// placement is interpreted the same way before constraint.Parse sees a line.
func parseFileHeader(content []byte) (trimmed, goBuild []byte, err error) {
	end := 0
	p := content
	ended := false
	inSlashStar := false

Lines:
	for len(p) > 0 {
		line := p
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			line, p = line[:i], p[i+1:]
		} else {
			p = p[len(p):]
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 && !ended {
			end = len(content) - len(p)
			continue Lines
		}
		if !bytes.HasPrefix(line, slashSlash) {
			ended = true
		}
		if !inSlashStar && isGoBuildComment(line) {
			if goBuild != nil {
				return nil, nil, errMultipleGoBuild
			}
			goBuild = line
		}

	Comments:
		for len(line) > 0 {
			if inSlashStar {
				if i := bytes.Index(line, starSlash); i >= 0 {
					inSlashStar = false
					line = bytes.TrimSpace(line[i+len(starSlash):])
					continue Comments
				}
				continue Lines
			}
			if bytes.HasPrefix(line, slashSlash) {
				continue Lines
			}
			if bytes.HasPrefix(line, slashStar) {
				inSlashStar = true
				line = bytes.TrimSpace(line[len(slashStar):])
				continue Comments
			}
			break Lines
		}
	}
	return content[:end], goBuild, nil
}
