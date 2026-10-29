package main

import (
	"flag"
	"reflect"
	"testing"
)

func TestParseFlagsLenient(t *testing.T) {
	t.Run("flags after positional arguments", func(t *testing.T) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		target := fs.String("target", "", "target format")
		strict := fs.Bool("strict", false, "strict mode")

		args := []string{"routewarden.json", "--target", "caddy", "--strict"}
		err := parseFlagsLenient(fs, args)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if *target != "caddy" {
			t.Errorf("expected target=caddy, got %s", *target)
		}
		if !*strict {
			t.Errorf("expected strict=true")
		}
		if !reflect.DeepEqual(fs.Args(), []string{"routewarden.json"}) {
			t.Errorf("expected positional args [routewarden.json], got %v", fs.Args())
		}
	})

	t.Run("flags before positional arguments", func(t *testing.T) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		format := fs.String("format", "text", "format")
		strict := fs.Bool("strict", false, "strict mode")

		args := []string{"--format", "json", "--strict", "file1.json", "file2.json"}
		err := parseFlagsLenient(fs, args)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if *format != "json" {
			t.Errorf("expected format=json, got %s", *format)
		}
		if !*strict {
			t.Errorf("expected strict=true")
		}
		if !reflect.DeepEqual(fs.Args(), []string{"file1.json", "file2.json"}) {
			t.Errorf("expected positional args [file1.json file2.json], got %v", fs.Args())
		}
	})

	t.Run("flag with equals sign", func(t *testing.T) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		port := fs.Int("port", 8080, "port")

		args := []string{"--port=9090", "positional"}
		err := parseFlagsLenient(fs, args)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if *port != 9090 {
			t.Errorf("expected port=9090, got %d", *port)
		}
		if !reflect.DeepEqual(fs.Args(), []string{"positional"}) {
			t.Errorf("expected positional args [positional], got %v", fs.Args())
		}
	})

	t.Run("stdin dash as positional argument", func(t *testing.T) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		strict := fs.Bool("strict", false, "strict")

		args := []string{"--strict", "-"}
		err := parseFlagsLenient(fs, args)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !*strict {
			t.Errorf("expected strict=true")
		}
		if !reflect.DeepEqual(fs.Args(), []string{"-"}) {
			t.Errorf("expected positional args [-], got %v", fs.Args())
		}
	})

	t.Run("double dash terminator", func(t *testing.T) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		format := fs.String("format", "text", "format")

		args := []string{"--format", "json", "--", "pos1", "pos2"}
		err := parseFlagsLenient(fs, args)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if *format != "json" {
			t.Errorf("expected format=json, got %s", *format)
		}
		if !reflect.DeepEqual(fs.Args(), []string{"pos1", "pos2"}) {
			t.Errorf("expected positional args [pos1 pos2], got %v", fs.Args())
		}
	})

	t.Run("help flag handling", func(t *testing.T) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.SetOutput(&dummyWriter{})

		args := []string{"--help", "positional"}
		err := parseFlagsLenient(fs, args)
		if err == nil {
			t.Errorf("expected ErrHelp error from --help flag")
		}
	})

	t.Run("dashboard up flags with positional log file", func(t *testing.T) {
		fs := flag.NewFlagSet("dashboard", flag.ContinueOnError)
		port := fs.Int("port", 7890, "port")
		file := fs.String("file", "", "file")
		auth := fs.String("auth", "", "auth")

		args := []string{"/var/log/access.log", "--port", "8888", "--auth", "admin:secret"}
		err := parseFlagsLenient(fs, args)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if *port != 8888 {
			t.Errorf("expected port=8888, got %d", *port)
		}
		if *auth != "admin:secret" {
			t.Errorf("expected auth=admin:secret, got %s", *auth)
		}
		if len(fs.Args()) != 1 || fs.Args()[0] != "/var/log/access.log" {
			t.Errorf("expected positional arg [/var/log/access.log], got %v", fs.Args())
		}
		if *file == "" && fs.NArg() > 0 {
			*file = fs.Arg(0)
		}
		if *file != "/var/log/access.log" {
			t.Errorf("expected file=/var/log/access.log, got %s", *file)
		}
	})

	t.Run("flag value starting with dash", func(t *testing.T) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		header := fs.String("header", "", "header")

		args := []string{"--header", "-X-Header: value", "pos1"}
		err := parseFlagsLenient(fs, args)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if *header != "-X-Header: value" {
			t.Errorf("expected header='-X-Header: value', got %q", *header)
		}
		if !reflect.DeepEqual(fs.Args(), []string{"pos1"}) {
			t.Errorf("expected positional args [pos1], got %v", fs.Args())
		}
	})

	t.Run("unknown flag does not consume next positional arg", func(t *testing.T) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.SetOutput(&dummyWriter{})

		args := []string{"-unknown-flag", "pos1", "pos2"}
		err := parseFlagsLenient(fs, args)
		if err == nil {
			t.Errorf("expected error for unknown flag")
		}
	})

	t.Run("combined space-separated flags in single argument", func(t *testing.T) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		docker := fs.Bool("docker", false, "docker mode")
		allTraffic := fs.Bool("all-traffic", false, "all traffic mode")

		args := []string{"-docker --all-traffic"}
		err := parseFlagsLenient(fs, args)
		if err != nil {
			t.Fatalf("unexpected error parsing combined flags: %v", err)
		}
		if !*docker {
			t.Errorf("expected docker=true")
		}
		if !*allTraffic {
			t.Errorf("expected allTraffic=true")
		}
	})
}

type dummyWriter struct{}

func (d *dummyWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}
