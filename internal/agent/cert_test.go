package agent

import (
	"reflect"
	"testing"
)

func TestCertificateCovers(t *testing.T) {
	tests := []struct {
		name   string
		cert   Certificate
		domain string
		want   bool
	}{
		{"точное совпадение", Certificate{Domain: "foo.example.com"}, "foo.example.com", true},
		{"чужой домен", Certificate{Domain: "foo.example.com"}, "bar.example.com", false},
		{"апекс зоны", Certificate{Domain: "example.com", Wildcard: true}, "example.com", true},
		{"поддомен зоны", Certificate{Domain: "example.com", Wildcard: true}, "docs.example.com", true},
		{"второй уровень вглубь", Certificate{Domain: "example.com", Wildcard: true}, "a.docs.example.com", false},
		{"похожее окончание", Certificate{Domain: "example.com", Wildcard: true}, "notexample.com", false},
		{"без wildcard поддомен не покрыт", Certificate{Domain: "example.com"}, "docs.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cert.Covers(tt.domain); got != tt.want {
				t.Errorf("Covers(%q) = %v, ожидалось %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestCertificatesGroupsUnderZone(t *testing.T) {
	cfg := &Config{
		WildcardZones: []string{"example.com"},
		Endpoints: []Endpoint{
			{Domain: "docs.example.com"},
			{Domain: "wiki.example.com"},
			{Domain: "app.other.net"},
		},
	}

	want := []Certificate{
		{Domain: "example.com", Wildcard: true},
		{Domain: "app.other.net"},
	}

	if got := cfg.Certificates(); !reflect.DeepEqual(got, want) {
		t.Errorf("Certificates() = %+v, ожидалось %+v", got, want)
	}
}

// Без объявленной зоны поведение прежнее: сертификат на каждый эндпоинт.
func TestCertificatesWithoutZones(t *testing.T) {
	cfg := &Config{Endpoints: []Endpoint{
		{Domain: "docs.example.com"},
		{Domain: "wiki.example.com"},
	}}

	want := []Certificate{{Domain: "docs.example.com"}, {Domain: "wiki.example.com"}}

	if got := cfg.Certificates(); !reflect.DeepEqual(got, want) {
		t.Errorf("Certificates() = %+v, ожидалось %+v", got, want)
	}
}

// Апекс зоны не должен заводить второй сертификат с тем же именем.
func TestCertificatesApexUsesZoneCert(t *testing.T) {
	cfg := &Config{
		WildcardZones: []string{"example.com"},
		Endpoints:     []Endpoint{{Domain: "example.com"}, {Domain: "docs.example.com"}},
	}

	got := cfg.Certificates()
	if len(got) != 1 {
		t.Fatalf("ожидался один сертификат, получено %+v", got)
	}
	if !got[0].Wildcard || got[0].Domain != "example.com" {
		t.Errorf("сертификат зоны = %+v", got[0])
	}
}

func TestCertNamesMapsEndpointsToCert(t *testing.T) {
	cfg := &Config{
		WildcardZones: []string{"example.com"},
		Endpoints: []Endpoint{
			{Domain: "docs.example.com"},
			{Domain: "app.other.net"},
		},
	}

	names := certNames(cfg.Certificates(), cfg.Endpoints)

	if names["docs.example.com"] != "example.com" {
		t.Errorf("поддомен зоны должен брать её сертификат, получено %q", names["docs.example.com"])
	}
	if names["app.other.net"] != "app.other.net" {
		t.Errorf("домен вне зоны должен брать свой сертификат, получено %q", names["app.other.net"])
	}
}
