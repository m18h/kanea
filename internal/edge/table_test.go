package edge

import "testing"

func TestNormalizeHost(t *testing.T) {
	// Each of these is a second spelling of one host. Without normalisation,
	// "unknown Host → 404" is defeated by typing the name differently.
	tests := []struct {
		in, want string
	}{
		{"web.shop.example.com", "web.shop.example.com"},
		{"WEB.Shop.Example.COM", "web.shop.example.com"},
		{"web.shop.example.com:443", "web.shop.example.com"},
		{"web.shop.example.com.", "web.shop.example.com"},
		{"WEB.shop.example.com.:8080", "web.shop.example.com"},
		{"  web.shop.example.com  ", "web.shop.example.com"},
		{"", ""},
		{"10.0.0.1:80", "10.0.0.1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
	}
	for _, tc := range tests {
		if got := NormalizeHost(tc.in); got != tc.want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTableLookup(t *testing.T) {
	table, err := NewTable(Snapshot{Index: 7, Routes: []Route{{
		Project: "shop", Service: "web",
		Domains:  []string{"web.shop.example.com", "shop.example.com"},
		Upstream: "10.201.0.1", Port: 3000,
	}}})
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	if table.Len() != 2 {
		t.Errorf("Len = %d, want 2", table.Len())
	}
	if table.Index() != 7 {
		t.Errorf("Index = %d, want 7", table.Index())
	}

	for _, host := range []string{"shop.example.com", "SHOP.example.com:443", "shop.example.com."} {
		route, ok := table.Lookup(host)
		if !ok {
			t.Fatalf("Lookup(%q) missed", host)
		}
		if route.Name() != "shop/web" {
			t.Errorf("Lookup(%q) = %s", host, route.Name())
		}
	}
	if _, ok := table.Lookup("other.example.com"); ok {
		t.Error("an unclaimed host resolved")
	}
}

func TestEmptyTableRoutesNothing(t *testing.T) {
	table := EmptyTable()
	if table.Len() != 0 {
		t.Errorf("Len = %d", table.Len())
	}
	if _, ok := table.Lookup("anything.example.com"); ok {
		t.Error("the empty table resolved a host")
	}
}
