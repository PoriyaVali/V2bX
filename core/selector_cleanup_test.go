package core

import (
	"errors"
	"reflect"
	"testing"

	"github.com/PoriyaVali/V2bX/conf"
)

type constructionCore struct {
	placeCore
	close func() error
}

func (c *constructionCore) Close() error { return c.close() }

func TestFailedSelectorConstructionClosesPreviouslyBuiltCores(t *testing.T) {
	const typ = "construction-cleanup-test"
	defer delete(cores, typ)
	constructionErr := errors.New("construction failed")
	cleanupErr := errors.New("cleanup failed")
	for _, failure := range []string{"factory", "unknown", "duplicate", "nil"} {
		t.Run(failure, func(t *testing.T) {
			var closed []string
			cores[typ] = func(c *conf.CoreConfig) (Core, error) {
				if c.Name == "fail" {
					if failure == "nil" {
						return nil, nil
					}
					return nil, constructionErr
				}
				name := c.Name
				return &constructionCore{close: func() error {
					closed = append(closed, name)
					if name == "second" {
						return cleanupErr
					}
					return nil
				}}, nil
			}
			last := conf.CoreConfig{Type: typ, Name: "fail"}
			if failure == "unknown" {
				last.Type = "unknown-construction-test"
			}
			if failure == "duplicate" {
				last.Name = "first"
			}
			selected, err := NewSelector([]conf.CoreConfig{{Type: typ, Name: "first"}, {Type: typ, Name: "second"}, last})
			if err == nil || selected != nil {
				t.Fatalf("invalid construction accepted: %v / %v", selected, err)
			}
			if !reflect.DeepEqual(closed, []string{"second", "first"}) {
				t.Fatalf("cleanup order: %v", closed)
			}
			if !errors.Is(err, cleanupErr) {
				t.Fatalf("cleanup error lost: %v", err)
			}
			if failure == "factory" && !errors.Is(err, constructionErr) {
				t.Fatalf("construction error lost: %v", err)
			}
		})
	}
}
