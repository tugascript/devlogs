// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package utils

type HashSet[T comparable] struct {
	items map[T]struct{}
}

func (h *HashSet[T]) Add(v T) {
	h.items[v] = struct{}{}
}

func (h *HashSet[T]) Remove(v T) {
	delete(h.items, v)
}

func (h *HashSet[T]) Contains(v T) bool {
	_, ok := h.items[v]
	return ok
}

func (h *HashSet[T]) Clear() {
	h.items = make(map[T]struct{})
}

func (h *HashSet[T]) Items() []T {
	items := make([]T, 0, len(h.items))
	for item := range h.items {
		items = append(items, item)
	}
	return items
}

func (h *HashSet[T]) Size() int {
	return len(h.items)
}

func (h *HashSet[T]) IsEmpty() bool {
	return len(h.items) == 0
}

func (h *HashSet[T]) MapToSlice(f func(*T) any) []any {
	items := make([]any, 0, len(h.items))
	for item := range h.items {
		items = append(items, f(&item))
	}
	return items
}

func MapHashSetToSlice[T comparable, V any](h HashSet[T], f func(*T) V) []V {
	items := make([]V, 0, len(h.items))
	for item := range h.items {
		items = append(items, f(&item))
	}
	return items
}

func MapHashSetToSliceWithError[T comparable, V any, E error](h HashSet[T], f func(*T) (V, E)) ([]V, E) {
	items := make([]V, 0, len(h.items))

	for item := range h.items {
		var err error
		mv, err := f(&item)
		if err != nil {
			if custErr, ok := err.(E); ok {
				return nil, custErr
			}
		}
		items = append(items, mv)
	}

	var err E
	return items, err
}

func MapSliceToHashSet[T comparable](s []T) HashSet[T] {
	h := HashSet[T]{
		items: make(map[T]struct{}),
	}

	for _, item := range s {
		h.Add(item)
	}

	return h
}
