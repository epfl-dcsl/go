package parser

import (
	"go/ast"
	"go/token"
)

// parseGosecCalls returns the stmt that contain the gosecure keyword.
// These are then stored in the File describing the package.
// We reload the source which is not efficient, but avoids modifying too much
// of the existing code.
// This function panics if called on a package that is not main.
func parseGosecCalls(fset *token.FileSet, filename string) (s []*ast.GosecStmt) {
	bytes, err := readSource(filename, nil)
	if err != nil {
		panic(err)
	}

	var p parser

	p.init(fset, filename, bytes, ImportsOnly|ParseComments)

	for p.tok != token.EOF {
		if p.tok == token.GOSEC {
			a := p.parseGosecStmt().(*ast.GosecStmt)
			s = append(s, a)
		} else {
			p.next()
		}
	}

	return
}
