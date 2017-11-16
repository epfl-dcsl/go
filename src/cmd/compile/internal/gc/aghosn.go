package gc

import (
	"fmt"
)

type Loc int

const (
	Left Loc = iota
	Right
	Body
	Top
)

//For stringer
func (l Loc) String() string {
	switch l {
	case Left:
		return "Left"
	case Right:
		return "Right"
	case Body:
		return "Body"
	case Top:
		return "Top"
	default:
		return "UNKNOWN"
	}
}

type Pair struct {
	l Loc
	n *Node
}

func dumpEverything(n *Node) {
	s := fmt.Sprintf("left: %v, right: %v, Ninit: %v, Nbody: %v, ", n.Left, n.Right, n.Ninit, n.Nbody)
	s += fmt.Sprintf("List: %v, RList: %v\n", n.List, n.Rlist)
	s += fmt.Sprintf("Type: %v, Orig: %v, Func; %v, Name: %v\n", n.Type, n.Orig, n.Func, n.Name)
	s += fmt.Sprintf("Etype: %v, Op: %v\n", n.Etype, n.Op)

	fmt.Println(s)
}

func (p Pair) String() string {
	//s := fmt.Sprintf("(%v) %v, type: %v, name: %v, Op: %v\n", p.l, p.n, p.n.Type, p.n.funcname(), p.n.Op)
	s := fmt.Sprintf("(%v) %+v\n", p.l, p.n)
	return s
}

func walkGosecure(n *Node, path *[]*Pair) bool {
	if n == nil {
		return false
	}
	if n.Op == OGOSECURE {
		if len(*path) != 0 {
			*path = append([]*Pair{{Left, n.Left}}, *path...)
		} else {
			*path = []*Pair{{Left, n.Left}}
		}
		if n.Left == nil || n.Left.Op != OCALLFUNC {
			panic("Not a call functiona argument")
		}

		if n.Left.Left == nil || n.Left.Left.Op != ONAME {
			panic("Don't have the name for the call.")
			//That level for the Func.Fname() maybe?
		}

		return true
	}

	if walkGosecure(n.Left, path) {
		*path = append([]*Pair{{Left, n.Left}}, *path...)
		return true
	}

	if walkGosecure(n.Right, path) {
		*path = append([]*Pair{{Right, n.Left}}, *path...)
		return true
	}

	for _, b := range n.Nbody.Slice() {
		if walkGosecure(b, path) {
			*path = append([]*Pair{{Body, b}}, *path...)
			return true
		}
	}

	return false
}

func printPath(p []*Pair) {
	for i, n := range p {
		fmt.Printf("%v\n", n)
		if i == len(p)-1 {
			if n.n.Op != OCALLFUNC {
				panic("I'm not looking at the correct entry.")
			}
			//what is left of the occalfunc.
			if n.n.Left == nil {
				panic("Left of OCALLFUNC is null.")
			}

			//What is left of left.
			n1 := n.n.Left

			//The function declaration.
			decl := n1.Name.Defn

			//TODO aghosn: check the Func Inldcl how it is generated.
			//Can actually highjack inlining mech to do the copy.
			fmt.Printf("The func arg %+v\n", decl.Func)
		}
	}
}

func PrintLast(path []*Pair) {
	n := path[len(path)-1]
	if n == nil {
		panic("The last element is nil!")
	}
	oname := n.n.Left.Name
	//fmt.Printf("The address of defn (%p): %+v", oname.Defn, oname)

	decl := oname.Defn
	//TODO aghosn: check the Func Inldcl how it is generated.
	//Can actually highjack inlining mech to do the copy.
	//fmt.Printf("The func arg %+v\n", decl.Func)
	//fmt.Printf("The name: %+v\n", decl.Func.Nname)
	fmt.Printf("The original: %+v\n\n", decl)

	//TODO try to copy the shit out of the node.
	ncpy := inlcopy(decl)

	//TODO print the copy
	fmt.Printf("The copy: %+v\n", ncpy)
}

func findGoSecure(ttop []*Node) {
	for _, n := range ttop {
		fmt.Printf("The top is %v, %v, %p\n", n.funcname(), n.Op, n)
		path := make([]*Pair, 0, 1)
		if walkGosecure(n, &path) {
			path = append([]*Pair{{Top, n}}, path...)
			PrintLast(path)
		}
	}
}
