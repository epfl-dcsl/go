package gc

// getCopy highjacks the inliner mechanism to generate a copy of the node.
func getCopy(n *Node) *Node {
	return inlcopy(n)
}

// getFnDecl returns the callee corresponding to a function call.
func getdFnDecl(n *Node) *Node {
	if n.Left == nil || n.Left.Op != OCALLFUNC {
		panic("GOSECURE: Not a call function argument.")
	}
	if n.Left.Left == nil || n.Left.Left.Op != ONAME {
		panic("GOSECURE: Missing name for the gosecure callee.")
	}
	oname := n.Left.Name
	if oname == nil || oname.Defn == nil {
		panic("GOSECURE: Name or Defn node is nul.")
	}
	return oname.Defn
}

func walkerList(n Nodes, res *[]*Node) {
	for _, b := range n.Slice() {
		walker(b, res)
	}
}

// walker walks an AST node and finds the gosecure calls.
// It appends a copy of the declaration nodes corresponding to the callee
// of the gosecure calls to the res slice.
//TODO aghosn should handle duplicates.
func walker(n *Node, res *[]*Node) {
	if n == nil {
		return
	}
	//Found a gosecure call.
	if n.Op == OGOSECURE {
		fnDecl := getdFnDecl(n)
		*res = append(*res, getCopy(fnDecl))
		return
	}

	walker(n.Left, res)
	walkerList(n.Ninit, res)
	walkerList(n.Nbody, res)
	walkerList(n.List, res)
	walkerList(n.Rlist, res)
	walker(n.Right, res)
}

// findSecureNodes calls the walker on the ttop nodes.
func findSecureNodes(ttop []*Node) {
	res := make([]*Node, 0, 1)
	for _, n := range ttop {
		walker(n, &res)
	}

	//TODO package everything in a new synthetic package.
}

//TODO function to create a package out of these nodes by using the inlining.
