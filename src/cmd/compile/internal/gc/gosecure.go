package gc

import (
	"fmt"
)

func gosecVerifyArgs(n *Node) {
	if n.Op != OCALLFUNC {
		fmt.Println("The Op ", n.Op)
		panic("Not a call")
	}
	fmt.Println("The node ", n)
	fmt.Println("The type ", n.Type)
	fmt.Println("The left ", n.Left.Op)
	fmt.Println("The list ", n.List)
	for _, a := range *n.List.slice {
		fmt.Println("The type ", a.Op)
	}
}
