package main

import (
	"Asyn_CBDC/onlinetx"
	"fmt"
)

func main() {
	//cmpplatypus.Comptdelta()
	//cmpplatypus.T_basetx()
	//cmpplatypus.Pure()
	//fmt.Println("enroll:")
	//enroll.T_Enroll()
	//cmpplatypus.Holdinglimit() //11584
	fmt.Println("offline:")
	fmt.Println("offlineWithNoRegulation:")
	//offlinetx.T_offlineTxWithNoRegulation() //33412
	fmt.Println("offlineWithNoLimitRegulation:")
	//offlinetx.T_offlineTxWithNoLimitRegulation() //39495
	fmt.Println("offlineWithHoldinglimitRegulation:")
	//offlinetx.T_offlineTxWithHoldinglimitRegulation() //48868
	fmt.Println("offlineWithFreqlimitRegulation:")
	//offlinetx.T_offlineTxWithFreqlimitRegulation() //61434
	fmt.Println("online:")
	onlinetx.Verify()

}
