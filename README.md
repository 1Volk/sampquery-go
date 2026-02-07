# SA-MP Server Query Go Library

## Installation

```bash
go get github.com/1Volk/sampquery-go
```

## Example

```go
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/1Volk/sampquery-go"
)

func main() {
	q, err := sampquery.NewQuery(&sampquery.Config{
		IP:      "sa.gambit-rp.com",
		Port:    7777,
		Timeout: time.Second * 1,
	})

	if err != nil {
		log.Fatal(err)
	}
	defer q.Close()

	// Retrieve server info
	data, err := q.GetData()
	if err != nil {
		log.Fatal(err)
	}

	// Output: Current Players / Max Players
	fmt.Println(data.Players, "/", data.MaxPlayers)
}
```



