package main

import (
	"fmt"
	"github.com/zhouchenh/era-facade/internal/apphost"
	"net"
	"net/http"
	"os"
)

func main() {
	r, e := apphost.Load(os.Args[1])
	if e != nil {
		panic(e)
	}
	defer r.Close()
	listen := "127.0.0.1:0"
	if len(os.Args) > 4 {
		listen = os.Args[4]
	}
	l, e := net.Listen("tcp", listen)
	if e != nil {
		panic(e)
	}
	fmt.Println(l.Addr())
	s := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		h := r.Match(q)
		if h == nil {
			http.NotFound(w, q)
			return
		}
		h.ServeHTTP(w, q)
	})}
	if e = s.ServeTLS(l, os.Args[2], os.Args[3]); e != nil {
		panic(e)
	}
}
