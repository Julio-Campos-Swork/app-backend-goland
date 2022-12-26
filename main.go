package main

import (
	"net/http"

	"github.com/Julio-Campos-Swork/Go-Rest-Api/routes"
	"github.com/gorilla/mux"
)

func main() {
	Routers()
}

func Routers() {
	router := mux.NewRouter()
	routes.InitDB()
	router.HandleFunc("/users", routes.GetUsers).Methods("GET")
	router.HandleFunc("/register", routes.Register).Methods("POST")
	router.HandleFunc("/login", routes.Login).Methods("POST")
	router.HandleFunc("/logout", routes.Logout).Methods("GET")
	router.HandleFunc("/users/{id}", routes.GetUser).Methods("GET")
	router.HandleFunc("/users/{id}", routes.UpdateUser).Methods("PUT")
	router.HandleFunc("/users/{id}", routes.DeleteUser).Methods("DELETE")
	http.ListenAndServe(":9080", &CORSRouterDecorator{router})
}

// CORSRouterDecorator applies CORS headers to a mux.Router
type CORSRouterDecorator struct {
	R *mux.Router
}

func (c *CORSRouterDecorator) ServeHTTP(rw http.ResponseWriter,
	req *http.Request) {
	if origin := req.Header.Get("Origin"); origin != "" {
		rw.Header().Set("Access-Control-Allow-Origin", origin)
		rw.Header().Set("Access-Control-Allow-Methods",
			"POST, GET, OPTIONS, PUT, DELETE")
		rw.Header().Set("Access-Control-Allow-Credentials", "true")
		rw.Header().Set("Access-Control-Allow-Headers",
			"Accept, Accept-Language,"+
				" Content-Type, YourOwnHeader")
	}
	// Stop here if its Preflighted OPTIONS request
	if req.Method == "OPTIONS" {
		return
	}

	c.R.ServeHTTP(rw, req)
}
