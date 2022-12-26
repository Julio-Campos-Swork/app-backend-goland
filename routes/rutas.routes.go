package routes

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Julio-Campos-Swork/Go-Rest-Api/util"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
)

// definimos la estructura que vamos a devolver, en este caso se devuelve
// los datos de usuarios previamente establecidos en la BD
type User struct {
	jwt.RegisteredClaims
	ID        string `json:"id"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
	Password  string `json:"password"`
}

// definimos las credenciales para la validacion del usuario
type Credentials struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

const key = "my secure jwt key"

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

var db *sql.DB
var err error

// definimos la conexion a la base de datos
func InitDB() {
	db, err = sql.Open("mysql",
		"root:@tcp(127.0.0.1:3306)/userdb")
	if err != nil {
		panic(err.Error())
	}
}

func TokenChecker(w http.ResponseWriter, r *http.Request) string {
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			fmt.Println("No cockie")
			w.WriteHeader(http.StatusUnauthorized)
			return "No autorizado"
		}
		fmt.Println("Bad request en checado de cockie")

		w.WriteHeader(http.StatusBadRequest)
		return "Bad Request"
	}

	tknStr := c.Value

	claims := &Claims{}
	//funcion para verificar si el token coincide con el generado previamente
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})
	// fmt.Println("tkn", tkn)
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			fmt.Println("Fallo la verificacion del token")
			w.WriteHeader(http.StatusUnauthorized)
			return "No autorizado"
		}
		fmt.Println("Bad request en la vwrificacion")
		w.WriteHeader(http.StatusBadRequest)
		return "Bad Request"
	}
	if !tkn.Valid {
		fmt.Println("Token no valido")
		w.WriteHeader(http.StatusUnauthorized)
		return "No autorizado"
	}
	// Finally, return the welcome message to the user, along with their
	// username given in the token
	// w.Write([]byte(fmt.Sprintf("Welcome %s!", claims.Username)))
	return "Autorizado"

}

func Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	//leemos lo que viene del POSt del front
	body, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err.Error())
	}
	//creamos la variable que almacena los datos
	keyVal := make(map[string]string)
	//decodificamos el JSON del body y lo pasamos al keyval
	json.Unmarshal(body, &keyVal)
	//asignamos las variables
	email := keyVal["email"]
	password := keyVal["password"]

	result, err := db.Query("SELECT id, email, password FROM users WHERE email = ?", email)
	if err != nil {
		fmt.Println(err)
		panic(err.Error())
	}
	//asignamos los valores de la consulta a las credenciales
	var creds Credentials
	for result.Next() {
		err := result.Scan(&creds.ID, &creds.Email, &creds.Password)
		if err != nil {
			panic(err.Error())
		}
	}
	// fmt.Println("Password de la base de datos", creds.Password)

	PasswordCompared := util.ComparePassword(creds.Password, password)

	if PasswordCompared == nil {
		fmt.Println("Credenciales", creds)
		if creds.ID == "" {
			fmt.Println("Error de datos")
			json.NewEncoder(w).Encode("Error de Credenciales")
			panic(err.Error())

		}
		// Declaramos tiempo de expiracion del token
		expirationTime := time.Now().Add(10000 * time.Minute)
		// Create the JWT claims, which includes the username and expiry time
		claims := &Claims{
			Username: creds.Email,
			RegisteredClaims: jwt.RegisteredClaims{
				// In JWT, the expiry time is expressed as unix milliseconds
				ExpiresAt: jwt.NewNumericDate(expirationTime),
			},
		}

		// Declare the token with the algorithm used for signing, and the claims
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		// Create the JWT string
		tokenString, err := token.SignedString([]byte(key))
		fmt.Println("JWT Token", tokenString)
		if err != nil {
			// If there is an error in creating the JWT return an internal server error
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationTime,
		})
		json.NewEncoder(w).Encode("Autenticado")
	} else {
		json.NewEncoder(w).Encode("Las contraseñas no coinciden")

	}

}

func Logout(w http.ResponseWriter, r *http.Request) {
	// immediately clear the token cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Expires: time.Now(),
	})
	json.NewEncoder(w).Encode("Sesion Cerrada")
}

func Register(w http.ResponseWriter, r *http.Request) {
	//configuramos cabezera de respuesta
	w.Header().Set("Content-Type", "application/json")
	stmt, err := db.Prepare("INSERT INTO users(first_name," + "last_name, email, password) VALUES(?,?,?,?)")
	if err != nil {
		panic(err.Error())
	}
	//leemos lo que viene del POSt del front
	body, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err.Error())
	}
	//creamos la variable que almacena los datos
	keyVal := make(map[string]string)
	//decodificamos el JSON del body y lo pasamos al keyval
	json.Unmarshal(body, &keyVal)
	//asignamos las variables
	first_name := keyVal["firstName"]
	last_name := keyVal["lastName"]
	email := keyVal["email"]
	password := keyVal["password"]
	//encriptamos el password
	HashedPassword := util.Hashpassword(password)
	fmt.Println(HashedPassword)

	//verificamos si ya existe el email
	result, err := db.Query("SELECT email from users WHERE email = ?", email)
	if err != nil {
		fmt.Println("error en la consulta")
		panic(err.Error())
	}
	defer result.Close()
	var emailChecker string
	for result.Next() {
		err := result.Scan(&emailChecker)
		if err != nil {
			fmt.Println("No encontro el dato")
		}
	}
	if emailChecker != "" {
		json.NewEncoder(w).Encode("ya existe un usuario con ese correo")

	} else {
		//asignamos los valores a a consulta que quedo pendiente en la base de datos
		//el "_" nos sirve como identificador en blanco ya que necesitamos
		//declarar una variable pero no la vamos a utilizar y es mejor declararla en blanco
		_, err = stmt.Exec(first_name, last_name, email, HashedPassword)
		if err != nil {
			panic(err.Error())
		}

		json.NewEncoder(w).Encode("New User Created")

	}

}

// funcion para obtener todos los usuarios sin restriccion
func GetUsers(w http.ResponseWriter, r *http.Request) {
	TokenStatus := TokenChecker(w, r)

	if TokenStatus == "Autorizado" {
		// se inicia la conexion a la base
		//configuramos la cabezera
		w.Header().Set("Content-Type", "application/json")
		//la variable users tendrá la misma estructura declarada previamente
		var users []User
		result, err := db.Query("SELECT id, first_name," +
			"last_name,email from users")
		if err != nil {
			panic(err.Error())
		}
		//retorna false cuando ya no encuentra mas datos para traer
		defer result.Close()
		for result.Next() {
			var user User
			err := result.Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email)
			if err != nil {
				panic(err.Error())
			}
			users = append(users, user)
		}
		//codificamos la informacion para mandarla en forma de JSON
		json.NewEncoder(w).Encode(users)

	} else {
		json.NewEncoder(w).Encode("No estas logeado")

	}

}

// Get user by ID
func GetUser(w http.ResponseWriter, r *http.Request) {
	//configuramos cabezera de respuesta
	w.Header().Set("Content-Type", "application/json")

	//asignamos los parametros que se pasan por URL /user:id
	params := mux.Vars(r)
	//realizamos la consulta
	result, err := db.Query("SELECT id, first_name,"+
		"last_name,email, password from users WHERE id = ?", params["id"])
	if err != nil {

		panic(err.Error())
	}
	//paramos la consulta cuando ya no tenga datos
	defer result.Close()
	var user User
	//hacemos una iteracion ara comprobar que todos los datos sean correctos
	for result.Next() {
		err := result.Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.Password)
		if err != nil {
			panic(err.Error())
		}
	}

	//devolvemos el resultado
	json.NewEncoder(w).Encode(user)
}

// UPDATE USER
func UpdateUser(w http.ResponseWriter, r *http.Request) {

	TokenStatus := TokenChecker(w, r)
	if TokenStatus == "Autorizado" {
		//el metodo es basicamente igual que el create user
		//con la diferencia de tomar todos los valores que vienen del front
		w.Header().Set("Content-Type", "application/json")
		params := mux.Vars(r)
		//preparamos la consulta y verificamos que este correcta
		stmt, err := db.Prepare("UPDATE users SET first_name = ?," +
			"last_name = ?, email = ? WHERE id = ?")

		if err != nil {
			panic(err.Error())
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			panic(err.Error())
		}
		keyVal := make(map[string]string)
		json.Unmarshal(body, &keyVal)
		first_name := keyVal["firstName"]
		last_name := keyVal["lasName"]
		email := keyVal["email"]
		//asignamos los valores a la query mediante el Exec
		//el "_" nos sirve como identificador en blanco ya que necesitamos
		//declarar una variable pero no la vamos a utilizar y es mejor declararla en blanco
		_, err = stmt.Exec(first_name, last_name, email, params["id"])
		if err != nil {
			panic(err.Error())
		}
		fmt.Fprintf(w, "User With ID = %s was updated", params["id"])

	} else {
		json.NewEncoder(w).Encode("No estas logeado")
	}
}

// DELETE USER
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	TokenStatus := TokenChecker(w, r)
	if TokenStatus == "Autorizado" {
		//configuramos cabezera de respuesta
		w.Header().Set("Content-Type", "application/json")
		params := mux.Vars(r)
		//preparamos la consulta
		stmt, err := db.Prepare("DELETE FROM users WHERE id = ?")
		if err != nil {
			panic(err.Error())
		}
		//ejecutamos la consulta
		//el "_" nos sirve como identificador en blanco ya que necesitamos
		//declarar una variable pero no la vamos a utilizar y es mejor declararla en blanco
		_, err = stmt.Exec(params["id"])
		if err != nil {
			panic(err.Error())
		}
		fmt.Fprintf(w, "User with ID = %s was deleted", params["id"])

	} else {
		json.NewEncoder(w).Encode("No estas logeado")

	}
}
