package database

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type Usersdata struct {
	username string
	password string
}

func Search_account_map(login_data map[string]interface{}) (result bool) {

	var login Usersdata
	login.username = login_data["username"].(string)
	login.password = login_data["password"].(string)

	result = Search_account(login)

	return result
}

func Search_account(User Usersdata) (result bool) { //Поиск аккаунта в базе данных users
	db, err := sql.Open("postgres", "postgres://admin:108@localhost/user-account?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}

	defer db.Close()

	rows, err := db.Query("select * from users")
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	users := []Usersdata{}

	for rows.Next() {
		p := Usersdata{}
		err := rows.Scan(&p.username, &p.password)
		if err != nil {
			fmt.Println(err)
			continue
		}
		users = append(users, p)
	}

	for i := 0; i < len(users); i++ {
		if users[i].username == User.username && users[i].password == User.password {
			result = true
			break
		} else {
			result = false
		}
	}

	return result

}
