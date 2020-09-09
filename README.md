# AWS Secrets (RestAPI - PHP)   
Created: 9/9/2020  
Version: 1.0-alpha  


This is a small PHP class that I created which can be used to retrieve secrets from an AWS endpoint without the need to load in the PHP-SDK. With some light modifications, it can be modified to work with other AWS services. 


----------


### Configuration & Requirements  
#### Requirements  
This class was developed and tested using PHP v7.2 using the CURL module but should work fine with PHP versions 7.0 - 7.3.  

#### Configuration  

For testing, I created a file that the class will read from called `template_credentials.ini` which will contain your credential information as well the AWS request details such as the `region` and `secret_id` etc. This helps by preventing you from storing this sensitive information hard-coded in the code and from being stored in your repo.  

This file should contain the following:  

```ini
[credentials]
access_key=""
secret_key=""

[request]
method="POST"
service="secretsmanager"
region=""
amz_target="GetSecretValue"
content_type="application/x-amz-json-1.1"
secret_id=""
```  

#### Testing
To test, just add your information to the `template_credentials.ini` file and save it as `credentials.ini`. This needs to be in the same directory as the `AWS_Secrets_RestAPI.php` file. 
 