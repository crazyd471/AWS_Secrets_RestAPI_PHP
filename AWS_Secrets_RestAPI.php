<?php

header("Content-Type: application/json");

/*
 * This is a simple PHP script that can be used to retrieve Secrets from AWS
 * without using the SDK.
 * 
 * Documentation: AWS Secrets RestAPI - GetSecretValue 
 * https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html#API_GetSecretValue_Examples
 */

$execute = new AWSSecrets();

class AWSSecrets {

    public $method = '';
    public $service = '';
    public $host = '';
    public $region = '';
    public $request_parameters = '';
    public $endpoint = '';
    public $content_type = '';
    public $amz_target = '';
    public $access_key = "";
    public $secret_key = "";
    public $secret_id = "";
    public $response = '';

    public function __construct() {
        /*
         * Load in our credentials.ini file. This will set our class variables 
         * needed to create and execute the POST request.
         */
        if (!$this->LoadConfiguration()) {
            die("Unable to load in credentials.ini");
        }

        /*
         * Setup our POST request body.
         */
        $this->request_parameters = array(
            "SecretId" => $this->secret_id,
            "VersionStage" => "AWSCURRENT" // Get the current version (Default)
        );

        /*
         * In the section below we are setting up the canonical request headers 
         * required to create a valid aws4_request
         * 
         * Documentation: Signing AWS requests with Signature Version 4
         * https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
         */

        $date_utc = new DateTime("now", new DateTimeZone("UTC"));

        $amz_date = $date_utc->format('Ymd') . "T" . $date_utc->format('His') . "Z";

        $date_stamp = $date_utc->format('Ymd');

        $canonical_uri = '/';

        $canonical_querystring = '';

        $canonical_headers = 'content-type:' . $this->content_type . "\n" . 'host:' . $this->host . "\n" . 'x-amz-date:' . $amz_date . "\n" . 'x-amz-target:' . $this->amz_target . "\n";

        $signed_headers = 'content-type;host;x-amz-date;x-amz-target';

        $payload_hash = hash("sha256", json_encode($this->request_parameters));

        $canonical_request = $this->method . "\n" . $canonical_uri . "\n" . $canonical_querystring . "\n" . $canonical_headers . "\n" . $signed_headers . "\n" . $payload_hash;

        $algorithm = 'AWS4-HMAC-SHA256';
        $credential_scope = $date_stamp . '/' . $this->region . '/' . $this->service . '/' . 'aws4_request';
        $string_to_sign = $algorithm . "\n" . $amz_date . "\n" . $credential_scope . "\n" . hash("sha256", $canonical_request);

        $signing_key = $this->getSignatureKey($this->secret_key, $date_stamp, $this->region, $this->service);

        $signature = hash_hmac("sha256", $string_to_sign, $signing_key);

        $authorization_header = $algorithm . ' ' . 'Credential=' . $this->access_key . '/' . $credential_scope . ', ' . 'SignedHeaders=' . $signed_headers . ', ' . 'Signature=' . $signature;


        /*
         * Now that our request is all setup, we can finally execute the request.
         */
        $ch = curl_init($this->endpoint);

        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            "Accept-Encoding:" . "identity",
            "Content-Type:" . $this->content_type,
            "X-Amz-Date:" . $amz_date,
            "X-Amz-Target:" . $this->amz_target,
            "Authorization:" . $authorization_header
        ));
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($this->request_parameters));
        curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1); // Use HTTP/1.1
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); //Development Env
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); //Development Env
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $response = curl_exec($ch);
        /*
         * If all went well, we can print out the response which should be in a
         * JSON format.
         */
        print_r($response);

        curl_close($ch);
    }

    /**
     * This function will load in our credentials.ini file. This should contain 
     * the following keys:
     * 
     * credentials: access_key, secret_key
     * request: method, service, region, amz_target, content_type
     * 
     * @return boolean
     */
    public function LoadConfiguration() {
        /*
         * Set our credentials path and filename.
         */
        $credential_filename = "credentials.ini";

        if (file_exists($credential_filename)) {
            $configuration_ini = parse_ini_file($credential_filename, true);
            /*
             * Setup the request class variables.
             */
            $ini_request = $configuration_ini['request'];

            $this->method = $ini_request['method'];
            $this->service = $ini_request['service'];
            $this->host = $ini_request['service'] . "." . $ini_request['region'] . ".amazonaws.com";
            $this->region = $ini_request['region'];
            $this->endpoint = "https://" . $ini_request['service'] . "." . $ini_request['region'] . ".amazonaws.com/";
            $this->amz_target = $ini_request['service'] . "." . $ini_request['amz_target'];
            $this->content_type = $ini_request['content_type'];
            $this->secret_id = $ini_request['secret_id'];

            /*
             * Setup the credential class variables.
             */
            $ini_credentials = $configuration_ini['credentials'];

            $this->access_key = $ini_credentials['access_key'];
            $this->secret_key = $ini_credentials['secret_key'];

            return true;
        }
        return false;
    }

    /**
     * This function is used to generate the signature key used in the authorization
     * header.
     * 
     * @param type $key string
     * @param type $date_stamp string
     * @param type $regionName string
     * @param type $serviceName string
     * @return string
     */
    public function getSignatureKey($key, $date_stamp, $regionName, $serviceName) {

        $kDate = $this->sign(('AWS4' . $key), $date_stamp);
        $kRegion = $this->sign($kDate, $regionName);
        $kService = $this->sign($kRegion, $serviceName);
        $kSigning = $this->sign($kService, 'aws4_request');
        return $kSigning;
    }

    /**
     * This is a helper function that returns raw binary data and not lowercase
     * hexits.
     * 
     * @param type $key string
     * @param type $msg string
     * @return type string
     */
    public function sign($key, $msg) {
        return hash_hmac("sha256", $msg, $key, true);
    }

}
