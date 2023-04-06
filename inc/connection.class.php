<?php

define('API_KEY',               'apiKey');
define('CPE_NAME',              'cpeName');
define('VULNERABLE',            'isVulnerable');
define('LAST_MOD_START_DATE ',  'lastModStartDate');
define('LAST_MOD_END_DATE ',    'lastModEndDate ');

class PluginNvdConnection {

    private static string $apiKey;

    private const baseUrl           = "https://services.nvd.nist.gov/rest/json/cves/2.0/";

    private string $urlParams;

	static function setApiKey($apiKey){
        /**
        * 
        * @todo Set API Key on DB
        */ 
		PluginNvdConnection::$apiKey = $apiKey;
	}

    static function getApiKey() {
        /**
        * 
        * @todo Get API Key on DB
        */ 
		return PluginNvdConnection::$apiKey;
    }

    public function setUrlParams($cpeName, $isVulnerable = False, $lastModDate = False){

        $this->urlParams = CPE_NAME . '=' . $cpeName;

        if ($isVulnerable) {
            $this->urlParams .= '&' . VULNERABLE;
        }

        if ($lastModDate) {
            /**
            * 
            * @todo Get LAST_MOD_START_DATE from DB
            */ 

            //$lastModStartDate = ...;
            $lastModEndDate = date(c);

            //$this->urlParams .= '&' . LAST_MOD_START_DATE . '=' . $lastModStartDate;
            $this->urlParams .= '&' . LAST_MOD_END_DATE . '=' . $lastModEndDate;
        }
    }

    public function getCompleteUrl() {

        return self::baseUrl . '?' . $this->urlParams;
    }

    public function requestNvdRecords(){

        /**
        * 
        * @todo Retrieve API key from DB
        */ 

        $url    = self::baseUrl . '?' . $this->urlParams;
        $header = API_KEY . ': ' . self::$apiKey;

        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, $header);

        $output = curl_exec($ch);

        curl_close($ch);

        return json_decode($output, true);
    }

}

?>