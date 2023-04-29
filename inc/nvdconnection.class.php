<?php

define('API_KEY',               'apiKey');
define('CPE_NAME',              'cpeName');
define('VULNERABLE',            'isVulnerable');
define('LAST_MOD_START_DATE ',  'lastModStartDate');
define('LAST_MOD_END_DATE ',    'lastModEndDate');

class PluginNvdNvdconnection extends PluginNvdConnection {

    private const baseRequestUrl    = "https://services.nvd.nist.gov/rest/json/cves/2.0/";
    private const baseCveUrl        = "https://nvd.nist.gov/vuln/detail/";

    /**
     * Construct parent class with base request url
     * 
     * @since 1.0.0
     * 
     * @return void 
     */
    public function __construct() {
        parent::__construct(baseRequestUrl);
    }

    /**
     * Retrieve url to CVE reccord on NVD database
     * 
     * @since 1.0.0
     * 
     * @param string $CveID     MITRE CVE vulnerability identifier
     * 
     * @return string 
     */
    static function getCveNvdUrl($CveID) {

        return self::baseCveUrl . $CveID;
    }
}

?>