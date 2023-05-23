<?php

define('API_KEY',               'apiKey');
define('CPE_NAME',              'cpeName');
define('CVE_ID',                'cveId');
define('VULNERABLE',            'isVulnerable');
define('LAST_MOD_START_DATE ',  'lastModStartDate');
define('LAST_MOD_END_DATE ',    'lastModEndDate');
define('START_INDEX',           'startIndex');

class PluginNvdNvdconnection extends PluginNvdConnection {

    private const baseRequestUrl    = "https://services.nvd.nist.gov/rest/json/cves/2.0/";

    /**
     * Construct parent class with base request url
     * 
     * @since 1.0.0
     * 
     * @return void 
     */
    public function __construct() {
        parent::__construct(self::baseRequestUrl);
    }
}

?>