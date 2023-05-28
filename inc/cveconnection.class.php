<?php

class PluginNvdCveconnection extends PluginNvdConnection {

    private const baseRequestUrl = "https://cve.circl.lu/api/browse/";

    /**
     * Construct parent class with base request url
     * 
     * @since 1.0.0
     * 
     * @param string $vendor    CPE vendor name
     * 
     * @return void 
     */
    public function __construct($vendor = NULL) {

        $baseUrl = self::baseRequestUrl . $vendor;

        parent::__construct($baseUrl);
    }
}

?>