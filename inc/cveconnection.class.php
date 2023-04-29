<?php

class PluginNvdCveconnection extends PluginNvdConnection {

    private const baseRequestUrl = "https://cve.circl.lu/api/browse/";

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