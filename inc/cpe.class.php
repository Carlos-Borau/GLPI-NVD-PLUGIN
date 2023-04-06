<?php

class PluginNvdCpe {

    public string $part         = '*';
    public string $vendor       = '*';
    public string $product      = '*';
    public string $version      = '*';
    public string $update       = '*';
    public string $edition      = '*';
    public string $language     = '*';
    public string $sw_edition   = '*';
    public string $target_sw    = '*';
    public string $target_hw    = '*';
    public string $other        = '*';

    static function get_CPE_params($software) {

        return $product;

    }

    public function __construct($part, $vendor, $product, $version){

        $this->part    = $part;
        $this->vendor  = $vendor;
        $this->product = $product;
        $this->version = $version;
    }

    public function get_CPE_WFN () {

        $cpe_wfn = "cpe:2.3";

        foreach($this as $attribute => $value){

            $cpe_wfn .= ':'.$value;
            
        } 

        return $cpe_wfn;
    }
}

?>