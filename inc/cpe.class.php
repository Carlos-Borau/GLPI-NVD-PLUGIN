<?php

define('CPE_PART',      0);
define('CPE_VENDOR',    1);
define('CPE_PRODUCT',   2);
define('CPE_VERSION',   3);
define('CPE_UPDATE',    4);
define('CPE_EDITION',   5);
define('CPE_LANGUAGE',  6);
define('CPE_SW_EDTION', 7);
define('CPE_TARGET_SW', 8);
define('CPE_TARGET_HW', 9);
define('CPE_OTHER',    10);


class PluginNvdCpe {

    public array $attributes = array(
        CPE_PART        => '*',
        CPE_VENDOR      => '*',
        CPE_PRODUCT     => '*',
        CPE_VERSION     => '*',
        CPE_UPDATE      => '*',
        CPE_EDITION     => '*',
        CPE_LANGUAGE    => '*',
        CPE_SW_EDTION   => '*',
        CPE_TARGET_SW   => '*',
        CPE_TARGET_HW   => '*',
        CPE_OTHER       => '*'
    );

    /**
     * Assign values to CPE attributes
     * 
     * @since 1.0.0
     * 
     * @param array $attributes Associative array with attribute values to assign
     * 
     * @return void 
     */
    public function set_CPE_attributes(array $attributes) {

        foreach ($attributes as $attribute => $value) {
            if (array_key_exists($attribute, $this->attributes) and gettype($value) == "string") {
                $this->attributes[$attribute] = $value;
            }
        }
    }

    /**
     * Returns the CPE WFN for the current CPE object
     * 
     * @since 1.0.0
     * 
     * @return string  
     */
    public function get_CPE_WFN () {

        $cpe_wfn = "cpe:2.3";

        foreach($this->attributes as $attribute => $value){
            $cpe_wfn .= ':'.$value;
        } 

        return $cpe_wfn;
    }

    /**
     * Returns a string containing a vendor name suitable for CPE format
     * 
     * @since 1.0.0
     * 
     * @return string  
     */
    public static function getVendorSugestedSearchTerms($vendorName) {

        $vendorName = strtolower($vendorName);
        $vendorName = str_replace('corporation', '', $vendorName);
        $vendorName = str_replace('inc.', '', $vendorName);
        $vendorName = str_replace(',', ' ', $vendorName);
        $vendorName = preg_replace('/\b\w{1,3}\b/', '', $vendorName);
        $vendorName = preg_replace('/\s+/', ' ', $vendorName);
        $vendorName = trim($vendorName);
        $vendorName = str_replace(' ', ',', $vendorName);

        $terms = explode(',', $vendorName);
        
        usort($terms, function($a, $b) { 
            return strlen($b) <=> strlen($a);
        });

        return $terms;
    }
}

?>