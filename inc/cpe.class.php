<?php

define('CPE_CPE_NAME',      0);
define('CPE_CPE_VERSION',   1);
define('CPE_PART',          2);
define('CPE_VENDOR',        3);
define('CPE_PRODUCT',       4);
define('CPE_VERSION',       5);
define('CPE_UPDATE',        6);
define('CPE_EDITION',       7);
define('CPE_LANGUAGE',      8);
define('CPE_SW_EDTION',     9);
define('CPE_TARGET_SW',    10);
define('CPE_TARGET_HW',    11);
define('CPE_OTHER',        12);


class PluginNvdCpe {

    private const cpe_name = "cpe";
    private const cpe_version = "2.3";

    public array $attributes = array(
        CPE_CPE_NAME    => self::cpe_name,
        CPE_CPE_VERSION => self::cpe_version,
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
     * Create CPE object and assign values to its attributes
     * 
     * @since 1.0.0
     * 
     * @param string $CPE_name CPE format name
     * 
     * @return void 
     */
    public function __construct($CPE_name = null) {

        if (is_null($CPE_name)) { return; }

        $attributes = explode(':', $CPE_name);

        foreach ($attributes as $attribute => $value) {

            $this->attributes[$attribute] = $value;
        }
    }

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

        $cpe_wfn = '';
        
        foreach($this->attributes as $attribute => $value){
            $cpe_wfn .= $value . ':';
        }

        return rtrim($cpe_wfn, ':');
    }

    /**
     * Add CPE term to list if it is set
     * 
     * @since 1.0.0
     * 
     * @param array     list    List of CPE terms
     * @param string    term    CPE term
     * 
     * @return void  
     */
    public static function addTermToAttributeList(&$list, $term) {

        if ($term != '*' and $term != '-' and !in_array($term, $list)) {

            $list[] = $term;
        }
    }

    /**
     * Returns an array containing sugested search terms to locate the vendor
     * 
     * @since 1.0.0
     * 
     * @param string    $vendorName     Vendor name to stract the terms from
     * 
     * @return array  
     */
    public static function getVendorSugestedSearchTerms($vendorName) {

        if (is_null($vendorName)) { return []; }
        
        // CPE names are allways lowercase
        $vendorName = strtolower($vendorName);

        // Remove unuseful common terms
        $vendorName = self::removeCommonTerms($vendorName);

        // Remove small words ( 1 <= len <= 3)
        $vendorName = preg_replace('/\b\w{1,3}\b/', '', $vendorName);

        // Clean string from unwanted characters
        $vendorName = self::cleanString($vendorName);

        // Turn string into array
        $terms = explode(',', $vendorName);
        
        return $terms;
    }

    /**
     * Returns an array containing sugested search terms to locate the product
     * 
     * @since 1.0.0
     * 
     * @param string    $productName    Product name to stract the terms from
     * @param array     $vendor_terms   Array containing search terms for the software's vendor
     * 
     * @return array  
     */
    public static function getProductSugestedSearchTerms($productName, $vendor_terms) {

        if (is_null($productName)) { return []; }

        // CPE names are allways lowercase
        $productName = strtolower($productName);

        // Remove vendor terms from software name
        foreach ($vendor_terms as $term) {
            $productName = str_replace($term, '', $productName);
        }

        // Remove unuseful common terms
        $productName = self::removeCommonTerms($productName);

        // Remove trailing information
        $productName = preg_replace('/-.*/', '', $productName);

        // Remove additional information
        $productName = preg_replace('/\(.*\)/', '', $productName);

        // Remove version
        $productName = preg_replace('/(\d\.)+\d/', '', $productName);

        // Clean string from unwanted characters
        $productName = self::cleanString($productName);

        // Turn string into array
        $terms = explode(',', $productName);
        
        return $terms;
    }

    /**
     * Removes common but unuseful terms from vendor or product name
     * 
     * @since 1.0.0
     * 
     * @param string    $name    Product or vendor name to remove the terms from
     * 
     * @return string  
     */
    private static function removeCommonTerms($name) {

        $name = str_replace('corporation', '', $name);
        $name = str_replace('inc.', '', $name);
        $name = str_replace('team', '', $name);
        $name = str_replace('edition', '', $name);
        $name = str_replace('32-bit', '', $name);
        $name = str_replace('64-bit', '', $name);

        return $name;
    }

    /**
     * Cleans string from unwanted characters
     * 
     * @since 1.0.0
     * 
     * @param string    $name    Product or vendor name to clean
     * 
     * @return string  
     */
    private static function cleanString($name) {

        $name = preg_replace('/\s+/', ' ', $name);
        $name = trim($name);
        $name = str_replace(' ', ',', $name);

        return $name;
    }
}

?>