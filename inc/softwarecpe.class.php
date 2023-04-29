<?php

class PluginNvdSoftwarecpe extends CommonDBTM {

    /**
    * Check if can view item
    *
    * @since 1.0.0
    *
    * @return boolean
    */
    static function canView() {
        
        return Config::canView();
    }

    /**
    * Get tab name for displayed item
    *
    * @since 1.0.0
    *
    * @return boolean
    */
    function getTabNameForItem(CommonGLPI $item, $withtemplate=0) {

        return self::createTabEntry(__('CPE Association'));
    }

    /**
    * Display tab content for given Software
    *
    * @since 1.0.0
    *
    * @param CommonGLPI $item       Software for which to display the CPE association
    * @param int $tabnum
    * @param int $withtemplate
    *
    * @return boolean
    */
    static function displayTabContentForItem(CommonGLPI $item, $tabnum=1, $withtemplate=0) {

        if ($item::getType() === Software::getType()) {
            self::prueba();
            #self::displayForSoftware($item);
        }
        
        return true;
    }

    /**
    * Display tab content for given Software item
    *
    * @since 1.0.0
    *
    * @param Software $item       Software item for which to display cpe associations
    *
    * @return void
    */
    private static function displayForSoftware(Software $item) {

        global $DB;

        /***********************************************************************************************
             * Request CPE vendor and product name associated with given software
             * 
             *  SELECT vendor_name, product_name
             *  FROM glpi_plugin_nvd_cpe_software_associations 
             *  WHERE softwares_id = $item->getID()
             **********************************************************************************************/
            $res = $DB->request(['SELECT' => ['vendor_name', 'product_name'],
                                 'FROM' => 'glpi_plugin_nvd_cpe_software_associations',
                                 'WHERE' => ['softwares_id' => $item->getID()]]);

            $vendor_name = NULL;
            $product_name = NULL;
            $vendor_search_name = NULL;
            $product_search_name = NULL;

            if ($res->numrows() > 0) {

                $row = $res->current();
                $vendor_name = $row['vendor_name'];
                $product_name = $row['product_name'];

            } else {

                /***********************************************************************************************
                 * Request software and vendor name for given software
                 * 
                 *  SELECT glpi_manufacturers.name, glpi_softwares.name
                 *  FROM glpi_softwares
                 *  INNER JOIN glpi_manufacturers
                 *  ON glpi_softwares.manufacturers_id = glpi_manufacturers.id
                 *  WHERE glpi_softwares.id = $item->getID()
                 **********************************************************************************************/
                $res = $DB->request(['SELECT' => ['glpi_manufacturers.name AS vendor', 'glpi_softwares.name AS product'],
                'FROM' => 'glpi_softwares',
                'INNER JOIN' => ['glpi_manufacturers' => ['FKEY' => ['glpi_softwares' => 'manufacturers_id',
                                                                     'glpi_manufacturers' => 'id']]],
                'WHERE' => ['glpi_softwares.id' => $item->getID()]]);

                $row = $res->current();

                $vendor_search_name = $row['vendor'];
                $product_search_name = $row['product'];
            }
            
            $CVEConn = new PluginNvdCveconnection();

            $output = json_decode($CVEConn->launchRequest(), true);

            $vendors = $output['vendor'];

            #print_r($vendors);

            echo "Vendor name: $vendor_name<br>";
            echo "Product name: $product_name<br>";
            echo "Vendor name: $vendor_search_name<br>";
            echo "Product name: $product_search_name<br>";
    } 

    private static function prueba() {

        $name = "Una Compania Corporation eso nombre extra grandeeeeeeeee";


        print_r(PluginNvdCpe::getVendorSugestedSearchTerms($name));
    }
}

?>