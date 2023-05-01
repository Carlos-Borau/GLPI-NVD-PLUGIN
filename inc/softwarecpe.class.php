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
            // self::prueba();
            self::displayForSoftware($item);
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

        global $DB, $CFG_GLPI;

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

        $action = 'insert';
        $vendor_name = NULL;
        $product_name = NULL;
        $vendor_GLPI_name = NULL;
        $product_GLPI_name = NULL;

        $CVEConn = new PluginNvdCveconnection();
        $output = json_decode($CVEConn->launchRequest(), true);
        $vendors = $output['vendor'];
        $products = [];

        if ($res->numrows() > 0) {

            $action = 'update';

            $row = $res->current();
            $vendor_name = $row['vendor_name'];
            $product_name = $row['product_name'];

            $CVEConn = new PluginNvdCveconnection($vendor_name);
            $output = json_decode($CVEConn->launchRequest(), true);
            $products = $output['product'];

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

            $vendor_GLPI_name = $row['vendor'];
            $product_GLPI_name = $row['product'];
        }
        
        self::printVendorAndProductDropdowns($action, $item->getID(), $vendors, $vendor_name, $products, $product_name);

        echo "<script>addEventListenerToVendorSelect();</script>";
    } 

    private static function printVendorAndProductDropdowns($action, $itemID, $vendors, $selected_vendor, $products, $selected_product) {

        $out =  '<form action="../plugins/nvd/front/softwarecpe.form.php" method="POST">';
        $out .= Html::hidden('_glpi_csrf_token', array('value' => Session::getNewCSRFToken()));
        $out .= Html::hidden('action', array('value' => $action));
        $out .= Html::hidden('softwares_id', array('value' => $itemID));

        $out .= '<div class="nve_cpe_dropdown_div">';

        $out .= '<div class="nvd_cpe_dropdowns_collumn">';
        $out .= '<div class="nvd_cpe_dropdowns_row">';
        $out .= '<div><b class="nvd_cpe_dropdown_title">' . __('Available Vendors: ') . '</b></div></div>';
        $out .= '<div class="nvd_cpe_dropdowns_row">';
        $out .= '<div><select name="vendor" id="nvd_cpe_vendor_dropdown" class="nvd_cpe_dropdown" required>';
        $out .= '<option disabled ' . (($selected_vendor==NULL) ? 'selected ' : '') . ' value>-- ' . __('SELECT A VENDOR') . ' --</option>';
        foreach ($vendors as $vendor) {

            $out .= '<option ' . (($selected_vendor==$vendor) ? 'selected ' : '') . "value=\"$vendor\">$vendor</option>";
        }
        $out .= '</select></div></div></div>';

        $out .= '<div class="nvd_cpe_dropdowns_collumn vertical_ruler"></div>';

        $out .= '<div class="nvd_cpe_dropdowns_collumn">';
        $out .= '<div class="nvd_cpe_dropdowns_row">';
        $out .= '<div><b class="nvd_cpe_dropdown_title">' . __('Available Products:') . '</b></div></div>';
        $out .= '<div class="nvd_cpe_dropdowns_row">';
        $out .= '<div><select name="product" id="nvd_cpe_product_dropdown" class="nvd_cpe_dropdown" required>';
        $out .= '<option disabled ' . (($selected_product==NULL) ? 'selected ' : '') . ' value>-- ' . __('SELECT A PRODUCT') . ' --</option>';
        foreach ($products as $product) {

            $out .= '<option ' . (($selected_product==$product) ? 'selected ' : '') . "value=\"$product\">$product</option>";
        }
        $out .= '</select></div></div></div></div>';

        $out .= '<br><div class="nve_cpe_dropdown_div">';
        $out .= '<input type="submit" value="' . __('Update CPE Associations') . '">';
        $out .= '</div></form>';

        echo "$out<br>";
    }

    private static function prueba() {

        $name = "Una Compania Corporation eso nombre extra grandeeeeeeeee";


        print_r(PluginNvdCpe::getVendorSugestedSearchTerms($name));
    }
}

?>