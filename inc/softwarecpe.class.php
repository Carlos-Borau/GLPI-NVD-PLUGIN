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
     * @param CommonGLPI $item
     * @param int        $withtemplate
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

        $CVEConn = new PluginNvdCveconnection();
        $output = $CVEConn->launchRequest();

        $vendors = $output['vendor'];
        $products = [];

        $action = 'insert';
        $vendor_name = NULL;
        $product_name = NULL;
        $vendor_GLPI_name = NULL;
        $product_GLPI_name = NULL;

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

        if ($res->numrows() > 0) {

            $action = 'update';

            $row = $res->current();
            $vendor_name = $row['vendor_name'];
            $product_name = $row['product_name'];

            // Get list of products from MITRE CVE API for associated vendor
            $CVEConn = new PluginNvdCveconnection($vendor_name);
            $output = $CVEConn->launchRequest();

            $products = $output['product'];
        } 

        /***********************************************************************************************
         * Request software and vendor names in GLPI for given software
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

        if ($res->numrows() == 1) {
            
            $row = $res->current();

            $vendor_GLPI_name = $row['vendor'];
            $product_GLPI_name = $row['product'];
        }

        // Print current CPE associations for given software
        self::printCurrentCPEAssociation($vendor_name, $product_name);

        // Print separator
        self::printHorizontalSeparator();

        // Print sugested search terms for given software's vendor and product names
        self::printFilters($vendor_GLPI_name, $product_GLPI_name);

        // Print separator
        self::printHorizontalSeparator();

        // Print form header and hidden fields
        self::printFormHeader($action, $item->getID());

        // Print form select dropdowns
        self::printVendorAndProductDropdowns($vendors, $vendor_name, $products, $product_name);

        // Print form footer, submit button and js function
        self::printFormFooter();
    } 

    /**
     * Display horizontal ruler
     *
     * @since 1.0.0
     *
     * @return void
     */
    private static function printHorizontalSeparator() {

        $out = '<div class="nvd_cpe_div horizontal_ruler"></div>';

        echo $out;
    }

    /**
     * Display current cpe vendor and product names associated with given software
     *
     * @since 1.0.0
     *
     * @param array     $vendor            Current CPE vendor name associated with given software
     * @param array     $product           Current CPE product name associated with given software
     *
     * @return void
     */
    private static function printCurrentCPEAssociation($vendor, $product) {

        $out =  '<div class="nvd_cpe_div">';
        $out .= '<div class="nvd_cpe_row">';
        $out .= '<div><b class="nvd_cpe_title">' . __('Current CPE Name:') . '</b></div></div>';
        $out .= '<div class="nvd_cpe_row">';
        $out .= '<div><b class="nvd_cpe_name"'; 

        if ($vendor!=NULL) {

            $CPE = new PluginNvdCpe();
            $CPE->set_CPE_attributes([CPE_PART => 'a', CPE_VENDOR => $vendor, CPE_PRODUCT => $product]);
            $CPEName = $CPE->get_CPE_WFN();

            $out .= ">$CPEName</b>";

        } else {
            $out .= ' style="color:red"><u>' . __('NOT ASSIGNED YET') . '</u></b>';
        }

        $out .= '</div></div></div>';

        echo $out;
    }

    /**
     * Display sugested search terms for given software's CPE vendor and product names
     * and filter textboxes to filter available vendors and products by.
     * 
     * Takes the software's manufacturer and software names stored by GLPI and leaves 
     * only the most relevant parts, displayed from longest to shortest as sugestions
     * to the user to use as search terms for the vendor and product dropdowns.
     *
     * @since 1.0.0
     *
     * @param string    $vendor_name    GLPI stored manufacturer name for given software
     * @param string    $product_name   GLPI stored software name for given software
     *
     * @return void
     */
    private static function printFilters($vendor_name, $product_name) {

        // Get sugested vendor search terms for given software
        $sugested_vendor_terms  = PluginNvdCpe::getVendorSugestedSearchTerms($vendor_name);

        // Get sugested product search terms for given software
        $sugested_product_terms = PluginNvdCpe::getProductSugestedSearchTerms($product_name, $sugested_vendor_terms);

        $out =  '<div class="nvd_cpe_div">';

        // Vendor terms and filter
        $out .= '<div class="nvd_cpe_stack_collumn">';
        $out .= '<div class="nvd_cpe_stack_row">';
        $out .= '<div><b class="nvd_cpe_title">' . __('Filter vendors: ') . '</b></div></div>';
        $out .= '<div class="nvd_cpe_stack_row">';
        $out .= '<div class="nvd_cpe_row"><div><b class="nvd_cpe_subtitle">' . __('Sugested terms') . ': </b></div></div>';
        $out .= '<div class="nvd_cpe_row">';
        $out .= '<div><select name="vendor_terms" id="nvd_cpe_vendor_terms_dropdown" class="nvd_cpe_wide_dropdown">';
        $out .= '<option disabled selected value="-DEFAULT-">-- ' . __('SELECT TERM TO FILTER VENDORS BY') . ' --</option>';
        foreach ($sugested_vendor_terms as $term) {

            $out .= '<option ' . "value=\"$term\">$term</option>";
        }
        $out .= '</select></div></div></div>';
        $out .= '<div class="nvd_cpe_stack_row">';
        $out .= '<div class="nvd_cpe_row"><div><b class="nvd_cpe_subtitle">' . __('Current filter') . ': </b></div></div>';
        $out .= '<div class="nvd_cpe_row">';
        $out .= '<div><input type="text" name="vendor_filter" id="nvd_cpe_vendor_filter" class="nvd_cpe_textinput"></input></div></div>';
        $out .= '<div class="nvd_cpe_row"><button id="nvd_cpe_apply_vendor_filter" class="btn btn-info" type="submit">' . __('Apply') . '</button></div>';
        $out .= '<div class="nvd_cpe_row"><button id="nvd_cpe_clear_vendor_filter" class="btn btn-danger" type="reset">' . __('Clear') . '</button></div>';
        $out .= '</div></div>';

        // Vertical separator
        $out .= '<div class="vertical_ruler"></div>';

        // Product terms and filter
        $out .= '<div class="nvd_cpe_stack_collumn">';
        $out .= '<div class="nvd_cpe_stack_row">';
        $out .= '<div><b class="nvd_cpe_title">' . __('Filter products') . ': </b></div></div>';
        $out .= '<div class="nvd_cpe_stack_row">';
        $out .= '<div class="nvd_cpe_row"><div><b class="nvd_cpe_subtitle">' . __('Sugested terms') . ': </b></div></div>';
        $out .= '<div class="nvd_cpe_row">';
        $out .= '<div><select name="product_terms" id="nvd_cpe_product_terms_dropdown" class="nvd_cpe_wide_dropdown">';
        $out .= '<option disabled selected value="-DEFAULT-">-- ' . __('SELECT TERM TO FILTER PRODUCTS BY') . ' --</option>';
        foreach ($sugested_product_terms as $term) {

            $out .= '<option ' . "value=\"$term\">$term</option>";
        }
        $out .= '</select></div></div></div>';
        $out .= '<div class="nvd_cpe_stack_row">';
        $out .= '<div class="nvd_cpe_row"><div><b class="nvd_cpe_subtitle">' . __('Current filter') . ': </b></div></div>';
        $out .= '<div class="nvd_cpe_row">';
        $out .= '<div><input type="text" name="product_filter" id="nvd_cpe_product_filter" class="nvd_cpe_textinput"></input></div></div>';
        $out .= '<div class="nvd_cpe_row"><button id="nvd_cpe_apply_product_filter" class="btn btn-info" type="submit">' . __('Apply') . '</button></div>';
        $out .= '<div class="nvd_cpe_row"><button id="nvd_cpe_clear_product_filter" class="btn btn-danger" type="reset">' . __('Clear') . '</button></div>';
        $out .= '</div></div></div>';

        echo $out;
    }

    /**
     * Print form header and hidden fields
     *
     * @since 1.0.0
     *
     * @param array     $action     Action to perform on DB (isnert | update)
     * @param int       $ItemID     Software item ID
     *
     * @return void
     */
    private static function printFormHeader($action, $ItemID) {

        // Hidden form fields: _glpi_csrf_token | action (insert or update) | softwares_id
        $out =  '<form action="../plugins/nvd/front/softwarecpe.form.php" method="POST">';
        $out .= Html::hidden('_glpi_csrf_token', array('value' => Session::getNewCSRFToken()));
        $out .= Html::hidden('action', array('value' => $action));
        $out .= Html::hidden('softwares_id', array('value' => $ItemID));

        echo $out;
    }

    /**
     * Display form selectors for vendor and product
     *
     * @since 1.0.0
     *
     * @param array     $vendors            List of available vendors retrieved from CVE API
     * @param string    $selected_vendor    Assigned vendor for given software | NULL if none is assigned
     * @param array     $products           List of available products for a specific vendor retrieved from CVE API
     * @param string    $selected_product   Assigned product for given software | NULL if none is assigned
     *
     * @return void
     */
    private static function printVendorAndProductDropdowns($vendors, $selected_vendor, $products, $selected_product) {

        $out =  '<div class="nvd_cpe_div">';

        // Hidden vendor and product lists
        $out .= '<p id="nvd_cpe_vendor_hidden_list" hidden>' . implode(' ', $vendors) . '</p>';
        $out .= '<p id="nvd_cpe_product_hidden_list" hidden></p>';

        // Vendor dropdown
        $out .= '<div class="nvd_cpe_collumn">';
        $out .= '<div class="nvd_cpe_row">';
        $out .= '<div><b class="nvd_cpe_title">' . __('Available Vendors: ') . '</b></div></div>';
        $out .= '<div class="nvd_cpe_row">';
        $out .= '<div><select name="vendor" id="nvd_cpe_vendor_dropdown" class="nvd_cpe_dropdown" required>';
        $out .= '<option disabled ' . (($selected_vendor==NULL) ? 'selected ' : '') . ' value="-DEFAULT-">-- ' . __('SELECT A VENDOR') . ' --</option>';
        foreach ($vendors as $vendor) {

            $out .= '<option ' . (($selected_vendor==$vendor) ? 'selected ' : '') . "value=\"$vendor\">$vendor</option>";
        }
        $out .= '</select></div></div></div>';

        // Vertical separator
        $out .= '<div class="vertical_ruler"></div>';

        // Product dropdown
        $out .= '<div class="nvd_cpe_collumn">';
        $out .= '<div class="nvd_cpe_row">';
        $out .= '<div><b class="nvd_cpe_title">' . __('Available Products:') . '</b></div></div>';
        $out .= '<div class="nvd_cpe_row">';
        $out .= '<div><select name="product" id="nvd_cpe_product_dropdown" class="nvd_cpe_dropdown" required>';
        $out .= '<option disabled ' . (($selected_product==NULL) ? 'selected ' : '') . ' value="-DEFAULT-">-- ' . __('SELECT A PRODUCT') . ' --</option>';
        foreach ($products as $product) {

            $out .= '<option ' . (($selected_product==$product) ? 'selected ' : '') . "value=\"$product\">$product</option>";
        }
        $out .= '</select></div></div></div></div>';

        echo $out;
    }

    /**
     * Print form footer, submit button and javascript function
     *
     * @since 1.0.0
     *
     * @return void
     */
    private static function printFormFooter() {

        // Submit button
        $out =  '<div class="nvd_cpe_div">';
        $out .= '<input class="button btn btn-primary" type="submit" value="' . __('Update CPE Associations') . '">';
        $out .= '</div></form>';

        // Javascript event listener
        $out .= '<script>addEventListeners();</script>';

        echo $out;
    }
}

?>