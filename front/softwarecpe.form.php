<?php

include ("../../../inc/includes.php");

// Check if plugin is activated...
$plugin = new Plugin();
if (!$plugin->isInstalled('nvd') || !$plugin->isActivated('nvd')) {
   Html::displayNotFoundError();
}

// Check if request is loocking for vendor products or wanting to set/update software vendor and product cpe names 
if (isset($_GET['vendor'])) {

    $vendor = $_GET['vendor'];
    
    $output = getProductsForVendor($vendor);

    $products = $output['product'];

    echo json_encode($products);

} elseif (isset($_POST['softwares_id']) and isset($_POST['vendor']) and isset($_POST['product']) and isset($_POST['action'])) {

    $softwares_id = $_POST['softwares_id'];
    $vendor = $_POST['vendor'];
    $product = $_POST['product'];
    $action = $_POST['action'];

    switch($action) {
        case 'insert':
            insertSoftwareCPENames($softwares_id, $vendor, $product);
            break;
        case 'update':
            updateSoftwareCPENames($softwares_id, $vendor, $product);
            break;
    };

    Html::redirect("{$CFG_GLPI['root_doc']}/front/software.form.php?id=$softwares_id");

} else {
    Html::redirect("{$CFG_GLPI['root_doc']}/front/software.php");
}

/**
 * Request products from CVE MITRE for a given vendor
 *
 * @since 1.0.0
 *
 * @param string $vendor    Software vendor for which to retrieve products
 *
 * @return string server JSON response
 */
function getProductsForVendor($vendor) {

    $CVEConn = new PluginNvdCveconnection($vendor);

    $output = $CVEConn->launchRequest();

    return $output;
}

/**
 * Insert new CPE vendor and product association with given software
 *
 * @since 1.0.0
 *
 * @param int       $softwares_id       ID of the software for which to create the association
 * @param string    $vendor             CPE vendor name for the given software
 * @param string    $product            CPE product name for the given software
 *
 * @return void
 */
function insertSoftwareCPENames($softwares_id, $vendor, $product) {

    global $DB;

    /***********************************************************************************************
     * Create CPE vendor and product name association for given software
     * 
     *  INSERT INTO glpi_plugin_nvd_cpe_software_associations 
     *  (softwares_id, vendor_name, product_name) VALUES ($softwares_id, $vendor, $product)
     **********************************************************************************************/
    $DB->insert(
        'glpi_plugin_nvd_cpe_software_associations', [
            'softwares_id' => $softwares_id,
            'vendor_name' => $vendor,
            'product_name' => $product
        ]
    );
}

function updateSoftwareCPENames($softwares_id, $vendor, $product) {

    global $DB;

    /***********************************************************************************************
     * Update CPE vendor and product name association for given software
     * 
     *  UPDATE glpi_plugin_nvd_cpe_software_associations 
     *  SET vendor_name = $softwares_id, product_name = $product
     *  WHERE softwares_id = $softwares_id
     **********************************************************************************************/
    $DB->update(
        'glpi_plugin_nvd_cpe_software_associations', [
            'vendor_name' => $vendor,
            'product_name' => $product
        ], [
            'softwares_id' => $softwares_id
        ]
    );
}

?>