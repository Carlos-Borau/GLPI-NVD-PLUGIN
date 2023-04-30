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
    
    $output = json_decode(getProductsForVendor($vendor), true);

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
}

function getProductsForVendor($vendor) {

    $CVEConn = new PluginNvdCveconnection($vendor);

    $output = $CVEConn->launchRequest();

    return $output;
}

function insertSoftwareCPENames($softwares_id, $vendor, $product) {

    global $DB;


}

function updateSoftwareCPENames($softwares_id, $vendor, $product) {

    global $DB;


}

?>