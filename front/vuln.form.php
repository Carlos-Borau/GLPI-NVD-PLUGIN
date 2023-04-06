<?php

include ("../../../inc/includes.php");

// Check if plugin is activated...
// $plugin = new Plugin();
// if (!$plugin->isInstalled('nvd') || !$plugin->isActivated('nvd')) {
//    Html::displayNotFoundError();
// }

if ($_POST && isset($_POST['part']) && isset($_POST['vendor']) && isset($_POST['product']) && isset($_POST['version'])) {

    $part       = $_POST["part"];
    $vendor     = $_POST["vendor"];
    $product    = $_POST["product"];
    $version    = $_POST["version"];

    $cpe = new PluginNvdCpe($part, $vendor, $product, $version);

    $cpe_name = $cpe->get_CPE_WFN();

    echo $cpe_name . '<br>';

    $nvd = new PluginNvdConnection();

    /**
    * 
    * @todo This should eventually go away
    */ 
    $nvd::setApiKey('e5cd5b7b-7288-4f00-9a45-d47a2f9942b2');

    echo $nvd::getApiKey() . '<br>';

    $nvd->setUrlParams($cpe_name, true);

    echo $nvd->getCompleteUrl() . '<br>';

    $records = $nvd->requestNvdRecords();

    echo json_encode($records, JSON_PRETTY_PRINT);

    // Html::redirect("{$CFG_GLPI['root_doc']}/plugins/nvd/front/vuln.php");

} else {
    Html::redirect("{$CFG_GLPI['root_doc']}/plugins/nvd/front/vuln.php");
}
    
?>